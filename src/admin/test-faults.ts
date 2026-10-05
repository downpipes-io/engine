// The HARNESS-ONLY test-fault CONSUMPTION side (owner-gated engine test-fault-hook). This module holds the
// gate, the four injection-seam consume helpers, and the gate/driver wrappers that turn an armed fault into
// the branch it forces. It is the twin of the DO store (scheduler-do-test-fault.ts): the store persists ONE
// armed fault, this consumes it single-shot at the real settle/canary/diff code path.
//
// SAFETY, the whole point: every helper here short-circuits on !testFaultsEnabled(env) BEFORE any Durable
// Object round-trip, so with HARNESS_TEST_FAULTS absent (every production, dev, uat and internal engine) the
// injection seams do NO work and the path is byte-identical. The EFFECT of a fault is therefore gated at the
// point of consumption, independently of the arming gate: a production engine can neither arm nor consume,
// so a fault has no way to exist or to fire there. The injected faults ride the REAL code paths (a REAL dead
// canary verdict, a REAL throwing deploy, a REAL dropped-binding diff), so they exercise exactly what a
// genuine fault would; they never shortcut a control or touch a data path.

import type { CanaryLiveness } from "../canary/types.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { ARMABLE_FAULT_KINDS } from "../sched/scheduler-do-test-fault.ts";
import { envFlagEnabled } from "./auth.ts";
import { doURL } from "../do-url.ts";
import { schedulerStub } from "./router-helpers.ts";
import type { DeployDriver, HealthGate } from "./update-types.ts";

// The closed set of arm-able fault kinds, re-exported from the DO store so the Worker validates the same set.
export { ARMABLE_FAULT_KINDS };

// testFaultsEnabled is THE gate. HARNESS_TEST_FAULTS is a truthy string ONLY on a harness estate; absent or
// falsey everywhere else, so the whole surface (routes, arming, and every consume below) is off.
export function testFaultsEnabled(env: Env): boolean {
  return envFlagEnabled(env.HARNESS_TEST_FAULTS);
}

// CONSUME_FAULT_SCHEDULE is SETTLE_PROBE_SCHEDULE's twin for the fault READ. A settle/cron consume runs on the
// JUST-PROMOTED isolate, whose code swap has reset every Durable Object, so a single round-trip to the fault
// store in that window can fail transiently (a thrown or non-ok DO fetch as the isolate re-instantiates),
// exactly as the settle canary flight can (update-gate.ts SETTLE_PROBE_SCHEDULE / probeSettleVerdict). The
// canary RETRIES through that window; a consume that used a SINGLE un-retried read could read an armed fault
// back as null and never inject it (a fault-injection miss). Bounded and short (three backoffs, ~3.5s worst
// case) so the settle stays interactive; a CLEAN answer from the DO (a fault OR a definitive empty) is never
// retried, so the normal no-fault path is untouched. Named at module scope and exported, and read at CALL
// time so it is visible to the validator, which injects a recording sleep so the suite never waits for real.
export const CONSUME_FAULT_SCHEDULE: { backoffMs: readonly number[] } = { backoffMs: [500, 1000, 2000] };

// ConsumeAttempt classifies ONE round-trip so the caller can tell a CLEAN answer (the DO was reached and its
// strongly-consistent storage read: a fault, or a definitive empty) from an UNAVAILABLE one (the round-trip
// threw or answered non-ok: the post-swap isolate-reset window). Only the latter is retried, so a genuinely
// empty store never spins.
type ConsumeAttempt = { readable: true; fault: { kind: string; binding?: string } | null } | { readable: false };

// consumeOnce is a single read-check-delete round-trip to the DO consume endpoint, classified per above.
async function consumeOnce(scheduler: DurableObjectStub, kinds: string[]): Promise<ConsumeAttempt> {
  try {
    const r = await scheduler.fetch(doURL("/test-fault/consume"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ kinds }) });
    if (!r.ok) return { readable: false };
    const { fault } = (await r.json()) as { fault: { kind: string; binding?: string } | null };
    return { readable: true, fault: fault ?? null };
  } catch {
    return { readable: false };
  }
}

// consumeArmedFault asks the DO to read-check-delete an armed fault whose kind is one of `kinds` (single-shot,
// atomic in the DO), POST-SWAP TOLERANT. It is called ONLY after the testFaultsEnabled gate, so a production
// engine never reaches it (byte-identical prod). A CLEAN read is returned at once (a fault fires; a definitive
// empty returns null with no retry and no sleep, so the normal no-fault path is unchanged). Only an UNAVAILABLE
// round-trip (thrown / non-ok, the isolate-reset window) is retried on the bounded backoff; if the window never
// clears within the budget it fails SAFE to null (never a crashed or hung settle/cron; the harness net-zero
// read-back is the authority). `sleep` is injectable so the validator drives the schedule with no real waiting.
export async function consumeArmedFault(
  scheduler: DurableObjectStub,
  kinds: string[],
  opts: { backoffMs?: readonly number[]; sleep?: (ms: number) => Promise<void> } = {},
): Promise<{ kind: string; binding?: string } | null> {
  const backoffs = opts.backoffMs ?? CONSUME_FAULT_SCHEDULE.backoffMs;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  let attempt = await consumeOnce(scheduler, kinds);
  for (let i = 0; i < backoffs.length && attempt.readable === false; i++) {
    await sleep(backoffs[i]!);
    attempt = await consumeOnce(scheduler, kinds);
  }
  return attempt.readable ? attempt.fault : null;
}

// consumeSettleFault consumes a verdict-affecting settle fault (canary-dead | rollback-deploy-fail) at the
// settle route. Returns which one fired, or null (flag off, none armed, or a different kind armed such as
// drop-source-binding, which this seam deliberately leaves for the binding-diff seam to consume).
export async function consumeSettleFault(env: Env, scheduler: DurableObjectStub): Promise<"canary-dead" | "rollback-deploy-fail" | null> {
  if (!testFaultsEnabled(env)) return null;
  const fault = await consumeArmedFault(scheduler, ["canary-dead", "rollback-deploy-fail"]);
  return fault?.kind === "canary-dead" || fault?.kind === "rollback-deploy-fail" ? fault.kind : null;
}

// consumeDropSourceBindingFault consumes a drop-source-binding fault at the KEPT-settle binding diff and
// returns the source-binding NAME to drop from the post-update set, or null (flag off / none armed / no name).
export async function consumeDropSourceBindingFault(env: Env, scheduler: DurableObjectStub): Promise<string | null> {
  if (!testFaultsEnabled(env)) return null;
  const fault = await consumeArmedFault(scheduler, ["drop-source-binding"]);
  return fault?.binding ?? null;
}

// consumeHourlyCanaryFault consumes an hourly-canary-unhealthy fault at the cron canary flight and returns
// whether it fired (so this flight's results are forced unhealthy). Single-shot: a second tick flies healthy.
export async function consumeHourlyCanaryFault(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  if (!testFaultsEnabled(env)) return false;
  return (await consumeArmedFault(scheduler, ["hourly-canary-unhealthy"])) !== null;
}

// consumeDestHeaderFault consumes a dest-header-corrupt fault at the SEAL WRITE seam (sliceDepsFromEnv) and
// returns whether it fired, so the NEXT run's outbound archive writes are wrapped to fault. Single-shot: a
// second run (or a retry of the failed one) writes clean. Gated on the flag first, so a production engine
// never reaches the store (byte-identical prod).
export async function consumeDestHeaderFault(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  if (!testFaultsEnabled(env)) return false;
  return (await consumeArmedFault(scheduler, ["dest-header-corrupt"])) !== null;
}

// consumeLicenceTokenReadFault consumes a licence-token-read-fail fault at the readLicence DO-read seam
// (licence.ts) and returns whether it fired, so the NEXT /licence-token read is forced into the existing
// fallback catch (fall back to the deploy-time env token, doReadFellBack recorded). Single-shot: a second read
// (or a retry of the same one) reads clean.
export async function consumeLicenceTokenReadFault(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  if (!testFaultsEnabled(env)) return false;
  return (await consumeArmedFault(scheduler, ["licence-token-read-fail"])) !== null;
}

// consumeReportDataFault consumes a report-data-read-fail fault at the assertReportData seam
// (router-posture.ts) and returns whether it fired, so the NEXT compliance report-data read is forced into
// the existing throw-to-5xx guard rather than a report ever being signed over an unavailable read.
// Single-shot: the next report build reads clean.
export async function consumeReportDataFault(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  if (!testFaultsEnabled(env)) return false;
  return (await consumeArmedFault(scheduler, ["report-data-read-fail"])) !== null;
}

// consumePasskeySessionMintFault consumes a passkey-session-mint-fail fault at the sessionCookieForFinish
// seam (router-auth-flow.ts) and returns whether it fired, so the NEXT verified finish ceremony's
// /passkey/session/issue call is forced into the existing fail-open catch (no session minted, ceremony body
// still returned; recordPasskeyOutcome then logs passkey-session-mint-failed). Single-shot: the next
// ceremony mints normally.
export async function consumePasskeySessionMintFault(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  if (!testFaultsEnabled(env)) return false;
  return (await consumeArmedFault(scheduler, ["passkey-session-mint-fail"])) !== null;
}

// HARNESS_CONTROL_PLANE_FAULT_REASON is the redaction-safe reason recorded when a control-plane-recovery-
// required fault latches (readControlPlaneStatus.reason, the console banner's driving field). Named once so
// the consume seam and its validate vectors quote the identical string.
export const HARNESS_CONTROL_PLANE_FAULT_REASON = "harness test-fault: control-plane recovery required (control-plane-recovery-required)";

// consumeControlPlaneRecoveryFault consumes a control-plane-recovery-required fault at the control-plane
// STATUS READ seam (router-identity.ts GET /admin/control-plane/status) and returns whether it fired. The
// caller then LATCHES the real recovery-required flag via the SAME setControlPlaneRecoveryRequired the cron
// health pass calls on a genuine wipe, rather than spoofing the response -- so this read and every later one
// on the same estate (whoami's degrade-to-viewer, the console recovery banner) see the real product
// behaviour. Single-shot: only the FIRST read after arming triggers the latch; the latch then
// PERSISTS exactly as production's does, released only by the harness-only /test-fault/control-plane-clear
// action (the real acknowledge/reconcile clears both refuse over an empty role table, which is exactly the
// state this fault-hook's own throwaway recovery estate is built to carry).
export async function consumeControlPlaneRecoveryFault(env: Env, scheduler: DurableObjectStub): Promise<boolean> {
  if (!testFaultsEnabled(env)) return false;
  return (await consumeArmedFault(scheduler, ["control-plane-recovery-required"])) !== null;
}

// maybeInjectControlPlaneRecoveryFault is the whole control-plane STATUS READ seam in one call (kept out of
// router-identity.ts, which already sits at the line-budget ceiling -- the same reason
// handleControlPlaneRecoveryAck stayed a standalone spoke). Consumes the fault and, when it fires, calls the
// SAME internal DO route the cron health pass calls (POST /control-plane/recovery-required) so the real
// latch is set for real, never a spoofed response. No-op with no extra DO round-trip unless HARNESS_TEST_FAULTS.
export async function maybeInjectControlPlaneRecoveryFault(env: Env, scheduler: DurableObjectStub): Promise<void> {
  if (await consumeControlPlaneRecoveryFault(env, scheduler)) {
    await scheduler.fetch(doURL("/control-plane/recovery-required"), { method: "POST", body: JSON.stringify({ reason: HARNESS_CONTROL_PLANE_FAULT_REASON }) });
  }
}

// forcedDeadGate wraps a HealthGate so its canary flight returns DEAD, while baseline() and selfCheck()
// delegate to the real gate. The REAL probeSettleVerdict then flies this, gets DEAD, and (a dead verdict is
// never retried) decides rollback immediately, producing the genuine settle trace the oracle reads.
export function forcedDeadGate(gate: HealthGate): HealthGate {
  return {
    baseline: () => gate.baseline(),
    flyNow: async (): Promise<CanaryLiveness> => "dead",
    selfCheck: () => gate.selfCheck(),
    flyNowMeasured: async (): Promise<{ status: CanaryLiveness; measured: boolean }> => ({ status: "dead", measured: true }),
  };
}

// deployFailingDriver wraps a DeployDriver so deployVersion THROWS (the compound rollback-deploy-fail leg),
// while every read method (currentLiveVersionId / currentLiveVersions / uploadVersion / ...) passes through.
// makeCfDeployDriver returns closure methods (no `this`), so the spread copies them faithfully.
export function deployFailingDriver(driver: DeployDriver): DeployDriver {
  return {
    ...driver,
    deployVersion: async (): Promise<void> => {
      throw new Error("harness test-fault: the rollback deploy was forced to fail (rollback-deploy-fail)");
    },
  };
}

// headerFaultingDestination wraps a Destination so its archive WRITES (put / putStream) fail with a
// malformed/unexpected destination response header, while every other method (get / exists / list /
// putConditional / the diagnostic accessors) passes straight through to the real destination. It is the
// dest-write twin of deployFailingDriver: it forces the engine's REAL header-fault outcome rather than
// shortcutting a control or corrupting a datum. A destination whose write answers with a malformed or
// unexpected response header is exactly what uploadPart's no-ETag throw and the credentialed-redirect guard
// already fail LOUD on (s3.ts / s3-multipart-ops.ts), so a wrapped write throws that shape and the seal
// records the run FAILED, proving the engine never stamps a good backup over a header-faulted write.
//
// The thrown message carries NO HTTP status and NO network vocabulary, so classifyDestError (dest/classify.ts)
// reads it as "permanent": withRetry fails it on the FIRST attempt (no retry) and the inline-throttle routing
// never park-and-resumes it, so the run fails terminally rather than healing on a later slice. A Proxy is used
// (not a spread) because a Destination is a class instance whose methods live on the prototype; every
// delegated method is bound to the real instance so its private fields keep working.
export function headerFaultingDestination(inner: Destination): Destination {
  return new Proxy(inner, {
    get(target, prop, receiver) {
      if (prop === "put" || prop === "putStream") {
        const op = prop === "put" ? "PUT" : "PUT stream";
        return async (key: string): Promise<void> => {
          throw new Error(`${op} ${key}: destination returned a malformed/unexpected response header (harness dest-header test-fault)`);
        };
      }
      const value = Reflect.get(target, prop, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

// maybeHeaderFaultDestination is the SEAL-side consume seam: called once per seal-deps build
// (sliceDepsFromEnv), it returns the destination UNCHANGED on every production/dev/uat/internal engine (the
// flag gate short-circuits BEFORE any Durable Object round-trip, byte-identical), and on a harness estate it
// consumes a single armed dest-header-corrupt fault and, when one fired, wraps the destination so this run's
// archive writes fault. Single-shot (the DO consume clears the record), so exactly one run's writes fault and
// a retry or the next run writes clean.
export async function maybeHeaderFaultDestination(env: Env, dest: Destination): Promise<Destination> {
  if (!testFaultsEnabled(env)) return dest;
  const armed = await consumeDestHeaderFault(env, schedulerStub(env));
  return armed ? headerFaultingDestination(dest) : dest;
}
