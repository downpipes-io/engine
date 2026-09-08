// Support-pack diagnostic coverage for the SCHEDULER subsystem.
//
// Each block proves the SAME two things the audit demands of every new recording:
//   (a) the evidence is recorded ON THE FAULT PATH (not on a happy path, not only in a Workers Logs line), and
//   (b) it is REDACTION-SAFE: a raw error message, a secret and a customer value planted at the fault site
//       NEVER appear anywhere in the recorded record or in the DO's support-pack read (GET /scheduler-signals).
//
// What each area covers:
//   "one downpipe never updates its next-run time"       -> storageFaults.lastDownpipeId ATTRIBUTES the
//        DO 128 KiB value-too-large put, and schedHealth counts the three silent housekeeping faults (a sweep
//        that keeps throwing, a TRUNCATED fleet enumeration, a failed due-index parity stamp).
//   "after we rolled the engine back, one downpipe stopped backing up entirely" -> the refused dp:
//        record is STAMPED (closed class + the version pair + a count) instead of skipped with a log line.
//   "a backup ran during our declared change freeze" / "our freeze window never applied" -> blackoutResolve
//        stamps the closed class on the downpipe, and config validation now REFUSES a degenerate (inert) window.
import { deferPastBlackoutsResolved } from "../src/sched/schedule-window.ts";
import { validateConfig } from "../src/sched/config-validate.ts";
import { applySchedHealth, applyStorageFault, EMPTY_SCHED_HEALTH, EMPTY_STORAGE_FAULTS, schedHealthView, stateRefusalView } from "../src/sched/scheduler-helpers.ts";
import { CONFIG_SCHEMA_VERSION, DUE_INDEX_HEALTH_KEY, SCHED_HEALTH_KEY, SEEN_ASSERTION_PREFIX, STATE_REFUSED_PREFIX, STORAGE_FAULT_KEY } from "../src/sched/scheduler-do-base.ts";
import type { DownpipeConfig } from "../src/sched/scheduler-do.ts";
import { getFailures, makeConfig, makeScheduler, ok, stubFetch } from "./validate-scheduler-shared.ts";

// The three POISON values planted at every fault site below. If ANY of them ever reaches a recorded record or
// the pack read, the recording is leaking (a raw error string, a secret, or a customer's own free text) and the
// redaction assertions fail. They are deliberately distinctive so a substring scan is conclusive.
const POISON_ERROR = "R2 PutObject denied: AKIAPOISONKEY/secret-token-9f3a";
const POISON_VALUE = "customers-crown-jewels-bucket";
const POISON_CRON = "*/7 3 * * POISONCRON";

// scan asserts NONE of the poison strings appears anywhere in a recorded structure.
function scanClean(label: string, subject: unknown): void {
  const json = JSON.stringify(subject ?? null);
  const leaked = [POISON_ERROR, POISON_VALUE, POISON_CRON, "AKIAPOISONKEY", "secret-token-9f3a"].filter((p) => json.includes(p));
  ok(`${label} (redaction: no raw error / secret / customer value in the record)`, leaked.length === 0);
}

// ---- storage-fault ATTRIBUTION + the silent housekeeping counters -------------------------
async function testStorageFaultAttribution(): Promise<void> {
  const { stub, storage } = makeScheduler();
  // A healthy downpipe first, so we prove the counter is written by the FAULT path, not by every persist.
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-healthy"));
  ok("a healthy persist writes NO storage-fault counter", storage.rawGet(STORAGE_FAULT_KEY) === undefined);

  // Fail the persist of ONE downpipe with a DO value-too-large error carrying the poison text. Only the dp:
  // write throws, so the best-effort counter write itself still succeeds (exactly the real value-too-large case,
  // which is per-KEY).
  const realPut = storage.put.bind(storage);
  storage.put = async (key: string, value: unknown): Promise<void> => {
    if (key === "dp:dp-oversized") throw new Error(`put failed: value is too large (128 KiB limit exceeded) while writing ${POISON_VALUE}: ${POISON_ERROR}`);
    return realPut(key, value);
  };
  const resp = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-oversized", { name: POISON_VALUE }));
  storage.put = realPut;
  ok("the oversized persist still FAILS LOUD to the caller (behaviour unchanged)", resp.status >= 400);

  const faults = storage.rawGet<Record<string, unknown>>(STORAGE_FAULT_KEY);
  ok("the storage fault is recorded", faults !== undefined);
  ok("it is classified value-too-large (the DO 128 KiB cap), not a generic put failure", faults?.lastKind === "value-too-large" && faults?.valueTooLarge === 1);
  ok("the fault NAMES the downpipe whose state is over the cap (lastDownpipeId)", faults?.lastDownpipeId === "dp-oversized");
  scanClean("storageFaults", faults);

  // An UNATTRIBUTED later fault must not ERASE the last known culprit.
  const carried = applyStorageFault(faults as never, "put-failed", 1_700_000_000_000);
  ok("an unattributed fault keeps the prior attribution (never erases the culprit)", carried.lastDownpipeId === "dp-oversized" && carried.putFailed === 1 && carried.total === 2);
  // A malformed/absent id is dropped, never coerced into a string like "undefined"/"null".
  const noId = applyStorageFault(EMPTY_STORAGE_FAULTS, "put-failed", 1, { secret: POISON_VALUE });
  ok("a non-string id is DROPPED (never coerced into the record)", noId.lastDownpipeId === null);
  scanClean("applyStorageFault with an object id", noId);
}

// ---- the housekeeping faults that were fully silent ---------------------------------------
async function testSchedHealth(): Promise<void> {
  // (1) the alarm's opportunistic housekeeping sweep THROWS -> counted, and the alarm still re-arms.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-a"));
    const realList = storage.list.bind(storage);
    storage.list = async (opts?: { prefix?: string; start?: string; end?: string; limit?: number }): Promise<Map<string, never>> => {
      if (opts?.prefix === SEEN_ASSERTION_PREFIX) throw new Error(`storage list failed: ${POISON_ERROR}`);
      return realList(opts) as Promise<Map<string, never>>;
    };
    await stub.alarm();
    storage.list = realList;
    const health = storage.rawGet<Record<string, { count: number; lastAt: number }>>(SCHED_HEALTH_KEY);
    ok("a THROWING housekeeping sweep is counted (it grew DO storage silently for months before)", (health?.sweepFaults?.count ?? 0) >= 1 && (health?.sweepFaults?.lastAt ?? 0) > 0);
    ok("the alarm still re-armed despite the failing sweep (best-effort, unchanged behaviour)", storage.lastAlarmAt !== null);
    scanClean("schedHealth after a sweep fault", health);
  }

  // (2) a due-index parity STAMP whose write fails -> counted, and the pack read marks the served snapshot STALE
  //     (otherwise the pack shows the PRIOR parity snapshot as if it had just been re-measured).
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-b"));
    await stub.rebuildDueIndex(); // a healthy rebuild writes a fresh parity snapshot
    const fresh = storage.rawGet<{ at: number }>(DUE_INDEX_HEALTH_KEY);
    ok("a healthy rebuild stamps the parity snapshot", typeof fresh?.at === "number");
    const realPut = storage.put.bind(storage);
    storage.put = async (key: string, value: unknown): Promise<void> => {
      if (key === DUE_INDEX_HEALTH_KEY) throw new Error(`storage put failed: ${POISON_ERROR}`);
      return realPut(key, value);
    };
    await stub.rebuildDueIndex();
    storage.put = realPut;
    const health = storage.rawGet<Record<string, { count: number }>>(SCHED_HEALTH_KEY);
    ok("a FAILED parity stamp is counted", (health?.parityStampFailures?.count ?? 0) === 1);
    const signals = await stub.schedulerSignals();
    ok("the pack read marks the served due-index snapshot STALE (never fresh)", signals.schedHealth.parityStampStale === true);
    ok("sweep/list counters stay zero (only the class that fired is counted)", signals.schedHealth.sweepFaults.count === 0 && signals.schedHealth.listTruncations.count === 0);
    scanClean("schedulerSignals after a parity-stamp fault", signals);
  }

  // (3) a TRUNCATED enumeration (the DO_LIST_MAX_PAGES guard ran out of pages before it ran out of keys). A
  //     truncated dp: enumeration means downpipes past the cap are NEVER scheduled and read as nonexistent.
  {
    const { stub, storage } = makeScheduler();
    const realList = storage.list.bind(storage);
    const fullPage = new Map<string, unknown>();
    for (let i = 0; i < 1000; i++) fullPage.set(`zz:${String(i).padStart(6, "0")}`, { name: POISON_VALUE });
    storage.list = async (opts?: { prefix?: string; start?: string; end?: string; limit?: number }): Promise<Map<string, never>> => {
      if (opts?.prefix === "zz:") return new Map(fullPage) as Map<string, never>; // every page comes back FULL: never exhausts
      return realList(opts) as Promise<Map<string, never>>;
    };
    await stub.listAllByPrefix("zz:");
    storage.list = realList;
    const health = storage.rawGet<Record<string, { count: number }>>(SCHED_HEALTH_KEY);
    ok("a TRUNCATED prefix enumeration is counted (silent under-reporting of the fleet before)", (health?.listTruncations?.count ?? 0) === 1);
    scanClean("schedHealth after a truncated enumeration", health);
  }

  // The pure counter clamps a corrupt persisted record rather than carrying a negative/NaN into the pack.
  const clamped = applySchedHealth({ sweepFaults: { count: -5, lastAt: Number.NaN }, listTruncations: { count: "x" as unknown as number, lastAt: 0 }, parityStampFailures: { count: 3, lastAt: 10 } }, "sweep-fault", 99);
  ok("a corrupt persisted counter is CLAMPED (never carries a negative/NaN into the pack)", clamped.sweepFaults.count === 1 && clamped.listTruncations.count === 0 && clamped.parityStampFailures.count === 3);
  const noStale = schedHealthView(EMPTY_SCHED_HEALTH, 1234);
  ok("parityStampStale is false when no stamp has ever failed", noStale.parityStampStale === false);
}

// ---- G095 / the rolled-back engine silently skipping a downpipe ---------------------------
async function testStateRefusal(): Promise<void> {
  const { stub, storage } = makeScheduler();
  // Two healthy downpipes, then REWRITE one record as if a NEWER engine had written it (the rollback case) and
  // one with a corrupt (non-number) version stamp. Both are load-bearing source-selection reads.
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-ok"));
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-future", { name: POISON_VALUE }));
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-corrupt"));
  const future = storage.rawGet<Record<string, unknown>>("dp:dp-future")!;
  await storage.put("dp:dp-future", { ...future, schemaVersion: CONFIG_SCHEMA_VERSION + 3, nextRunAt: Date.now() - 60_000 });
  const corrupt = storage.rawGet<Record<string, unknown>>("dp:dp-corrupt")!;
  await storage.put("dp:dp-corrupt", { ...corrupt, schemaVersion: `v${CONFIG_SCHEMA_VERSION + 1}-${POISON_VALUE}`, nextRunAt: Date.now() - 60_000 });
  const okDp = storage.rawGet<Record<string, unknown>>("dp:dp-ok")!;
  await storage.put("dp:dp-ok", { ...okDp, nextRunAt: Date.now() - 60_000 });
  await stub.rebuildDueIndex();

  const dueResp = await stubFetch(stub, "GET", "/due");
  const due = (await dueResp.json()) as { due: Array<{ config: { id: string } }> };
  ok("the refused downpipes are SKIPPED and the rest of the fleet still dispatches", due.due.length === 1 && due.due[0]?.config.id === "dp-ok");

  const newer = storage.rawGet<Record<string, unknown>>(`${STATE_REFUSED_PREFIX}dp-future`);
  ok("the rollback refusal is STAMPED with the closed class", newer?.class === "schema-newer");
  ok("the stamp carries the VERSION PAIR as clamped ints (stored vs supported)", newer?.storedVersion === CONFIG_SCHEMA_VERSION + 3 && newer?.supportedVersion === CONFIG_SCHEMA_VERSION);
  ok("the stamp carries a count and a time", newer?.count === 1 && typeof newer?.at === "number" && (newer?.at as number) > 0);
  scanClean("the schema-newer stamp", newer);

  const malformed = storage.rawGet<Record<string, unknown>>(`${STATE_REFUSED_PREFIX}dp-corrupt`);
  ok("a MALFORMED version stamp is refused (it can no longer defeat the guard silently)", malformed?.class === "schema-version-malformed" && malformed?.storedVersion === 0);
  scanClean("the schema-version-malformed stamp (the raw stamp value never rides)", malformed);
  ok("a healthy downpipe carries NO refusal stamp", storage.rawGet(`${STATE_REFUSED_PREFIX}dp-ok`) === undefined);

  // The stamp is written to its OWN key: the refused dp: record must NOT be re-stamped with THIS engine's
  // version (that would clobber the new-shape state the guard exists to protect).
  const stillFuture = storage.rawGet<Record<string, unknown>>("dp:dp-future");
  ok("the refused dp: record is NOT re-stamped (the newer-schema state is preserved, not clobbered)", stillFuture?.schemaVersion === CONFIG_SCHEMA_VERSION + 3);

  // A second due() pass COUNTS the repeat refusal (a downpipe stuck for days shows a climbing count).
  await stub.rebuildDueIndex();
  await stubFetch(stub, "GET", "/due");
  ok("repeat refusals are counted (a downpipe stuck for days shows a climbing count)", (storage.rawGet<{ count: number }>(`${STATE_REFUSED_PREFIX}dp-future`)?.count ?? 0) === 2);

  // The manual run-now path (trigger) also stamps, and still 500s to the operator.
  const trig = await stubFetch(stub, "POST", "/trigger", { id: "dp-future" });
  ok("run-now on a refused downpipe still fails loud (500), and the refusal is stamped", trig.status >= 400 && (storage.rawGet<{ count: number }>(`${STATE_REFUSED_PREFIX}dp-future`)?.count ?? 0) === 3);

  // The pack read exposes the refusals with the customer's own downpipe label, closed class and clamped ints.
  const signals = await stub.schedulerSignals();
  const ids = signals.stateRefusals.downpipes.map((d) => d.downpipeId).sort();
  ok("the pack read carries both refused downpipes", signals.stateRefusals.total === 2 && ids.join(",") === "dp-corrupt,dp-future");
  ok("the pack read is not truncated at this size", signals.stateRefusals.truncated === false);
  scanClean("schedulerSignals.stateRefusals", signals.stateRefusals);

  // A repaired downpipe stops reporting: a trigger whose record now reads CLEAN clears the stamp.
  await storage.put("dp:dp-future", { ...(storage.rawGet<Record<string, unknown>>("dp:dp-future") as object), schemaVersion: CONFIG_SCHEMA_VERSION });
  const okTrig = await stubFetch(stub, "POST", "/trigger", { id: "dp-future" });
  ok("once the record reads clean the trigger succeeds and the refusal stamp is CLEARED", okTrig.status === 200 && storage.rawGet(`${STATE_REFUSED_PREFIX}dp-future`) === undefined);

  // The read-side projection is the redaction choke point: an unrecognised class is DROPPED, never echoed.
  const forged = stateRefusalView("dp-x", { class: POISON_ERROR as never, at: -1, count: Number.NaN, storedVersion: 2, supportedVersion: 1 });
  ok("an unrecognised (forged/corrupt) class is DROPPED by the pack projection, never echoed as text", forged === null);
}

// ---- blackout windows silently violated ---------------------------------------------------
async function testBlackoutResolve(): Promise<void> {
  // (1) a degenerate start === end window covers NOTHING, so the declared freeze has never once applied.
  const degenerate = { timeZone: "UTC", blackoutWindows: [{ startMinute: 180, endMinute: 180 }] };
  const degRes = deferPastBlackoutsResolved(Date.UTC(2026, 5, 17, 3, 30), degenerate);
  ok("a degenerate (start === end) window is classed INERT (it has never applied)", degRes.class === "degenerate-window-inert");
  ok("the deferral itself is unchanged (the inert window still defers nothing)", degRes.at === Date.UTC(2026, 5, 17, 3, 30));

  // (2) windows that TILE the whole day: every hop lands in another window, so the hop ceiling is exhausted and
  //     the run fires INSIDE the customer's declared change freeze. This is the silent violation.
  const tiling = { timeZone: "UTC", blackoutWindows: [{ startMinute: 0, endMinute: 720 }, { startMinute: 720, endMinute: 1440 }] };
  const tiled = deferPastBlackoutsResolved(Date.UTC(2026, 5, 17, 3, 30), tiling);
  ok("a hop-ceiling exhaustion that leaves the fire INSIDE a window is recorded", tiled.class === "hop-ceiling-fired-inside-window");

  // (3) the healthy path is still classed ok, and a fire outside the window is untouched.
  const healthy = { timeZone: "UTC", blackoutWindows: [{ startMinute: 120, endMinute: 240 }] };
  const deferred = deferPastBlackoutsResolved(Date.UTC(2026, 5, 17, 2, 30), healthy);
  ok("a clean deferral out of a window is classed ok, with the deferred instant unchanged", deferred.class === "ok" && deferred.at === Date.UTC(2026, 5, 17, 4, 0));
  ok("no windows resolves to ok (the cadence/cron path is untouched)", deferPastBlackoutsResolved(1000, undefined).class === "ok");

  // (4) the DO STAMPS the class on the downpipe at create time, carrying the class + time and NOTHING else:
  //     no window minutes, no days, no cron string (the schedule-string pack exclusion is preserved).
  const { stub, storage } = makeScheduler();
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-freeze", { name: POISON_VALUE, schedule: tiling }));
  const ds = storage.rawGet<{ blackoutResolve?: Record<string, unknown> }>("dp:dp-freeze");
  ok("the downpipe row carries the blackout class (the pack can finally see the violation)", ds?.blackoutResolve?.class === "hop-ceiling-fired-inside-window");
  ok("the stamp is CLASS + TIME only (no window minutes, no days ever ride)", JSON.stringify(Object.keys(ds?.blackoutResolve ?? {}).sort()) === '["at","class"]');
  scanClean("the blackoutResolve stamp", ds?.blackoutResolve);

  // A downpipe with NO windows carries no stamp at all (nothing to resolve).
  await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-nofreeze"));
  ok("a downpipe with no blackout windows carries no stamp", storage.rawGet<{ blackoutResolve?: unknown }>("dp:dp-nofreeze")?.blackoutResolve === undefined);

  // (5) the degenerate window is now REFUSED at the write path, so it becomes a counted refusal the operator
  //     sees immediately instead of a freeze that silently does nothing for months.
  let refused = false;
  try {
    validateConfig(makeConfig("dp-degenerate", { schedule: { timeZone: "UTC", blackoutWindows: [{ startMinute: 180, endMinute: 180 }] } }) as unknown as DownpipeConfig);
  } catch (e) {
    refused = /must differ/.test((e as Error).message);
  }
  ok("config validation REFUSES a degenerate (inert) blackout window", refused);
  const badResp = await stubFetch(stub, "POST", "/downpipes", makeConfig("dp-degenerate", { schedule: { blackoutWindows: [{ startMinute: 180, endMinute: 180 }] } }));
  ok("the DO write path rejects it too (400), so it never lands as a silent no-op window", badResp.status === 400);
}

async function main(): Promise<void> {
  await testStorageFaultAttribution();
  await testSchedHealth();
  await testStateRefusal();
  await testBlackoutResolve();
  const failures = getFailures();
  console.log(failures === 0 ? "sched-diag: OK" : `sched-diag: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

await main();
