// validate-config-schema-version: proves the read-time schema guard for the persisted per-downpipe
// DownpipeState (the dp:<id> record in the SchedulerDO) — the one persisted surface that previously had
// NEITHER a version field NOR a read-time validator (validateConfig ran only on write, every read was a
// blind cast), so a future engine that changed a load-bearing config field could read an old/new-shape
// record back as undefined and seal the WRONG/EMPTY source set while still reporting ok (a silent partial).
// It mirrors the seal CHECKPOINT's v:1 fail-closed gate and the migrateCanaryState read-time-migration
// precedent. Proven SERVER-SIDE with the shared in-memory storage double only (no network, no deploy):
//   - migrateOrRejectConfig accepts an ABSENT schemaVersion (legacy v1), the CURRENT version, an OLDER
//     number, and a non-number, all unchanged, and passes undefined through; it THROWS only on a stored
//     schemaVersion strictly NEWER than CONFIG_SCHEMA_VERSION (a rollback reading new-shape state);
//   - persistDownpipeState (the single writer) STAMPS schemaVersion = CONFIG_SCHEMA_VERSION at the storage
//     boundary WITHOUT mutating the in-memory state it was handed (addDownpipe's return is byte-identical);
//   - due() (the cron seal loop's source-selection read) SKIPS-WITH-ALERT a future-stamped record (so one
//     bad record cannot halt the whole fleet) while still dispatching a current/legacy one;
//   - trigger() (the manual run-now source-selection read) THROWS on a future-stamped record while still
//     allocating a run for a current/legacy one.
// Every assertion drives the REAL SchedulerDO methods over the shared storage double, never a stub.
//
// Run: node test/validate-config-schema-version.ts

import type { SchedulerDOSurface } from "../src/sched/scheduler-do-base.ts";
import { CONFIG_SCHEMA_VERSION, StateRefusedError, migrateOrRejectConfig } from "../src/sched/scheduler-do-base.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { makeScheduler, makeConfig, seedDueIndex, ok, getFailures } from "./validate-scheduler-shared.ts";

// surf casts the real SchedulerDO to its public testable surface so the production methods
// (persistDownpipeState, addDownpipe, due, trigger) can be driven directly, the SAME code the routes call.
const surf = (dobj: unknown): SchedulerDOSurface => dobj as unknown as SchedulerDOSurface;

// dueState builds a minimal valid DownpipeState that is DUE now (enabled, nextRunAt in the past, not in
// flight), optionally carrying an at-rest schemaVersion stamp.
function dueState(id: string, schemaVersion?: number): DownpipeState {
  const base: DownpipeState = { config: makeConfig(id), nextRunAt: Date.now() - 1000, lastRunId: null, inFlight: false };
  return schemaVersion === undefined ? base : { ...base, schemaVersion };
}

async function main(): Promise<void> {
  // ---- 1. migrateOrRejectConfig: the pure guard, every branch ------------------------------------
  ok("guard: undefined (absent key) passes through", migrateOrRejectConfig(undefined) === undefined);
  const absent = dueState("absent");
  ok("guard: ABSENT schemaVersion (legacy v1) accepted unchanged", migrateOrRejectConfig(absent) === absent);
  const current = { ...dueState("current"), schemaVersion: CONFIG_SCHEMA_VERSION };
  ok("guard: CURRENT version accepted unchanged", migrateOrRejectConfig(current) === current);
  const older = { ...dueState("older"), schemaVersion: CONFIG_SCHEMA_VERSION - 1 };
  ok("guard: OLDER numeric version accepted (forward-migration slot)", migrateOrRejectConfig(older) === older);
  // A PRESENT-but-non-number version stamp is now REFUSED, not accepted. A corrupt or hand-edited stamp
  // (e.g. the string "2") would otherwise DEFEAT the guard silently and let this older code read new-shape state.
  // (An ABSENT stamp is still the legacy-v1 accept path, asserted above, so every existing record stays readable.)
  const corrupt = { ...dueState("corrupt"), schemaVersion: "x" as unknown as number };
  let corruptThrew = false;
  try {
    migrateOrRejectConfig(corrupt);
  } catch (e) {
    corruptThrew = e instanceof StateRefusedError && e.refusalClass === "schema-version-malformed";
  }
  ok("guard: non-number version FAILS LOUD as schema-version-malformed (a corrupt stamp cannot defeat the guard)", corruptThrew);
  let guardThrew = false;
  try {
    migrateOrRejectConfig({ ...dueState("future"), schemaVersion: CONFIG_SCHEMA_VERSION + 1 });
  } catch {
    guardThrew = true;
  }
  ok("guard: strictly-NEWER version FAILS LOUD (throws)", guardThrew);

  // ---- 2. persistDownpipeState stamps at the storage boundary, leaves the in-memory state untouched
  {
    const { storage, stub } = makeScheduler();
    const ds = dueState("stamp-1");
    await surf(stub).persistDownpipeState(ds);
    const stored = storage.rawGet<DownpipeState>("dp:stamp-1");
    ok("write: stored record carries schemaVersion = CONFIG_SCHEMA_VERSION", stored?.schemaVersion === CONFIG_SCHEMA_VERSION);
    ok("write: the in-memory state handed in is NOT mutated (still no schemaVersion)", ds.schemaVersion === undefined);
  }

  // ---- 3. addDownpipe end to end: stored record stamped, returned value byte-identical (no stamp) -
  {
    const { storage, stub } = makeScheduler();
    const returned = await surf(stub).addDownpipe(makeConfig("add-1"));
    ok("addDownpipe: returned state has NO schemaVersion (byte-identical return)", returned.schemaVersion === undefined);
    const stored = storage.rawGet<DownpipeState>("dp:add-1");
    ok("addDownpipe: stored record IS stamped v1", stored?.schemaVersion === CONFIG_SCHEMA_VERSION);
  }

  // ---- 4. due() skips-with-alert a future-stamped record, still dispatches a current/legacy one ---
  {
    const { storage, stub } = makeScheduler();
    // A normal (no-stamp = legacy v1) record and a future-stamped one, both due, both indexed.
    await storage.put("dp:due-ok", dueState("due-ok"));
    await storage.put("dp:due-future", dueState("due-future", CONFIG_SCHEMA_VERSION + 5));
    await seedDueIndex(storage, "due-ok");
    await seedDueIndex(storage, "due-future");
    // The skip alert is log("error", ...), which routes to console.error; capture it.
    const errs: string[] = [];
    const origErr = console.error;
    console.error = (...args: unknown[]): void => {
      errs.push(args.map(String).join(" "));
    };
    let result: { due: DownpipeState[] };
    try {
      result = await surf(stub).due();
    } finally {
      console.error = origErr;
    }
    const ids = result.due.map((d) => d.config.id);
    ok("due: a current/legacy downpipe is dispatched", ids.includes("due-ok"));
    ok("due: a future-stamped downpipe is SKIPPED (not dispatched, no silent partial)", !ids.includes("due-future"));
    ok("due: the skip is ALERTED (logged at error)", errs.some((l) => l.includes("skipping downpipe due-future")));
  }

  // ---- 5. trigger() throws on a future-stamped record, allocates a run for a current/legacy one ---
  {
    const { storage, stub } = makeScheduler();
    await storage.put("dp:trig-future", dueState("trig-future", CONFIG_SCHEMA_VERSION + 1));
    let trigThrew = false;
    try {
      await surf(stub).trigger({ id: "trig-future" });
    } catch {
      trigThrew = true;
    }
    ok("trigger: a future-stamped record FAILS LOUD (throws)", trigThrew);

    await storage.put("dp:trig-ok", dueState("trig-ok"));
    const r = await surf(stub).trigger({ id: "trig-ok" });
    ok("trigger: a current/legacy record allocates a run", "runId" in r && typeof r.runId === "string");
  }

  const failures = getFailures();
  console.log(failures === 0 ? "\nvalidate-config-schema-version: ALL PASS" : `\nvalidate-config-schema-version: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
