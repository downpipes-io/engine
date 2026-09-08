// Version skew / migration: prove the fail-closed schema-migration guards that stand between a
// freshly deployed or self-updated engine and the state or archives a DIFFERENT version wrote. This is the
// owner's top-fear surface: a deploy that cannot read the state the prior version persisted, or that
// silently reads a record a NEWER version wrote and seals the wrong thing while reporting ok. Net-zero by
// construction: synthetic in-memory records and fixtures only. No estate, no network, no deploy, no
// Date.now() in the graded assertions. Run:
//   node test/validate-version-skew.ts
//
// Three version-skew surfaces, each a read-time guard the running code applies to a record it did not
// necessarily write:
//  1. migrateOrRejectConfig (scheduler-do-base.ts) is the read-time guard for the persisted per-downpipe
//     DownpipeState (the dp:<id> record). It ACCEPTS an absent stamp (legacy v1), the current version and an
//     older number unchanged, REFUSES a strictly-newer schemaVersion (fail closed, a rollback reading
//     new-shape state), and REFUSES a present-but-non-number stamp. This is the data-plane surface: a
//     mis-read here could seal the WRONG source set while still reporting ok.
//  2. migrateCanaryState / ensureCanaryState (scheduler-do-canary.ts) is the canary-state sibling. Its
//     migration is SHAPE-based, not version-numbered: a legacy single-destination record (no destinationIds)
//     is upgraded to the multi-destination shape, and a current record is passed through unchanged, NOT
//     re-migrated. Documented asymmetry: because the canary record carries no version number, there is no
//     schema-newer REFUSAL here (unlike the config guard). It is the engine's own known-answer self-test
//     state, not customer data, so the deliberate scope of the version gate is the config surface. This test
//     asserts what the code ACTUALLY does and names the asymmetry rather than assuming a refusal that is not
//     there.
//  3. checkFormatVersion (structural-gates.ts) is the archive read-time guard. It ACCEPTS exactly its own
//     major.minor (downpipe/0.1.x) at any patch and REFUSES every other label (a newer minor is an
//     incompatible format identity, a newer major, an older minor, a foreign prefix, a malformed label), so
//     a reader never silently reads bytes under a format it does not implement.
//
// Note on existing coverage: validate-config-schema-version.ts already drives migrateOrRejectConfig through
// the real SchedulerDO end to end (persist, addDownpipe, due, trigger). This axis file is the consolidated
// version-skew view across all three surfaces at the guard level, and it carries the required DEFAULT-FAIL
// refuters: a broken migrateOrRejectConfig that silently accepts a schema-newer record, and a broken
// checkFormatVersion that reads any label sharing the prefix, each proving its graded cell would fail a
// broken implementation.

import { CONFIG_SCHEMA_VERSION, migrateOrRejectConfig, StateRefusedError } from "../src/sched/scheduler-do-base.ts";
import { CANARY_KEY } from "../src/sched/scheduler-do-records.ts";
import { checkFormatVersion } from "../src/format/structural-gates.ts";
import { VERSION } from "../src/format/version.ts";
import { makeScheduler } from "./validate-scheduler-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// surf casts the real SchedulerDO to a loose surface so the production canary methods can be driven
// directly, the same code the read path calls. Types are stripped at runtime, so this is identity.
// biome-ignore lint/suspicious/noExplicitAny: test-only cast to reach the real instance methods.
const surf = (o: unknown): any => o;

// threw runs a thunk and reports only whether it threw, for the accept (no throw) versus refuse (throw)
// distinction the format guard and the config guard both express by throwing.
function threw(fn: () => void): boolean {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}

// refusalClassOf runs a config-guard thunk and returns the typed refusal class it threw, or null if it did
// not throw, or "OTHER" if it threw something that was not a StateRefusedError. This proves the guard fails
// LOUD with the CLOSED class the caller keys its redaction-safe evidence off, not a bare Error.
function refusalClassOf(fn: () => void): string | null {
  try {
    fn();
    return null;
  } catch (e) {
    return e instanceof StateRefusedError ? e.refusalClass : "OTHER";
  }
}

// state builds a minimal persisted DownpipeState, optionally carrying an at-rest schemaVersion stamp.
// migrateOrRejectConfig reads only the stamp and returns the record by reference, so the rest is filler that
// keeps the record shaped like a real one.
function state(schemaVersion?: number): unknown {
  const base = { config: { id: "dp-1" }, nextRunAt: 0, lastRunId: null, inFlight: false };
  return schemaVersion === undefined ? base : { ...base, schemaVersion };
}

// ---- 1. migrateOrRejectConfig: accept legacy / current / older, refuse newer and malformed -------------
function testConfigGuard(): void {
  ok("config: undefined (absent record) passes through as undefined", migrateOrRejectConfig(undefined) === undefined);

  const legacy = state(); // absent schemaVersion = a record written before the stamp shipped
  ok("config: ACCEPT legacy (absent stamp) unchanged, by reference", migrateOrRejectConfig(legacy as never) === legacy);

  const current = state(CONFIG_SCHEMA_VERSION);
  ok("config: ACCEPT current version unchanged, by reference", migrateOrRejectConfig(current as never) === current);

  const older = state(CONFIG_SCHEMA_VERSION - 1);
  ok("config: ACCEPT older numeric version unchanged (the forward-migration slot)", migrateOrRejectConfig(older as never) === older);

  // The fail-closed cell: a record a NEWER engine wrote must be REFUSED, never read under older code.
  const newer = state(CONFIG_SCHEMA_VERSION + 1);
  ok("config: REFUSE strictly-newer version (fail closed, throws)", threw(() => migrateOrRejectConfig(newer as never)));
  ok("config: REFUSE strictly-newer is typed schema-newer", refusalClassOf(() => migrateOrRejectConfig(newer as never)) === "schema-newer");
  let storedVersion = -1;
  try {
    migrateOrRejectConfig(newer as never);
  } catch (e) {
    if (e instanceof StateRefusedError) storedVersion = e.storedVersion;
  }
  ok("config: schema-newer refusal carries the stored version as an integer", storedVersion === CONFIG_SCHEMA_VERSION + 1);

  const wayNewer = state(CONFIG_SCHEMA_VERSION + 99);
  ok("config: REFUSE a far-newer version too (throws schema-newer)", refusalClassOf(() => migrateOrRejectConfig(wayNewer as never)) === "schema-newer");

  // A present-but-non-number stamp is a corrupt or hand-edited record and must fail loud, not be read.
  const malformed = { ...(state() as object), schemaVersion: "2" };
  ok("config: REFUSE a non-number stamp (throws)", threw(() => migrateOrRejectConfig(malformed as never)));
  ok("config: non-number stamp is typed schema-version-malformed", refusalClassOf(() => migrateOrRejectConfig(malformed as never)) === "schema-version-malformed");
}

// ---- 2. migrateCanaryState / ensureCanaryState: accept legacy shape, pass current through --------------
async function testCanaryMigration(): Promise<void> {
  const { storage, stub } = makeScheduler();

  // A legacy single-destination record: config.destinationId pinned, top-level lastRunId and a one-item
  // history, and NO destinationIds. migrateCanaryState upgrades it to the multi-destination shape.
  const check = { at: "2026-07-20T00:00:00.000Z", runSeq: 3, status: "alive", destinationId: "dst-A" };
  const legacyPinned = {
    config: { enabled: true, destinationId: "dst-A", intervalSeconds: 3600 },
    status: "alive",
    lastRunAt: "2026-07-20T00:00:00.000Z",
    nextRunAt: 1_800_000,
    runSeq: 3,
    deadSince: null,
    lastRunId: "run-xyz",
    consecutivePasses: 2,
    history: [check],
  };
  const migrated = surf(stub).migrateCanaryState(legacyPinned);
  ok("canary: ACCEPT legacy pinned -> destinationIds becomes [pinned]", Array.isArray(migrated.config.destinationIds) && migrated.config.destinationIds.length === 1 && migrated.config.destinationIds[0] === "dst-A");
  ok("canary: ACCEPT legacy pinned -> enabled and intervalSeconds preserved", migrated.config.enabled === true && migrated.config.intervalSeconds === 3600);
  ok("canary: ACCEPT legacy pinned -> status, lastRunAt, nextRunAt, runSeq preserved", migrated.status === "alive" && migrated.lastRunAt === "2026-07-20T00:00:00.000Z" && migrated.nextRunAt === 1_800_000 && migrated.runSeq === 3);
  ok("canary: ACCEPT legacy pinned -> inFlight forced false (a migrated record is not mid-flight)", migrated.inFlight === false);
  ok("canary: ACCEPT legacy pinned -> one per-destination dest seeded from the old single liveness", Array.isArray(migrated.dests) && migrated.dests.length === 1 && migrated.dests[0].destinationId === "dst-A" && migrated.dests[0].lastRunId === "run-xyz");
  ok("canary: ACCEPT legacy pinned -> old history lifted into a per-flight shape, results carry the old check", Array.isArray(migrated.history) && migrated.history.length === 1 && migrated.history[0].runSeq === 3 && migrated.history[0].results[0].destinationId === "dst-A");

  // A legacy DEFAULT record: old null destination (all destinations) and no completed run, so no dest seeded.
  const legacyDefault = {
    config: { enabled: true, destinationId: null, intervalSeconds: 3600 },
    status: "pending",
    lastRunAt: null,
    nextRunAt: null,
    runSeq: 0,
    history: [],
  };
  const migratedDefault = surf(stub).migrateCanaryState(legacyDefault);
  ok("canary: ACCEPT legacy default (null) -> destinationIds stays null (all destinations)", migratedDefault.config.destinationIds === null);
  ok("canary: ACCEPT legacy default with no prior run -> no per-destination state seeded", Array.isArray(migratedDefault.dests) && migratedDefault.dests.length === 0);

  // End to end through the real read path: ensureCanaryState detects a legacy record (destinationIds absent)
  // and migrates it, and returns a CURRENT record unchanged (does NOT re-migrate or mangle it).
  await storage.put(CANARY_KEY, legacyPinned);
  const routedLegacy = await surf(stub).ensureCanaryState();
  ok("canary: ensureCanaryState ROUTES a legacy record to migration (destinationIds now [pinned])", Array.isArray(routedLegacy.config.destinationIds) && routedLegacy.config.destinationIds[0] === "dst-A" && routedLegacy.inFlight === false);

  // A current record carries destinationIds and inFlight true. A passthrough returns it unchanged; a
  // re-migration would force inFlight false and rebuild dests. inFlight staying true proves passthrough.
  const currentRec = {
    config: { enabled: true, destinationIds: ["dst-X", "dst-Y"], intervalSeconds: 3600 },
    status: "alive",
    lastRunAt: "2026-07-21T00:00:00.000Z",
    nextRunAt: 2_000_000,
    inFlight: true,
    runSeq: 7,
    dests: [],
    history: [],
  };
  await storage.put(CANARY_KEY, currentRec);
  const routedCurrent = await surf(stub).ensureCanaryState();
  ok("canary: ACCEPT current record unchanged (destinationIds preserved, NOT re-migrated)", Array.isArray(routedCurrent.config.destinationIds) && routedCurrent.config.destinationIds.length === 2 && routedCurrent.config.destinationIds[0] === "dst-X");
  ok("canary: ACCEPT current record is a passthrough (inFlight true survives, runSeq preserved)", routedCurrent.inFlight === true && routedCurrent.runSeq === 7);
}

// ---- 3. checkFormatVersion: accept downpipe/0.1.x, refuse every other label ----------------------------
function testFormatGuard(): void {
  // ACCEPT: the frozen label and any patch within the reader's own major.minor.
  ok(`format: ACCEPT the frozen VERSION label (${VERSION})`, !threw(() => checkFormatVersion(VERSION)));
  ok("format: ACCEPT downpipe/0.1.0", !threw(() => checkFormatVersion("downpipe/0.1.0")));
  ok("format: ACCEPT downpipe/0.1.9 (a higher patch)", !threw(() => checkFormatVersion("downpipe/0.1.9")));
  ok("format: ACCEPT downpipe/0.1.123 (any patch)", !threw(() => checkFormatVersion("downpipe/0.1.123")));

  // REFUSE: a newer minor is an incompatible format identity, a newer major, an older minor.
  ok("format: REFUSE downpipe/0.2.0 (newer minor, incompatible identity)", threw(() => checkFormatVersion("downpipe/0.2.0")));
  ok("format: REFUSE downpipe/1.0.0 (newer major)", threw(() => checkFormatVersion("downpipe/1.0.0")));
  ok("format: REFUSE downpipe/0.0.9 (older minor)", threw(() => checkFormatVersion("downpipe/0.0.9")));

  // REFUSE: a foreign prefix and malformed labels the reader must never read. A TWO-component label is
  // malformed rather than a version somebody could go and find a reader for: the pre-release lineage that
  // stamped MAJOR.MINOR was retired and nothing obtainable emits one. downpipe/0.1 is the
  // trap in that shape, carrying the same two numbers this build implements.
  ok("format: REFUSE a foreign label (borg/0.1.0)", threw(() => checkFormatVersion("borg/0.1.0")));
  ok("format: REFUSE downpipe/0.1 (missing the patch component)", threw(() => checkFormatVersion("downpipe/0.1")));
  ok("format: REFUSE downpipe/1.0 (a two-component label is not a version)", threw(() => checkFormatVersion("downpipe/1.0")));
  ok("format: REFUSE downpipe/ (empty version components)", threw(() => checkFormatVersion("downpipe/")));
  ok("format: REFUSE the empty string", threw(() => checkFormatVersion("")));
}

// ---- REFUTERS: prove the graded cells above catch a broken implementation -------------------------------

// brokenMigrateSilentAccept is the DEFAULT-FAIL refuter the axis requires: a migrateOrRejectConfig that
// silently ACCEPTS whatever it is handed, never refusing a schema-newer record. This is the exact regression
// the fail-closed guard exists to prevent (an older engine reading new-shape state it cannot understand).
function brokenMigrateSilentAccept(raw: unknown): unknown {
  return raw;
}

// brokenCheckFormatPrefixOnly is the format-guard refuter: a checkFormatVersion that validates only the
// prefix and reads any label that starts with downpipe/, so it silently accepts a newer or foreign minor.
function brokenCheckFormatPrefixOnly(v: string): void {
  if (!v.startsWith("downpipe/")) throw new Error("not a downpipe label");
}

function testRefuters(): void {
  // Config guard: the real guard refuses a schema-newer record; the silent-accept impl returns it.
  const newer = state(CONFIG_SCHEMA_VERSION + 1);
  const realRefused = threw(() => migrateOrRejectConfig(newer as never));
  const brokenRefused = threw(() => brokenMigrateSilentAccept(newer));
  ok("REFUTER[config silent-accept]: the REAL guard REFUSES a schema-newer record (throws)", realRefused);
  ok(
    "REFUTER[config silent-accept]: a silent-accept impl RETURNS the newer record (no throw) -> the graded refuse-newer cell would FAIL it",
    brokenRefused === false && brokenMigrateSilentAccept(newer) === newer,
  );

  // Format guard: the real guard refuses a newer minor and a far-off major; the prefix-only impl accepts both.
  const realRefusedMinor = threw(() => checkFormatVersion("downpipe/0.2.0"));
  const brokenAcceptsMinor = !threw(() => brokenCheckFormatPrefixOnly("downpipe/0.2.0"));
  const brokenAcceptsMajor = !threw(() => brokenCheckFormatPrefixOnly("downpipe/9.9.9"));
  ok("REFUTER[format prefix-only]: the REAL guard REFUSES downpipe/0.2.0 (newer minor)", realRefusedMinor);
  ok(
    "REFUTER[format prefix-only]: a prefix-only impl ACCEPTS downpipe/0.2.0 and downpipe/9.9.9 -> the graded refuse cells would FAIL it",
    brokenAcceptsMinor && brokenAcceptsMajor,
  );
}

async function main(): Promise<void> {
  testConfigGuard();
  await testCanaryMigration();
  testFormatGuard();
  testRefuters();

  console.log(failures === 0 ? "\nVERSION-SKEW VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
