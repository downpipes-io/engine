// validate-canary-lease-loss: THE CANARY'S IN-FLIGHT LEASE HAS TWO RECLAIM PATHS AND ONLY ONE SAID SO.
//
// THE DEFECT THIS PINS. `CANARY_LEASE_MS` (20 minutes) bounds the canary's in-flight lease: a flight still
// marked in flight past it is treated as crashed (an evicted worker, a limit, a redeploy mid-cycle) and
// reclaimed. G091's `lost-flight` exists to count exactly that, and the ledger says why in its own words:
// "a flight allocated under a lease that then expired is silently re-allocated on the next tick, so
// 'lastRunAt keeps sliding' has no cause".
//
// `canaryDue` (the cron path) counts it. `canaryRunNow` -- POST /admin/canary/run, the console "Fly now"
// button -- reclaimed the SAME expired lease, cleared `inFlight`, and counted NOTHING. Clearing the flag is
// what makes the count unreachable: the next `canaryDue` sees `inFlight === false` and its booking never
// fires. So the abandonment is recorded when nobody intervenes and ERASED when somebody does, and the
// somebody is an operator pressing the button BECAUSE the bird looks stuck. The action taken in response to
// the symptom destroys the evidence of the cause.
//
// It is SILENT rather than dishonest: no wrong sentence is printed, the key is simply absent from the pack.
// That is the eighth/ninth/tenth defect's shape, and the remedy was already in the product and already used
// at the sibling site, so this registers with `recordCanaryLoss` rather than inventing a second mechanism.
//
// AND THE TWO SITES DISAGREED AT THE BOUNDARY EXACTLY, which is the "each branch correct about its own case"
// trap: `canaryDue` holds the lease while `elapsed < CANARY_LEASE_MS`, so `elapsed === CANARY_LEASE_MS` is
// EXPIRED there; `canaryRunNow` reclaimed only past `> CANARY_LEASE_MS`. At that one instant the cron path
// reclaimed-and-counted while the operator path left the bird wedged. They now share one edge, and the edge
// is asserted from both sides.
//
// THE DOSE IS ELAPSED TIME, INJECTED RATHER THAN WAITED FOR, at the boundary the product actually reads
// (`CanaryState.inFlightSince` against `Date.now()`), because `canaryRunNow` takes no clock argument.
//
// THE INJECTION IS PROVEN BY A KNOWN POSITIVE BEFORE ANY ZERO IT REPORTS IS TRUSTED (section A), and the
// DECLARED sibling books on the same rig in the same session (section B), so a zero from `canaryRunNow` is
// attributable to `canaryRunNow` rather than to a dead ledger. Either failing REFUSES the run at exit 2.
//
// AT THE BOUNDARY THE VALUE IS ABSENT RATHER THAN A ZERO, asserted directly on both sides, because that
// distinction was the whole of the eighth defect: below the edge the `lost-flight` key is not present in the
// aggregate at all, so a healthy estate and a lease-losing one are not the same reading with a different
// number.
//
// THE R1 SHAPE IS GUARDED WITH A SENTINEL THAT MUST BE REACHED, not an absence or a count: section G drives
// two DISTINCT reclaims on ONE subject and requires the value 2 to arrive THROUGH THE REAL PACK PROJECTOR
// (`fetchSchedDiag`, the same read the support pack takes), following the declaration all the way to the
// reader rather than stopping at the ledger. A blank page cannot satisfy it.
//
// Run: node test/validate-canary-lease-loss.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { CANARY_KEY } from "../src/sched/scheduler-do-base.ts";
import { CANARY_LEASE_MS } from "../src/canary/types.ts";
import type { CanaryState } from "../src/canary/types.ts";
import { CANARY_LOSSES_KEY, type CanaryLossRecord } from "../src/sched/sched-fault-ledger.ts";
import { fetchSchedDiag } from "../src/admin/support-sections-diag.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

// A DISTINCT SUBJECT per dose: a fresh DO over a fresh storage, so no dose can inherit another's ledger.
function subject(): { stub: SchedulerDO; storage: MockStorage } {
  const storage = new MockStorage();
  return { stub: new SchedulerDO({ storage } as unknown as DurableObjectState), storage };
}

async function seedDests(storage: MockStorage): Promise<void> {
  await storage.put("destinations", {
    list: [{ id: "r2", label: "primary", endpoint: "https://x.example", bucket: "r2", region: "auto", accessKeyId: "k", secretAccessKey: "s", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }],
    defaultId: "r2",
  });
}

// seedFlight writes the canary state with a flight in flight whose lease STARTED `elapsedMs` ago. That is
// the clock injection: the instant is moved, not the clock. `elapsedMs === null` seeds the pre-lease shape
// (inFlight true, no inFlightSince), which both reclaim paths treat as expired.
//
// `destinationIds` MUST be present. Its absence is what ensureCanaryState reads as a pre-multi-destination
// record, and migrateCanaryState rebuilds that shape with `inFlight: false` and no `inFlightSince` at all --
// so a seed without it is silently discarded and every dose reads "already reclaimed". THE FIRST RUN OF THIS
// VALIDATOR DID EXACTLY THAT, and A1 PASSED on a seed that had never reached the code. Only A2 and the
// sibling control failing turned it into a refusal instead of a green sheet.
async function seedFlight(storage: MockStorage, opts: { enabled?: boolean; inFlight: boolean; elapsedMs: number | null }): Promise<void> {
  const now = Date.now();
  const s: CanaryState = {
    config: { enabled: opts.enabled ?? true, destinationIds: null, intervalSeconds: 3600 },
    dests: [],
    history: [],
    transitions: [],
    status: "unknown",
    inFlight: opts.inFlight,
    ...(opts.elapsedMs === null ? {} : { inFlightSince: now - opts.elapsedMs }),
    lastRunAt: null,
    nextRunAt: null,
    runSeq: 0,
  } as unknown as CanaryState;
  await storage.put(CANARY_KEY, s);
}

const readState = async (storage: MockStorage): Promise<CanaryState> => (await storage.get<CanaryState>(CANARY_KEY))!;
const readLosses = async (storage: MockStorage): Promise<CanaryLossRecord | undefined> => storage.get<CanaryLossRecord>(CANARY_LOSSES_KEY);

// lostFlightCount returns `undefined` when the key is ABSENT and the integer when it is present. The two are
// deliberately NOT collapsed to 0: an absent key and a zero are the distinction this whole validator turns on.
async function lostFlightCount(storage: MockStorage): Promise<number | undefined> {
  const rec = await readLosses(storage);
  return rec?.counts?.["lost-flight"]?.count;
}

// ---- A. THE CLOCK INJECTION, PROVEN TWO-SIDED BEFORE ANY ZERO IS TRUSTED --------------------------------
// An instrument that answers the same thing at both doses is not measuring the dose. An earlier pass's temporal
// sweep answered DECLARED at both trees on its first run and only a known positive caught it.
async function sectionInjection(): Promise<boolean> {
  console.log("\nA. the clock injection (known positive, run FIRST)");
  const over = subject();
  await seedDests(over.storage);
  await seedFlight(over.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS + 60_000 });
  await over.stub.canaryRunNow();
  const overReclaimed = (await readState(over.storage)).inFlight === false;

  const under = subject();
  await seedDests(under.storage);
  await seedFlight(under.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS - 60_000 });
  await under.stub.canaryRunNow();
  const underReclaimed = (await readState(under.storage)).inFlight === false;

  ok("A1 a lease seeded a minute PAST CANARY_LEASE_MS is reclaimed (the dose reached the code)", overReclaimed);
  ok("A2 a lease seeded a minute SHORT of it is NOT reclaimed (the dose is two-sided)", underReclaimed === false);
  return overReclaimed && !underReclaimed;
}

// ---- B. THE DECLARED SIBLING ON THE SAME RIG (instrument control) ---------------------------------------
// canaryDue books `lost-flight` for the same abandonment. If IT cannot book in this session then the ledger
// write path is dead and every zero below is worthless.
async function sectionSiblingControl(): Promise<boolean> {
  console.log("\nB. the DECLARED sibling books on this rig, in this session");
  const s = subject();
  await seedDests(s.storage);
  await seedFlight(s.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS + 60_000 });
  await s.stub.canaryDue(Date.now());
  const n = await lostFlightCount(s.storage);
  ok("B1 canaryDue books lost-flight for an expired lease (the ledger write path is alive)", n === 1);
  return n === 1;
}

// ---- C/D. DOSE-RESPONSE OVER THE BOUNDARY, DISTINCT SUBJECTS -------------------------------------------
interface Dose { label: string; elapsedMs: number | null; expired: boolean }
const DOSES: Dose[] = [
  { label: "0", elapsedMs: 0, expired: false },
  { label: "1ms", elapsedMs: 1, expired: false },
  { label: "1min", elapsedMs: 60_000, expired: false },
  { label: "half the lease", elapsedMs: Math.floor(CANARY_LEASE_MS / 2), expired: false },
  { label: "LEASE-1ms", elapsedMs: CANARY_LEASE_MS - 1, expired: false },
  { label: "LEASE exactly", elapsedMs: CANARY_LEASE_MS, expired: true },
  { label: "LEASE+1ms", elapsedMs: CANARY_LEASE_MS + 1, expired: true },
  { label: "2x LEASE", elapsedMs: CANARY_LEASE_MS * 2, expired: true },
  { label: "24h", elapsedMs: 24 * 60 * 60 * 1000, expired: true },
  { label: "no inFlightSince at all (pre-lease record)", elapsedMs: null, expired: true },
];

async function sectionDoseResponse(): Promise<void> {
  console.log("\nC. dose-response over CANARY_LEASE_MS, one fresh subject per dose");
  for (const d of DOSES) {
    const s = subject();
    await seedDests(s.storage);
    await seedFlight(s.storage, { inFlight: true, elapsedMs: d.elapsedMs });
    await s.stub.canaryRunNow();
    const reclaimed = (await readState(s.storage)).inFlight === false;
    const n = await lostFlightCount(s.storage);
    ok(`C ${d.label}: reclaimed=${d.expired}`, reclaimed === d.expired);
    if (d.expired) {
      ok(`C ${d.label}: lost-flight is PRESENT and counts exactly 1`, n === 1);
    } else {
      // ABSENT, not zero. A zero would make a healthy estate and a lease-losing one the same reading.
      ok(`C ${d.label}: lost-flight is ABSENT (not a zero)`, n === undefined);
    }
    // nextRunAt is armed either way: the reclaim is not what makes the bird due.
    ok(`C ${d.label}: the flight is armed regardless`, (await readState(s.storage)).nextRunAt === 0);
  }
}

async function sectionEdge(): Promise<void> {
  console.log("\nD. the edge exactly, asserted from both sides");
  const below = subject();
  await seedDests(below.storage);
  await seedFlight(below.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS - 1 });
  await below.stub.canaryRunNow();
  ok("D1 at LEASE-1ms the lease is HELD", (await readState(below.storage)).inFlight === true);
  ok("D2 at LEASE-1ms nothing is booked at all", (await readLosses(below.storage)) === undefined);

  const at = subject();
  await seedDests(at.storage);
  await seedFlight(at.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS });
  await at.stub.canaryRunNow();
  ok("D3 at the lease EXACTLY the lease is reclaimed", (await readState(at.storage)).inFlight === false);
  ok("D4 at the lease EXACTLY the loss is booked", (await lostFlightCount(at.storage)) === 1);
}

// ---- E. THE INTERNAL DIFFERENTIAL: the module disagreed with itself -------------------------------------
// The SAME state, the SAME elapsed time, differing only in WHICH reclaim path runs. Pre-fix the cron path
// booked and the operator path did not, at every dose past the lease, and the two disagreed outright at the
// lease exactly. This is the check that fails loudest if the repair is reverted.
async function sectionInternalDifferential(): Promise<void> {
  console.log("\nE. internal differential: the two reclaim paths must agree");
  for (const elapsed of [CANARY_LEASE_MS, CANARY_LEASE_MS + 1, CANARY_LEASE_MS * 3]) {
    const viaDue = subject();
    await seedDests(viaDue.storage);
    await seedFlight(viaDue.storage, { inFlight: true, elapsedMs: elapsed });
    await viaDue.stub.canaryDue(Date.now());

    const viaRunNow = subject();
    await seedDests(viaRunNow.storage);
    await seedFlight(viaRunNow.storage, { inFlight: true, elapsedMs: elapsed });
    await viaRunNow.stub.canaryRunNow();

    const a = await lostFlightCount(viaDue.storage);
    const b = await lostFlightCount(viaRunNow.storage);
    ok(`E elapsed=${elapsed}ms: the cron path books ${String(a)} and the operator path books the same`, a === 1 && b === 1);
  }
  // And the same differential at the one instant the two edges used to differ.
  const boundaryDue = subject();
  await seedDests(boundaryDue.storage);
  await seedFlight(boundaryDue.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS });
  await boundaryDue.stub.canaryDue(Date.now());
  ok("E4 at the lease EXACTLY the cron path already treated it as expired", (await lostFlightCount(boundaryDue.storage)) === 1);
}

// ---- F. THE OVER-FIX DIRECTION: four negatives that must classify DIFFERENTLY --------------------------
// The cheap repair books a loss on every press of the button. These are the states where booking would be a
// lie, and each must stay ABSENT.
async function sectionOverFix(): Promise<void> {
  console.log("\nF. negatives: states where a booking would be a lie");
  const idle = subject();
  await seedDests(idle.storage);
  await seedFlight(idle.storage, { inFlight: false, elapsedMs: null });
  await idle.stub.canaryRunNow();
  ok("F1 a bird that is NOT in flight has lost nothing", (await lostFlightCount(idle.storage)) === undefined);

  const live = subject();
  await seedDests(live.storage);
  await seedFlight(live.storage, { inFlight: true, elapsedMs: Math.floor(CANARY_LEASE_MS / 2) });
  await live.stub.canaryRunNow();
  ok("F2 a lease still inside its window books nothing", (await lostFlightCount(live.storage)) === undefined);
  ok("F2b ... and the live flight is left in flight", (await readState(live.storage)).inFlight === true);

  const disabled = subject();
  await seedDests(disabled.storage);
  await seedFlight(disabled.storage, { enabled: false, inFlight: true, elapsedMs: CANARY_LEASE_MS * 4 });
  let threw = false;
  try {
    await disabled.stub.canaryRunNow();
  } catch {
    threw = true;
  }
  ok("F3 a disabled bird refuses before any reclaim", threw);
  ok("F3b ... and books no canary loss (the refusal is its own record)", (await lostFlightCount(disabled.storage)) === undefined);

  const twice = subject();
  await seedDests(twice.storage);
  await seedFlight(twice.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS * 2 });
  await twice.stub.canaryRunNow();
  await twice.stub.canaryRunNow();
  ok("F4 pressing the button twice books ONE loss, not two (the second reclaims nothing)", (await lostFlightCount(twice.storage)) === 1);
}

// ---- G. THE SENTINEL THAT MUST BE REACHED, THROUGH THE REAL PACK READER ---------------------------------
// Not an absence and not a bare count: TWO distinct abandonments on ONE subject must arrive at the value 2
// through `fetchSchedDiag`, the projection the support pack itself takes. An assertion that only counts
// absences would hold over a blank page; this one cannot.
async function sectionPackReader(): Promise<void> {
  console.log("\nG. the declaration reaches the PACK READER, and the value must be REACHED");
  const s = subject();
  await seedDests(s.storage);
  await seedFlight(s.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS * 2 });
  await s.stub.canaryRunNow();
  // A second abandonment on the same subject: re-arm the flight, let its lease lapse, press the button again.
  await seedFlight(s.storage, { inFlight: true, elapsedMs: CANARY_LEASE_MS * 5 });
  await s.stub.canaryRunNow();
  ok("G1 two abandonments accumulate to 2 in the ledger", (await lostFlightCount(s.storage)) === 2);

  const stub = { fetch: (u: string, init?: RequestInit) => s.stub.fetch(new Request(u, init)) } as unknown as DurableObjectStub;
  const diag = await fetchSchedDiag(stub);
  const cl = diag.canaryLosses as { counts?: Record<string, { count: number; lastAt: string }>; uncoveredDestIds?: string[] } | undefined;
  ok("G2 the pack projection carries canaryLosses at all", cl !== undefined);
  ok("G3 SENTINEL: the pack reader reports lost-flight = 2 (a value that must be REACHED)", cl?.counts?.["lost-flight"]?.count === 2);
  ok("G4 the projected row carries a clamped ISO instant", typeof cl?.counts?.["lost-flight"]?.lastAt === "string" && !Number.isNaN(Date.parse(cl!.counts!["lost-flight"]!.lastAt)));
  // Redaction: this kind names no destination. uncoveredDestIds belongs to dest-excluded-by-cap alone.
  ok("G5 no destination label rides on a lost-flight booking", (cl?.uncoveredDestIds ?? []).length === 0);
}

async function main(): Promise<void> {
  const injectionOk = await sectionInjection();
  const siblingOk = await sectionSiblingControl();
  if (!injectionOk || !siblingOk) {
    console.log("\nREFUSED: the clock injection or the sibling control did not hold, so no zero below is a measurement");
    if (1 > 0) process.exitCode = 1;
    process.exit(2);
  }
  await sectionDoseResponse();
  await sectionEdge();
  await sectionInternalDifferential();
  await sectionOverFix();
  await sectionPackReader();
  console.log(failures === 0 ? "\nCANARY LEASE LOSS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
