// validate-cov-sched-scheduler-do-canary: branch-coverage proof for the CanaryMixin (the on-by-default
// known-answer integrity flight) extracted into src/sched/scheduler-do-canary.ts. It drives the REAL
// SchedulerDO over in-memory storage through the DO's own canary routes (GET /canary, POST /canary/config,
// /canary/due, /canary/complete, /canary/run-now) and, where the wire (JSON) cannot carry a value, the real
// method on the real instance. Every assertion checks a real outcome: a view field, a returned transition,
// a stored liveness, or an HTTP status. The aim is the error returns, the owner gate, the absent-config
// fallbacks, the validation rejections, the migration of an old single-destination record, the lease and
// in-flight edge conditions, and the per-destination liveness folding (dead/recovered/sticky-dead) the
// existing validate-canary.ts only partly reaches.
//
// Run: node test/validate-cov-sched-scheduler-do-canary.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import { CANARY_KEY } from "../src/sched/scheduler-do-base.ts";
import { CANARY_LEASE_MS } from "../src/canary/types.ts";
import type { CanaryView, CanaryFlightPlan, CanaryCheckResult, CanaryState } from "../src/canary/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { stub: SchedulerDO; storage: MockStorage } {
  const storage = new MockStorage();
  const stub = new SchedulerDO({ storage } as unknown as DurableObjectState);
  return { stub, storage };
}

// A bare-token caller resolves (roleForCaller) to owner break-glass, so the canary owner re-check passes; the
// canary internal routes ignore the header but it is harmless. A second access-method caller resolves to
// viewer (no role table entry), which the owner gate refuses.
const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
const VIEWER_CALLER: Caller = { method: "access", email: "viewer-cov@acme.example", subject: "viewer-cov-subject", role: "viewer", groups: [] };

function doFetch(dobj: SchedulerDO, method: string, path: string, body?: unknown, caller: Caller = OWNER_CALLER): Promise<Response> {
  return dobj.fetch(
    new Request(`https://scheduler.internal${path}`, {
      method,
      headers: { [CALLER_HEADER]: encodeCaller(caller), ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }),
  );
}
const getView = async (dobj: SchedulerDO): Promise<CanaryView> => (await (await doFetch(dobj, "GET", "/canary")).json()) as CanaryView;

// seedDests writes the destination collection the canary fans out over. label is optional so the "label
// falls back to the id" branch can be reached with a deliberately label-less destination.
async function seedDests(storage: MockStorage, dests: Array<{ id: string; label?: string }>, defaultId: string): Promise<void> {
  const list = dests.map((d) => ({ id: d.id, ...(d.label !== undefined ? { label: d.label } : {}), endpoint: "https://x.example", bucket: d.id, region: "auto", accessKeyId: "k", secretAccessKey: "s", setAt: 1, setBy: null, verifiedAt: 1, deleteProbe: "ok" }));
  await storage.put("destinations", { list, defaultId });
}

const aliveOf = (id: string | null): CanaryCheckResult => ({ status: "alive", durationMs: 5, destinationId: id, aspects: [], byteDelta: 0, deadReason: null });
const deadOf = (id: string | null): CanaryCheckResult => ({ status: "dead", durationMs: 6, destinationId: id, aspects: [{ key: "decrypt-integrity", outcome: "fail", detail: "1 byte strayed" }], byteDelta: 1, deadReason: "decrypt-integrity: 1 byte strayed" });
const ailingOf = (id: string | null): CanaryCheckResult => ({ status: "ailing", durationMs: 7, destinationId: id, aspects: [], byteDelta: null, deadReason: null });

interface Transition {
  destinationId: string | null;
  label: string;
  transitioned: "dead" | "recovered";
}
// flyOnce arms an immediate flight (run-now -> due -> complete) with the supplied results and returns the
// transitions the completion reports. nowMs increments per call so each due check clears the prior nextRunAt.
let flyClock = 2_000_000;
async function flyOnce(dobj: SchedulerDO, results: CanaryCheckResult[]): Promise<Transition[]> {
  await doFetch(dobj, "POST", "/canary/run-now");
  flyClock += 1_000_000;
  const due = (await (await doFetch(dobj, "POST", "/canary/due", { nowMs: flyClock })).json()) as { due: boolean; run?: CanaryFlightPlan };
  if (!due.due || !due.run) throw new Error("flyOnce: expected the canary to be due");
  return ((await (await doFetch(dobj, "POST", "/canary/complete", { run: due.run, results })).json()) as { transitions: Transition[] }).transitions;
}

// ---- S1: the full multi-destination lifecycle (config clamps, due/lease, complete folding) -----------------
async function sectionLifecycle(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await seedDests(storage, [{ id: "r2", label: "R2 Primary" }, { id: "s3", label: "S3 Backup" }], "r2");

  const v0 = await getView(stub);
  ok("S1 fresh canary defaults to enabled, all destinations, pending", v0.config.enabled === true && v0.flyingToAll === true && v0.status === "pending");
  ok("S1 fresh view lists both destinations as pending with the default flagged", v0.dests.length === 2 && v0.dests.find((d) => d.destinationId === "r2")!.isDefault === true && v0.dests.find((d) => d.destinationId === "s3")!.isDefault === false && v0.dests.every((d) => d.status === "pending"));

  // Config BEFORE any flight: nothing else set, so the schedule stays unscheduled (lastRunAt is null).
  const cMid = (await (await doFetch(stub, "POST", "/canary/config", { intervalSeconds: 7200 })).json()) as CanaryView;
  ok("S1 a mid-range cadence is accepted verbatim", cMid.config.intervalSeconds === 7200 && cMid.nextRunAt === null);
  const cLow = (await (await doFetch(stub, "POST", "/canary/config", { intervalSeconds: 100 })).json()) as CanaryView;
  ok("S1 a too-small cadence is clamped up to the 300s floor", cLow.config.intervalSeconds === 300);
  const cHigh = (await (await doFetch(stub, "POST", "/canary/config", { intervalSeconds: 999_999 })).json()) as CanaryView;
  ok("S1 a too-large cadence is clamped down to the 86400s ceiling", cHigh.config.intervalSeconds === 86_400);

  // First flight: due with one runId per destination, then the in-flight lease holds a second due-check off.
  const due1 = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 1_000_000 })).json()) as { due: boolean; run?: CanaryFlightPlan };
  ok("S1 first flight is due with a per-destination plan and distinct runIds", due1.due === true && due1.run!.dests.length === 2 && due1.run!.dests[0]!.runId !== due1.run!.dests[1]!.runId);
  ok("S1 the first flight has no prior cell to clean up", due1.run!.dests.every((d) => d.cleanupRunId === null));
  const due1b = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 1_000_100 })).json()) as { due: boolean };
  ok("S1 a second due-check inside the lease is not re-flown", due1b.due === false);

  // Complete one alive + one dead -> the dead destination transitions, with its resolved label.
  const t1 = ((await (await doFetch(stub, "POST", "/canary/complete", { run: due1.run, results: [aliveOf("r2"), deadOf("s3")] })).json()) as { transitions: Transition[] }).transitions;
  ok("S1 exactly the dead destination transitions, labelled from the collection", t1.length === 1 && t1[0]!.destinationId === "s3" && t1[0]!.transitioned === "dead" && t1[0]!.label === "S3 Backup");
  const v1 = await getView(stub);
  ok("S1 the aggregate is dead when any destination died, with a per-destination deadSince", v1.status === "dead" && v1.dests.find((d) => d.destinationId === "r2")!.status === "alive" && v1.dests.find((d) => d.destinationId === "s3")!.deadSince !== null && v1.dests.find((d) => d.destinationId === "s3")!.lastCheck !== null);

  // After a completed flight nextRunAt is in the future, so a low-nowMs due-check is not yet due.
  const dueEarly = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 5 })).json()) as { due: boolean };
  ok("S1 a due-check before nextRunAt is not due", dueEarly.due === false);

  // run-now from a NOT-in-flight state leaves the lease alone (no reclaim), and the next flight cleans up the prior cell.
  await doFetch(stub, "POST", "/canary/run-now");
  const due2 = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 6_000_000 })).json()) as { due: boolean; run?: CanaryFlightPlan };
  ok("S1 run-now makes the next flight due, carrying the prior cell to clean up", due2.due === true && due2.run!.dests.find((d) => d.destinationId === "s3")!.cleanupRunId !== null);
  const t2 = ((await (await doFetch(stub, "POST", "/canary/complete", { run: due2.run, results: [aliveOf("r2"), aliveOf("s3")] })).json()) as { transitions: Transition[] }).transitions;
  ok("S1 the recovered destination transitions back to alive", t2.length === 1 && t2[0]!.destinationId === "s3" && t2[0]!.transitioned === "recovered");
  ok("S1 the aggregate is alive once every destination is alive again", (await getView(stub)).status === "alive");

  // s3 dies, then dies AGAIN: the first death transitions + stamps deadSince; the second neither transitions
  // nor re-stamps (the death is sticky). r2 staying alive across flights exercises the consecutive-pass count.
  const t3 = await flyOnce(stub, [aliveOf("r2"), deadOf("s3")]);
  ok("S1 a fresh death transitions to dead", t3.length === 1 && t3[0]!.transitioned === "dead");
  const t4 = await flyOnce(stub, [aliveOf("r2"), deadOf("s3")]);
  ok("S1 an already-dead destination does not transition again", t4.length === 0);

  // Ailing folding: the alive destination goes ailing (status becomes ailing); the dead one stays dead (sticky).
  await flyOnce(stub, [ailingOf("r2"), ailingOf("s3")]);
  const vAil = await getView(stub);
  ok("S1 an ailing flight sets the previously-alive destination to ailing", vAil.dests.find((d) => d.destinationId === "r2")!.status === "ailing");
  ok("S1 an ailing flight cannot clear a sticky death", vAil.dests.find((d) => d.destinationId === "s3")!.status === "dead" && vAil.status === "dead");

  // Pin to a subset: the dropped destination's per-destination state is pruned on the next completion.
  const vPin = (await (await doFetch(stub, "POST", "/canary/config", { destinationIds: ["r2"] })).json()) as CanaryView;
  ok("S1 pinning a subset stops flying to all and lists only the pinned destination", vPin.flyingToAll === false && vPin.dests.length === 1 && vPin.dests[0]!.destinationId === "r2");
  await flyOnce(stub, [aliveOf("r2")]);
  const vPruned = await getView(stub);
  ok("S1 the de-selected destination is pruned from the per-destination state", vPruned.dests.length === 1 && vPruned.dests[0]!.destinationId === "r2" && vPruned.status === "alive");

  // Config rejections + no-op + the empty-selection-is-all-destinations rule + the null-is-all rule.
  ok("S1 a pin to an unknown destination is refused 400", (await doFetch(stub, "POST", "/canary/config", { destinationIds: ["nope"] })).status === 400);
  const vEmpty = (await (await doFetch(stub, "POST", "/canary/config", { destinationIds: [] })).json()) as CanaryView;
  ok("S1 an empty selection means all destinations", vEmpty.flyingToAll === true);
  await doFetch(stub, "POST", "/canary/config", { destinationIds: ["r2"] });
  const vNull = (await (await doFetch(stub, "POST", "/canary/config", { destinationIds: null })).json()) as CanaryView;
  ok("S1 a null selection means all destinations", vNull.flyingToAll === true);
  const vNoop = (await (await doFetch(stub, "POST", "/canary/config", {})).json()) as CanaryView;
  ok("S1 an empty config body changes nothing", vNoop.config.enabled === true && vNoop.flyingToAll === true);

  // Disable: the bird reads disabled, is never due, and run-now refuses; re-enable re-derives liveness.
  const vOff = (await (await doFetch(stub, "POST", "/canary/config", { enabled: false })).json()) as CanaryView;
  ok("S1 disabling reads disabled and clears the schedule", vOff.status === "disabled" && vOff.nextRunAt === null && vOff.dests.every((d) => d.status === "disabled"));
  ok("S1 a disabled canary is never due", ((await (await doFetch(stub, "POST", "/canary/due", { nowMs: 9_000_000 })).json()) as { due: boolean }).due === false);
  ok("S1 run-now on a disabled canary is refused 400", (await doFetch(stub, "POST", "/canary/run-now")).status === 400);
  const vOn = (await (await doFetch(stub, "POST", "/canary/config", { enabled: true })).json()) as CanaryView;
  ok("S1 re-enabling re-derives the aggregate liveness from the destinations", vOn.status === "alive" && vOn.nextRunAt !== null);
}

// ---- S2: no console destinations -> the canary flies to the env default (the null id) ---------------------
async function sectionNoDestinations(): Promise<void> {
  const { stub } = makeScheduler();
  const v = await getView(stub);
  ok("S2 with no destinations the canary flies to the single default (null) cell", v.dests.length === 1 && v.dests[0]!.destinationId === null && v.dests[0]!.isDefault === true && v.dests[0]!.label === "Default destination");
  ok("S2 the destination collection is reported empty", v.destinationCount === 0 && v.allDestinations.length === 0);
  const due = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 1 })).json()) as { due: boolean; run?: CanaryFlightPlan };
  ok("S2 the default-cell flight is due with one null-destination descriptor", due.due === true && due.run!.dests.length === 1 && due.run!.dests[0]!.destinationId === null);
  const t = ((await (await doFetch(stub, "POST", "/canary/complete", { run: due.run, results: [deadOf(null)] })).json()) as { transitions: Transition[] }).transitions;
  ok("S2 a dead default cell transitions with the default-destination label", t.length === 1 && t[0]!.destinationId === null && t[0]!.label === "the default destination" && t[0]!.transitioned === "dead");
}

// ---- S3: pinned ids that later dangle -> the default (or the null cell) is flown instead ------------------
async function sectionDanglingPins(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await seedDests(storage, [{ id: "a", label: "A" }, { id: "b", label: "B" }], "a");
  await doFetch(stub, "POST", "/canary/config", { destinationIds: ["a", "b"] });

  // Replace the whole collection: both pins now dangle, so the flight falls back to the (new) default.
  await seedDests(storage, [{ id: "c", label: "C" }], "c");
  const vDefault = await getView(stub);
  ok("S3 when every pin dangles the canary falls back to the default destination", vDefault.flyingToAll === false && vDefault.dests.length === 1 && vDefault.dests[0]!.destinationId === "c");

  // The pins that no longer resolve are NAMED in the view. Before this, the drop was
  // silent: the pin vanished from `dests` and the aggregate went on reading healthy for whatever remained,
  // so an operator who had deliberately pinned a bucket could lose that proof with nothing on screen.
  ok("S3 the view names both dangling pins", JSON.stringify([...vDefault.danglingPins].sort()) === JSON.stringify(["a", "b"]));

  // Remove all destinations: with the pins still dangling and no default, it flies the null cell.
  await storage.delete("destinations");
  const vNull = await getView(stub);
  ok("S3 with dangling pins and no destinations at all the canary flies the null cell", vNull.dests.length === 1 && vNull.dests[0]!.destinationId === null);

  // A PARTIAL dangle: one pin survives, one is gone. This is the case that had NO trace anywhere. The
  // all-dangling case at least records a fault-ledger entry; a partial dangle recorded nothing and
  // reached no screen, so the canary quietly stopped proving one destination the operator had chosen.
  {
    const { stub: s2, storage: st2 } = makeScheduler();
    await seedDests(st2, [{ id: "keep", label: "Keep" }, { id: "gone", label: "Gone" }], "keep");
    await doFetch(s2, "POST", "/canary/config", { destinationIds: ["keep", "gone"] });
    await seedDests(st2, [{ id: "keep", label: "Keep" }], "keep");
    const v = await getView(s2);
    ok("S3 a partial dangle still flies the surviving pin", v.dests.length === 1 && v.dests[0]!.destinationId === "keep");
    ok("S3 and names ONLY the pin that no longer resolves", JSON.stringify(v.danglingPins) === JSON.stringify(["gone"]));
  }

  // The healthy pinned case: nothing dangles, so the field is empty rather than absent. A reader must be
  // able to treat non-empty as "something is wrong" without also handling undefined.
  {
    const { stub: s3, storage: st3 } = makeScheduler();
    await seedDests(st3, [{ id: "x", label: "X" }, { id: "y", label: "Y" }], "x");
    await doFetch(s3, "POST", "/canary/config", { destinationIds: ["x", "y"] });
    const v = await getView(s3);
    ok("S3 a healthy pinned canary reports no dangling pins", Array.isArray(v.danglingPins) && v.danglingPins.length === 0);
  }

  // Flying to all: there are no pins, so there is nothing that can dangle, even after the collection changes.
  {
    const { stub: s4, storage: st4 } = makeScheduler();
    await seedDests(st4, [{ id: "p", label: "P" }], "p");
    await doFetch(s4, "POST", "/canary/config", { destinationIds: null });
    await seedDests(st4, [{ id: "q", label: "Q" }], "q");
    const v = await getView(s4);
    ok("S3 flying to all reports no dangling pins even after the collection is replaced", v.flyingToAll === true && v.danglingPins.length === 0);
  }
}

// ---- S4: migration of the pre-multi-destination single-record shapes ----------------------------------
async function sectionMigration(): Promise<void> {
  // A. an OLD record pinned to one destination, with a last run + history + a death stamp + a pass count.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, {
      config: { enabled: true, destinationId: "r2", intervalSeconds: 3600 },
      status: "alive", lastRunAt: "2026-06-13T00:00:00.000Z", nextRunAt: 1, runSeq: 4,
      deadSince: null, lastRunId: "OLDRUN", consecutivePasses: 3,
      history: [{ at: "2026-06-13T00:00:00.000Z", ok: true, status: "alive", durationMs: 5, destinationId: "r2", runSeq: 4, aspects: [], byteDelta: 0, deadReason: null }],
    });
    const v = await getView(stub);
    ok("S4a an old pinned record migrates to flying to exactly that destination, liveness + history preserved", v.flyingToAll === false && v.dests.length === 1 && v.dests[0]!.destinationId === "r2" && v.dests[0]!.status === "alive" && v.dests[0]!.lastCheck !== null && v.history.length === 1);
  }
  // B. an OLD DEFAULT record (no pin, no last run, no history) -> the all-destinations default, empty state.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, { config: { enabled: true, intervalSeconds: 3600 }, status: "pending", lastRunAt: null, nextRunAt: null, runSeq: 0 });
    const v = await getView(stub);
    ok("S4b an old default record migrates to flying to all destinations with no per-destination state", v.flyingToAll === true && v.dests.length === 1 && v.dests[0]!.destinationId === "r2" && v.dests[0]!.status === "pending");
  }
  // C. an OLD pinned record WITH a last run but an EMPTY history and no death stamp / pass count: the
  //    per-destination state seeds with a null latest-check and a null deadSince (the ?? fallbacks).
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, { config: { enabled: true, destinationId: "r2", intervalSeconds: 3600 }, status: "alive", lastRunAt: "2026-06-13T00:00:00.000Z", nextRunAt: 1, runSeq: 2, lastRunId: "OLD2", history: [] });
    const v = await getView(stub);
    ok("S4c an old record with a run but no history migrates with a null latest-check and null deadSince", v.dests.length === 1 && v.dests[0]!.destinationId === "r2" && v.dests[0]!.status === "alive" && v.dests[0]!.lastCheck === null && v.dests[0]!.deadSince === null);
  }
}

// ---- S5: the in-flight lease + reclaim edges (seeded states the normal flow cannot reach mid-stream) -----
async function sectionLeaseEdges(): Promise<void> {
  const base = (over: Partial<CanaryState>): CanaryState => ({ config: { enabled: true, destinationIds: null, intervalSeconds: 3600 }, status: "pending", lastRunAt: null, nextRunAt: null, inFlight: false, runSeq: 0, dests: [], history: [], ...over });

  // D1: inFlight but NO inFlightSince (a record from before the lease stamp) -> the lease guard cannot hold
  //     it (the inFlightSince!==undefined arm is false), so it is due and re-flown.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, base({ inFlight: true }));
    const due = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 1 })).json()) as { due: boolean };
    ok("S5 D1 an in-flight record with no lease stamp is treated as reclaimable and re-flown", due.due === true);
  }
  // D2: inFlight with an OLD inFlightSince beyond the lease -> the lease has expired, so it is due.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, base({ inFlight: true, inFlightSince: 0 }));
    const due = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: CANARY_LEASE_MS + 100 })).json()) as { due: boolean };
    ok("S5 D2 an in-flight record past the lease is reclaimed and re-flown", due.due === true);
  }
  // D3: run-now reclaims an in-flight record with no lease stamp.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, base({ inFlight: true }));
    ok("S5 D3 run-now succeeds on a stuck (lease-less) in-flight record", (await doFetch(stub, "POST", "/canary/run-now")).status === 200);
    ok("S5 D3 run-now reclaimed the lease-less in-flight flag", (await getView(stub)).inFlight === false);
  }
  // D4: run-now reclaims an in-flight record whose lease has expired.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, base({ inFlight: true, inFlightSince: Date.now() - CANARY_LEASE_MS - 100_000 }));
    await doFetch(stub, "POST", "/canary/run-now");
    ok("S5 D4 run-now reclaims an expired-lease in-flight record", (await getView(stub)).inFlight === false);
  }
  // D5: run-now does NOT reclaim a FRESH in-flight record (a flight genuinely in progress) -> the flag stays.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await storage.put(CANARY_KEY, base({ inFlight: true, inFlightSince: Date.now() }));
    await doFetch(stub, "POST", "/canary/run-now");
    ok("S5 D5 run-now leaves a fresh in-flight flight alone (no premature reclaim)", (await getView(stub)).inFlight === true);
  }
}

// ---- S6: canaryComplete input validation, skip-and-default folding, and the unknown-id fallbacks ----------
async function sectionComplete(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");

  // Each of the three required-shape arms refused with a 400.
  ok("S6 completion with no run is refused 400", (await doFetch(stub, "POST", "/canary/complete", { results: [] })).status === 400);
  ok("S6 completion with a run lacking a dests array is refused 400", (await doFetch(stub, "POST", "/canary/complete", { run: { runSeq: 1 }, results: [] })).status === 400);
  ok("S6 completion with no results array is refused 400", (await doFetch(stub, "POST", "/canary/complete", { run: { runSeq: 1, dests: [] } })).status === 400);

  // A valid flight whose results carry a null entry, a non-string-status entry, and a sparse alive entry
  // (no durationMs / aspects / byteDelta): the bad entries are skipped, the sparse one folds to safe defaults.
  const due = (await (await doFetch(stub, "POST", "/canary/due", { nowMs: 1_000_000 })).json()) as { due: boolean; run?: CanaryFlightPlan };
  const sparse = { status: "alive", destinationId: "r2" } as unknown as CanaryCheckResult;
  await doFetch(stub, "POST", "/canary/complete", { run: due.run, results: [null, { status: 123, destinationId: "r2" }, sparse] });
  const v = await getView(stub);
  const lc = v.dests.find((d) => d.destinationId === "r2")!.lastCheck!;
  ok("S6 a sparse alive result folds to safe defaults (0 duration, no aspects, null byteDelta) and is recorded alive", lc.durationMs === 0 && lc.aspects.length === 0 && lc.byteDelta === null && lc.status === "alive");

  // A completion whose results name a destination NOT in the posted run AND not in the collection: the runId
  // falls back (no run entry), the transition label falls back to the raw id, and the off-plan state is pruned.
  const ghostRun: CanaryFlightPlan = { runSeq: 9, dests: [{ runId: "RUNR2", runSeq: 9, destinationId: "r2", cleanupRunId: null }] };
  const t = ((await (await doFetch(stub, "POST", "/canary/complete", { run: ghostRun, results: [deadOf("ghost")] })).json()) as { transitions: Transition[] }).transitions;
  ok("S6 a result for a destination off the plan transitions with its raw id as the label", t.length === 1 && t[0]!.destinationId === "ghost" && t[0]!.label === "ghost" && t[0]!.transitioned === "dead");
  ok("S6 the off-plan destination is pruned from the persisted per-destination state", (await getView(stub)).dests.every((d) => d.destinationId !== "ghost"));
}

// ---- S7: the owner gate, the corrupt-record fault, and the label fallback + non-finite cadence edges ------
async function sectionGuards(): Promise<void> {
  // The DO re-resolves the caller's role from its own tables: a non-owner config change is refused 403 even
  // router-bypassed (defence in depth).
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    ok("S7 a non-owner canary config change is refused 403 at the DO", (await doFetch(stub, "POST", "/canary/config", { enabled: false }, VIEWER_CALLER)).status === 403);
    ok("S7 the refused change did not disable the canary", (await getView(stub)).config.enabled === true);
  }
  // A corrupt stored record with no config object surfaces as a clean 500, not an unhandled fault.
  {
    const { stub, storage } = makeScheduler();
    await storage.put(CANARY_KEY, { status: "pending", lastRunAt: null, nextRunAt: null, inFlight: false, runSeq: 0, dests: [], history: [] });
    ok("S7 a stored canary record with no config yields a clean 500", (await doFetch(stub, "GET", "/canary")).status === 500);
  }
  // A label-less destination falls back to its id as the rendered label.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "x1", label: "X One" }, { id: "x2" }], "x1");
    const v = await getView(stub);
    ok("S7 a destination with no label renders its id as the label", v.dests.find((d) => d.destinationId === "x1")!.label === "X One" && v.dests.find((d) => d.destinationId === "x2")!.label === "x2");
  }
  // A non-finite cadence (NaN cannot ride JSON, so the real method is called directly) is ignored: the
  // Number.isFinite guard leaves the existing cadence untouched.
  {
    const { stub, storage } = makeScheduler();
    await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");
    await doFetch(stub, "POST", "/canary/config", { intervalSeconds: 1800 });
    const after = (await (stub as unknown as { setCanaryConfig(req: { intervalSeconds?: unknown }, caller: Caller): Promise<CanaryView> }).setCanaryConfig({ intervalSeconds: Number.NaN }, OWNER_CALLER));
    ok("S7 a non-finite cadence is ignored and the existing cadence is kept", after.config.intervalSeconds === 1800);
  }
}

// ---- S8: ailingCause folds through canaryComplete into the persisted CanaryCheck --
async function sectionAilingCauseFold(): Promise<void> {
  const { stub, storage } = makeScheduler();
  await seedDests(storage, [{ id: "r2", label: "R2 Primary" }], "r2");

  const posture: CanaryCheckResult = { status: "ailing", durationMs: 7, destinationId: "r2", aspects: [], byteDelta: null, deadReason: null, ailingCause: "other" };
  await flyOnce(stub, [posture]);
  const v1 = await getView(stub);
  ok(
    "S8 an ailing result WITH a cause folds it into the persisted lastCheck verbatim",
    v1.dests.find((d) => d.destinationId === "r2")!.lastCheck!.ailingCause === "other",
  );

  // A plain ailing result with NO cause (the pre-existing ailingOf fixture: an "old record" / non-posture-
  // attributable shape) folds with ailingCause absent -- never a fabricated cause.
  await flyOnce(stub, [ailingOf("r2")]);
  const v2 = await getView(stub);
  ok("S8 an ailing result with NO cause folds with ailingCause absent (never fabricated)", v2.dests.find((d) => d.destinationId === "r2")!.lastCheck!.ailingCause === undefined);

  // A clean pass never carries a cause either.
  await flyOnce(stub, [aliveOf("r2")]);
  const v3 = await getView(stub);
  ok("S8 an alive result folds with no ailingCause", v3.dests.find((d) => d.destinationId === "r2")!.lastCheck!.ailingCause === undefined);
}

async function main(): Promise<void> {
  await sectionLifecycle();
  await sectionNoDestinations();
  await sectionDanglingPins();
  await sectionMigration();
  await sectionLeaseEdges();
  await sectionComplete();
  await sectionGuards();
  await sectionAilingCauseFold();
  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
