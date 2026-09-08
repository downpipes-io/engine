// validate-cov-sched-scheduler-do-observability: focused branch-coverage vectors for the SchedulerDO
// ObservabilityMixin (src/sched/scheduler-do-observability.ts) -- the read-mostly observability cluster
// (scheduled restore tests + restorability-proven record, the on-demand fleet drill, and the security
// centre / posture computation + risk-accept writes). Every assertion drives the REAL SchedulerDO over an
// in-memory paging storage that honours startAfter + limit exactly like the platform, either through the
// production fetch() router (so the HTTP status mapping is exercised) or by calling the mixin method on the
// real DO instance with a hand-built caller (the defence-in-depth re-checks the router gates first). No
// network, no deploy, no cost; the only side effects are reads/writes of the in-memory store.
//
// Run: node test/validate-cov-sched-scheduler-do-observability.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState, FleetDrillProgress } from "../src/sched/scheduler-do.ts";
import type { SealFault } from "../src/seal/seal-faults.ts";
import type { FleetDrillCampaign } from "../src/sched/scheduler-do-base.ts";
import { encodeCaller, CALLER_HEADER, type Caller } from "../src/admin/identity.ts";
import { FLEET_DRILL_ACTIVE_KEY, FLEET_DRILL_LAST_KEY, FLEET_DRILL_INFLIGHT_TIMEOUT_MS, FLEET_DRILL_FAILED_SAMPLE } from "../src/sched/scheduler-do-limits.ts";
import { DESTINATIONS_KEY, ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { EXPIRY_PREFIX } from "../src/admin/expiry.ts";
import { POSTURE_ACCEPT_PREFIX, POSTURE_SNAPSHOT_KEY, type PostureReport, type PostureCheck, type RiskAccept } from "../src/admin/posture.ts";

// fleetDrillProgress + persistOrFinishFleetDrill are real methods the ObservabilityMixin adds to the
// SchedulerDO at runtime, but they are internal helpers the SchedulerDOSurface interface deliberately
// omits, so they are not on the SchedulerDO *type* (unlike its sibling fleet-drill methods, which the
// surface declares). Declare their exact runtime signatures here and reach them through a single precise
// `dobj as unknown as ObservabilityMethods` cast per block, so the call sites stay typed (not `any`).
interface ObservabilityMethods {
  fleetDrillProgress(c: FleetDrillCampaign): FleetDrillProgress;
  persistOrFinishFleetDrill(campaign: FleetDrillCampaign, now: number): Promise<void>;
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- In-memory DO storage that HONOURS startAfter + limit (paginates like the platform), supports the
// batched array-get signature, and can inject a one-shot get() fault so the best-effort catch path in
// advanceFleetDrill is reachable through a real thrown error rather than a stub of the logic under test.
const PLATFORM_LIST_PAGE = 1000;
class PagingStorage {
  private map = new Map<string, unknown>();
  private throwNextGet = false;
  armThrowNextGet(): void {
    this.throwNextGet = true;
  }
  async get<T>(key: string): Promise<T | undefined>;
  async get<T>(keys: string[]): Promise<Map<string, T>>;
  async get<T>(keyOrKeys: string | string[]): Promise<T | undefined | Map<string, T>> {
    if (this.throwNextGet) {
      this.throwNextGet = false;
      throw new Error("injected storage.get fault");
    }
    if (Array.isArray(keyOrKeys)) {
      const out = new Map<string, T>();
      for (const k of keyOrKeys) {
        const v = this.map.get(k);
        if (v !== undefined) out.set(k, JSON.parse(JSON.stringify(v)) as T);
      }
      return out;
    }
    const v = this.map.get(keyOrKeys);
    return v === undefined ? undefined : (JSON.parse(JSON.stringify(v)) as T);
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string; start?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
    if (opts?.start !== undefined) keys = keys.filter((k) => k >= opts.start!);
    const cap = Math.min(opts?.limit ?? PLATFORM_LIST_PAGE, PLATFORM_LIST_PAGE);
    const page = keys.slice(0, cap);
    const out = new Map<string, T>();
    for (const k of page) out.set(k, JSON.parse(JSON.stringify(this.map.get(k))) as T);
    return out;
  }
  async setAlarm(_t: number): Promise<void> {}
  async deleteAlarm(): Promise<void> {}
  async getAlarm(): Promise<number | null> {
    return null;
  }
}

function makeScheduler(): { storage: PagingStorage; dobj: SchedulerDO } {
  const storage = new PagingStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, dobj: new SchedulerDO(state) };
}

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, caller?: Caller | null): Promise<Response> {
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(caller != null ? { [CALLER_HEADER]: encodeCaller(caller) } : {}),
  };
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(`https://scheduler.internal${path}`, init));
}

// Caller fixtures (typed as consts so the structural excess-property check never fires at the call sites).
const ownerAccess: Caller = { method: "access", email: "owner@acme.au", subject: "sub-owner", role: "owner", groups: [] };
const ownerAccessIp = { method: "access" as const, email: "owner@acme.au", subject: "sub-owner", role: "owner" as const, groups: [] as string[], sourceIp: "203.0.113.7" };
const ownerToken = { method: "token" as const, email: null, subject: null, role: "owner" as const, groups: [] as string[] };
const viewer: Caller = { method: "access", email: "viewer@acme.au", subject: "sub-viewer", role: "viewer", groups: [] };
const operator: Caller = { method: "access", email: "operator@acme.au", subject: "sub-op", role: "operator", groups: [] };

function dpState(id: string, extra: Partial<DownpipeState> = {}, config: Record<string, unknown> = {}): DownpipeState {
  return {
    config: { id, name: `pipe ${id}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_x", include: [], exclude: [] }, ...config },
    inFlight: false,
    nextRunAt: Date.now() + 3_600_000,
    ...extra,
  } as unknown as DownpipeState;
}

async function threw(fn: () => Promise<unknown>): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch {
    return true;
  }
}

const AT = 1_700_000_000_000; // a fixed timestamp so stored recency is deterministic

async function main(): Promise<void> {
  // ========================================================================================
  // restoreTestsDue: cadence off / never-tested / stale / recent
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    const now = Date.now();
    await storage.put("dp:off", dpState("off", {}, { restoreTestCadenceSeconds: 0 })); // cadence off
    await storage.put("dp:absent", dpState("absent")); // cadence field absent (?? 0) -> off
    await storage.put("dp:never", dpState("never", {}, { restoreTestCadenceSeconds: 100 })); // never tested -> due
    await storage.put("dp:stale", dpState("stale", { lastRestoreTestAt: now - 200_000 }, { restoreTestCadenceSeconds: 100 })); // older than cadence -> due
    await storage.put("dp:fresh", dpState("fresh", { lastRestoreTestAt: now }, { restoreTestCadenceSeconds: 100_000 })); // recent -> not due
    const due = (await dobj.restoreTestsDue()).due.map((d) => d.config.id).sort();
    ok("restoreTestsDue returns exactly the never-tested + stale downpipes", JSON.stringify(due) === JSON.stringify(["never", "stale"]));
  }

  // ========================================================================================
  // completeRestoreTest: id guards, at default, ok flag, deepVerify cursor, RTO sample
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    await storage.put("dp:c1", dpState("c1"));

    // id guards: non-string id, empty id, and a valid id for a missing downpipe are all benign {ok:true}.
    ok("completeRestoreTest: non-string id is a no-op success", (await dobj.completeRestoreTest({})).ok === true);
    ok("completeRestoreTest: empty id is a no-op success", (await dobj.completeRestoreTest({ id: "" })).ok === true);
    ok("completeRestoreTest: unknown downpipe is a no-op success", (await dobj.completeRestoreTest({ id: "ghost" })).ok === true);

    // A failed drill with an explicit at: records recency (ok=false), no deepVerify, no RTO sample.
    await dobj.completeRestoreTest({ id: "c1", ok: false, at: AT });
    let s = await storage.get<DownpipeState>("dp:c1");
    ok("completeRestoreTest: a failed drill stamps lastRestoreTestAt = supplied at", s?.lastRestoreTestAt === AT);
    ok("completeRestoreTest: a failed drill records lastRestoreTestOk = false", s?.lastRestoreTestOk === false);
    ok("completeRestoreTest: a failed drill records no RTO sample", s?.recoverySamples === undefined);

    // A successful drill with no at (DO-clock default) + a valid deepVerify wrapped pass + an RTO sample.
    await dobj.completeRestoreTest({ id: "c1", ok: true, durationMs: 1200, bytesVerified: 4096, recordsVerified: 8, deepVerify: { runId: "run-A", cursor: 5, records: 50, wrapped: true } });
    s = await storage.get<DownpipeState>("dp:c1");
    ok("completeRestoreTest: success with no at uses the DO clock (a finite timestamp)", typeof s?.lastRestoreTestAt === "number" && s!.lastRestoreTestAt !== AT);
    ok("completeRestoreTest: success records lastRestoreTestOk = true", s?.lastRestoreTestOk === true);
    ok("completeRestoreTest: a wrapped deepVerify pass persists the advanced cursor + a lastFullPassAt", s?.deepVerify?.runId === "run-A" && s?.deepVerify?.cursor === 5 && typeof s?.deepVerify?.lastFullPassAt === "number");
    ok("completeRestoreTest: a measured success appends one RTO sample", Array.isArray(s?.recoverySamples) && s!.recoverySamples!.length === 1);

    // A second deepVerify for the SAME runId but NOT wrapped carries the prior lastFullPassAt forward.
    const priorFullPass = s!.deepVerify!.lastFullPassAt;
    await dobj.completeRestoreTest({ id: "c1", ok: true, deepVerify: { runId: "run-A", cursor: 12, records: 50, wrapped: false } });
    s = await storage.get<DownpipeState>("dp:c1");
    ok("completeRestoreTest: a non-wrapped deepVerify advance carries the prior lastFullPassAt forward", s?.deepVerify?.cursor === 12 && s?.deepVerify?.lastFullPassAt === priorFullPass);

    // A first non-wrapped deepVerify advance (no prior full pass for this runId) stamps no lastFullPassAt.
    await storage.put("dp:c3", dpState("c3"));
    await dobj.completeRestoreTest({ id: "c3", ok: true, deepVerify: { runId: "fresh", cursor: 3, records: 9, wrapped: false } });
    const s3 = await storage.get<DownpipeState>("dp:c3");
    ok("completeRestoreTest: a first non-wrapped deepVerify advance carries no lastFullPassAt", s3?.deepVerify?.cursor === 3 && s3?.deepVerify?.lastFullPassAt === undefined);

    // A malformed deepVerify (empty runId) is ignored: the prior deepVerify is untouched.
    await dobj.completeRestoreTest({ id: "c1", ok: true, deepVerify: { runId: "", cursor: 99, records: 1, wrapped: true } });
    s = await storage.get<DownpipeState>("dp:c1");
    ok("completeRestoreTest: a malformed deepVerify (empty runId) is ignored", s?.deepVerify?.cursor === 12);

    // A non-finite at falls back to the DO clock (the at default branch).
    await dobj.completeRestoreTest({ id: "c1", ok: false, at: Number.NaN });
    s = await storage.get<DownpipeState>("dp:c1");
    ok("completeRestoreTest: a non-finite at falls back to the DO clock", typeof s?.lastRestoreTestAt === "number" && Number.isFinite(s!.lastRestoreTestAt));

    // A successful drill that measured duration but ZERO bytes records NO RTO sample (bytesVerified must be >0);
    // and recordsVerified absent defaults the sample's records to 0 when a sample IS taken.
    await storage.put("dp:c2", dpState("c2"));
    await dobj.completeRestoreTest({ id: "c2", ok: true, durationMs: 500, bytesVerified: 0 });
    let s2 = await storage.get<DownpipeState>("dp:c2");
    ok("completeRestoreTest: a success with zero bytes verified records no RTO sample", s2?.recoverySamples === undefined);
    await dobj.completeRestoreTest({ id: "c2", ok: true, durationMs: 500, bytesVerified: 2048 });
    s2 = await storage.get<DownpipeState>("dp:c2");
    ok("completeRestoreTest: a success with bytes but no recordsVerified records a sample with records 0", s2?.recoverySamples?.[0]?.recordsVerified === 0);
  }

  // ========================================================================================
  // recordRestoreProven: capability re-check, field guards, success (email + null email), integrity stamp
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    await storage.put("dp:p1", dpState("p1"));

    // A null caller (no restore.verify) is refused at the DO defence-in-depth re-check -> AuthError -> 403.
    const noCaller = await fetchDO(dobj, "POST", "/restore-proven", { downpipeId: "p1", method: "blind-test", runId: "r1" });
    ok("recordRestoreProven: a caller without restore.verify is refused (403)", noCaller.status === 403);

    // A viewer HOLDS restore.verify. An empty downpipeId is a benign {ok:false} (200, no record).
    const emptyId = await fetchDO(dobj, "POST", "/restore-proven", { downpipeId: "", method: "blind-test", runId: "r1" }, viewer);
    ok("recordRestoreProven: an empty downpipeId returns ok:false (200)", emptyId.status === 200 && ((await emptyId.json()) as { ok: boolean }).ok === false);

    // An invalid method is a 400 validation error.
    const badMethod = await fetchDO(dobj, "POST", "/restore-proven", { downpipeId: "p1", method: "nope", runId: "r1" }, viewer);
    ok("recordRestoreProven: an invalid method is rejected (400)", badMethod.status === 400);

    // A missing runId is a 400 validation error.
    const noRun = await fetchDO(dobj, "POST", "/restore-proven", { downpipeId: "p1", method: "keyless-attest" }, viewer);
    ok("recordRestoreProven: a missing runId is rejected (400)", noRun.status === 400);

    // A known method but a missing downpipe is a benign {ok:false}.
    const goneRes = await dobj.recordRestoreProven({ downpipeId: "ghost", method: "blind-test", runId: "r1", at: AT }, viewer);
    ok("recordRestoreProven: an unknown downpipe returns ok:false", goneRes.ok === false);

    // Success with an attributable caller (email) records who+when+method+runId AND refreshes integrity recency.
    const okRes = await dobj.recordRestoreProven({ downpipeId: "p1", method: "blind-test", runId: "r-proof", at: AT }, viewer);
    const sp = await storage.get<DownpipeState>("dp:p1");
    ok("recordRestoreProven: a passed blind test returns ok:true", okRes.ok === true);
    ok("recordRestoreProven: the restoreProven record carries the prover email + method + runId + at", sp?.restoreProven?.by === "viewer@acme.au" && sp?.restoreProven?.method === "blind-test" && sp?.restoreProven?.runId === "r-proof" && sp?.restoreProven?.at === AT);
    ok("recordRestoreProven: a pass also stamps integrityVerified how:attest", sp?.integrityVerified?.how === "attest" && sp?.integrityVerified?.at === AT);

    // Success with a bare-token caller (no email) records by:null and defaults at to the DO clock.
    await dobj.recordRestoreProven({ downpipeId: "p1", method: "keyless-attest", runId: "r-token" }, ownerToken);
    const sp2 = await storage.get<DownpipeState>("dp:p1");
    ok("recordRestoreProven: a bare-token prover records by:null and a DO-clock at", sp2?.restoreProven?.by === null && sp2?.restoreProven?.method === "keyless-attest" && typeof sp2?.restoreProven?.at === "number");
  }

  // ========================================================================================
  // fleetDrillProgress: the redaction-safe projection, with and without finishedAt
  // ========================================================================================
  {
    const { dobj } = makeScheduler();
    const obs = dobj as unknown as ObservabilityMethods;
    const base: FleetDrillCampaign = { campaignId: "C1", startedAt: 1, startedBy: "owner@acme.au", total: 3, pending: ["a"], inFlight: { b: 2 }, passed: 1, failed: 0, failedSample: [], done: false };
    const active = obs.fleetDrillProgress(base);
    ok("fleetDrillProgress: an active campaign has completed=passed+failed, remaining=pending+inFlight, no finishedAt", active.completed === 1 && active.remaining === 2 && active.finishedAt === undefined);
    const finished = obs.fleetDrillProgress({ ...base, pending: [], inFlight: {}, passed: 3, done: true, finishedAt: 99 });
    ok("fleetDrillProgress: a finished campaign carries finishedAt", finished.finishedAt === 99 && finished.done === true && finished.remaining === 0);
  }

  // ========================================================================================
  // startFleetDrill: capability gate, no-clobber, done-existing proceeds, subset filter, empty reason
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    await storage.put("dp:f1", dpState("f1"));
    await storage.put("dp:f2", dpState("f2"));

    // No drill.run (viewer) -> AuthError. (Also proven via the route for the 403 status below.)
    ok("startFleetDrill: a caller without drill.run throws", await threw(() => dobj.startFleetDrill({}, viewer)));

    // An operator HOLDS drill.run: a campaign over the whole fleet starts.
    const started = await dobj.startFleetDrill({}, operator);
    ok("startFleetDrill: an operator starts a campaign over the whole fleet", started.ok === true && started.total === 2 && typeof started.campaignId === "string");
    const stored = await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
    ok("startFleetDrill: the campaign records the starter email", stored?.startedBy === "operator@acme.au");

    // A second start while one is active REFUSES to clobber it.
    const second = await dobj.startFleetDrill({}, operator);
    ok("startFleetDrill: a second start while one is active refuses (alreadyActive, same id)", second.ok === false && second.alreadyActive === true && second.campaignId === started.campaignId);

    // Mark the campaign done in storage: a new start now PROCEEDS (the existing-but-done branch).
    await storage.put(FLEET_DRILL_ACTIVE_KEY, { ...stored!, done: true });
    const afterDone = await dobj.startFleetDrill({ downpipeIds: ["f1", 123, "ghost"] }, ownerToken);
    ok("startFleetDrill: a done existing campaign does not block a new one; the subset drops non-strings + unknown ids", afterDone.ok === true && afterDone.total === 1);
    const stored2 = await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
    ok("startFleetDrill: a bare-token starter records startedBy:null", stored2?.startedBy === null);

    // A subset that matches nothing is a clean refusal with a reason.
    await storage.put(FLEET_DRILL_ACTIVE_KEY, { ...stored2!, done: true });
    const none = await dobj.startFleetDrill({ downpipeIds: ["nope"] }, operator);
    ok("startFleetDrill: a subset matching no downpipes returns a reason", none.ok === false && typeof none.reason === "string");
  }

  // startFleetDrill: a fleet larger than the cap throws (FLEET_DRILL_MAX = 5000). Seeded over a paging store.
  {
    const { storage, dobj } = makeScheduler();
    for (let i = 0; i < 5001; i++) await storage.put(`dp:big_${String(i).padStart(5, "0")}`, dpState(`big_${i}`));
    ok("startFleetDrill: a fleet exceeding the cap throws (narrow with a subset)", await threw(() => dobj.startFleetDrill({}, operator)));
  }

  // ========================================================================================
  // fleetDrillNextBatch: no campaign, cap normalisation, deleted-dp-counted, failed-sample cap, drain
  // ========================================================================================
  {
    const { dobj } = makeScheduler();
    const empty = await dobj.fleetDrillNextBatch(2);
    ok("fleetDrillNextBatch: with no active campaign returns done:true and a null campaignId", empty.done === true && empty.campaignId === null && empty.due.length === 0);
  }
  {
    const { storage, dobj } = makeScheduler();
    for (const id of ["n1", "n2", "n3"]) await storage.put(`dp:${id}`, dpState(id));
    await dobj.startFleetDrill({}, operator);
    // cap 2.9 -> floor 2 (finite & >=1); returns 2, pending still has 1 (the due<cap exit).
    const b1 = await dobj.fleetDrillNextBatch(2.9);
    ok("fleetDrillNextBatch: a fractional cap floors to 2 and dispatches a full batch", b1.due.length === 2 && b1.done === false);
    // cap 0 -> normalised to 1; pending empties (the pending>0 exit) so the last (single) member dispatches.
    const b2 = await dobj.fleetDrillNextBatch(0);
    ok("fleetDrillNextBatch: a sub-1 cap normalises to 1 and drains the last member", b2.due.length === 1);
  }
  {
    // A deleted downpipe is counted as failed so the campaign converges; the failed sample is bounded.
    const { storage, dobj } = makeScheduler();
    await storage.put("dp:d1", dpState("d1"));
    await dobj.startFleetDrill({}, operator);
    await storage.delete("dp:d1"); // delete between start and dispatch
    const batch = await dobj.fleetDrillNextBatch(5);
    ok("fleetDrillNextBatch: a deleted downpipe dispatches nothing but is counted (campaign finishes)", batch.due.length === 0 && batch.done === true);
    const last = await storage.get<FleetDrillCampaign>(FLEET_DRILL_LAST_KEY);
    ok("fleetDrillNextBatch: the deleted downpipe is recorded in the failed sample", last?.failed === 1 && last?.failedSample.includes("d1") === true);
  }
  {
    // failedSample cap: a campaign whose sample is already full does not push another deleted id.
    const { storage, dobj } = makeScheduler();
    const fullSample = Array.from({ length: FLEET_DRILL_FAILED_SAMPLE }, (_v, i) => `pre_${i}`);
    const camp: FleetDrillCampaign = { campaignId: "Cfull", startedAt: 1, startedBy: null, total: 26, pending: ["missing"], inFlight: {}, passed: 0, failed: FLEET_DRILL_FAILED_SAMPLE, failedSample: fullSample, done: false };
    await storage.put(FLEET_DRILL_ACTIVE_KEY, camp);
    await dobj.fleetDrillNextBatch(5); // "missing" dp absent -> failed++ but sample is full
    const after = await storage.get<FleetDrillCampaign>(FLEET_DRILL_LAST_KEY);
    ok("fleetDrillNextBatch: a full failed sample is not grown past the cap", after?.failedSample.length === FLEET_DRILL_FAILED_SAMPLE && after?.failed === FLEET_DRILL_FAILED_SAMPLE + 1);
  }
  {
    // self-heal: a stale in-flight member is re-queued after the timeout.
    const { storage, dobj } = makeScheduler();
    await storage.put("dp:h1", dpState("h1"));
    await dobj.startFleetDrill({}, operator);
    await dobj.fleetDrillNextBatch(1); // dispatch h1 (now in flight, fresh)
    const fresh = await dobj.fleetDrillNextBatch(1); // not stale yet -> nothing, not done
    ok("fleetDrillNextBatch: a fresh in-flight member is not re-dispatched and the campaign is not done", fresh.due.length === 0 && fresh.done === false);
    const active = (await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY))!;
    for (const id of Object.keys(active.inFlight)) active.inFlight[id] = Date.now() - FLEET_DRILL_INFLIGHT_TIMEOUT_MS - 1;
    await storage.put(FLEET_DRILL_ACTIVE_KEY, active);
    const requeued = await dobj.fleetDrillNextBatch(1);
    ok("fleetDrillNextBatch: a stale in-flight member is re-queued after the timeout (self-heal)", requeued.due.length === 1 && requeued.due[0]!.config.id === "h1");
  }

  // ========================================================================================
  // advanceFleetDrill: no campaign, done campaign, not-in-flight, pass, fail (+ sample cap), best-effort catch
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    // No active campaign -> no-op (does not throw).
    ok("advanceFleetDrill: no active campaign is a no-op", !(await threw(() => dobj.advanceFleetDrill("x", true))));

    // A done campaign -> no-op.
    await storage.put(FLEET_DRILL_ACTIVE_KEY, { campaignId: "Cd", startedAt: 1, startedBy: null, total: 1, pending: [], inFlight: {}, passed: 1, failed: 0, failedSample: [], done: true });
    await dobj.advanceFleetDrill("x", true);
    ok("advanceFleetDrill: a done campaign is not mutated", (await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY))?.passed === 1);

    // An id not in flight -> no-op. (A leftover pending member keeps the campaign active across the pass below.)
    await storage.put(FLEET_DRILL_ACTIVE_KEY, { campaignId: "Ce", startedAt: 1, startedBy: null, total: 3, pending: ["leftover"], inFlight: { a: Date.now() }, passed: 0, failed: 0, failedSample: [], done: false });
    await dobj.advanceFleetDrill("not-dispatched", true);
    let c = await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
    ok("advanceFleetDrill: a completion for a non-in-flight id is ignored", c?.passed === 0 && c?.failed === 0 && Object.keys(c!.inFlight).length === 1);

    // A pass advances passed and clears the in-flight entry (the leftover pending keeps it active).
    await dobj.advanceFleetDrill("a", true);
    c = await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
    ok("advanceFleetDrill: a pass advances passed and clears in-flight", c?.passed === 1 && Object.keys(c!.inFlight).length === 0);

    // A fail UNDER the sample cap records the id in the failed sample (the push branch).
    await storage.put(FLEET_DRILL_ACTIVE_KEY, { campaignId: "Cu", startedAt: 1, startedBy: null, total: 2, pending: ["keep"], inFlight: { zz: Date.now() }, passed: 0, failed: 0, failedSample: [], done: false });
    await dobj.advanceFleetDrill("zz", false);
    const cu = await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY);
    ok("advanceFleetDrill: a fail under the sample cap records the id in the failed sample", cu?.failed === 1 && cu?.failedSample.includes("zz") === true);

    // A fail with a full sample advances failed but does not grow the sample.
    const fullSample = Array.from({ length: FLEET_DRILL_FAILED_SAMPLE }, (_v, i) => `pre_${i}`);
    await storage.put(FLEET_DRILL_ACTIVE_KEY, { campaignId: "Cf", startedAt: 1, startedBy: null, total: 1, pending: [], inFlight: { z: Date.now() }, passed: 0, failed: FLEET_DRILL_FAILED_SAMPLE, failedSample: fullSample, done: false });
    await dobj.advanceFleetDrill("z", false);
    const last = await storage.get<FleetDrillCampaign>(FLEET_DRILL_LAST_KEY);
    ok("advanceFleetDrill: a fail advances failed; a full sample stays capped; the drained campaign finishes", last?.failed === FLEET_DRILL_FAILED_SAMPLE + 1 && last?.failedSample.length === FLEET_DRILL_FAILED_SAMPLE && last?.done === true);

    // Best-effort: a storage fault inside advanceFleetDrill is swallowed (never fails the completion).
    await storage.put(FLEET_DRILL_ACTIVE_KEY, { campaignId: "Cg", startedAt: 1, startedBy: null, total: 1, pending: [], inFlight: { y: Date.now() }, passed: 0, failed: 0, failedSample: [], done: false });
    storage.armThrowNextGet();
    ok("advanceFleetDrill: a storage fault is swallowed (best-effort bookkeeping)", !(await threw(() => dobj.advanceFleetDrill("y", true))));
  }

  // ========================================================================================
  // persistOrFinishFleetDrill: finishes when empty, persists when not (driven directly)
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    const obs = dobj as unknown as ObservabilityMethods;
    const finishCamp: FleetDrillCampaign = { campaignId: "Cpf", startedAt: 1, startedBy: null, total: 1, pending: [], inFlight: {}, passed: 1, failed: 0, failedSample: [], done: false };
    await obs.persistOrFinishFleetDrill(finishCamp, 555);
    ok("persistOrFinishFleetDrill: an empty campaign is finished (moved to last, active deleted)", finishCamp.done === true && finishCamp.finishedAt === 555 && (await storage.get(FLEET_DRILL_ACTIVE_KEY)) === undefined && (await storage.get<FleetDrillCampaign>(FLEET_DRILL_LAST_KEY))?.campaignId === "Cpf");
    const liveCamp: FleetDrillCampaign = { campaignId: "Cpf2", startedAt: 1, startedBy: null, total: 2, pending: ["q"], inFlight: {}, passed: 0, failed: 0, failedSample: [], done: false };
    await obs.persistOrFinishFleetDrill(liveCamp, 777);
    ok("persistOrFinishFleetDrill: a non-empty campaign stays active (not finished)", liveCamp.done === false && (await storage.get<FleetDrillCampaign>(FLEET_DRILL_ACTIVE_KEY))?.campaignId === "Cpf2");
  }

  // ========================================================================================
  // fleetDrillStatus: active, then last-finished, then null
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    const none = await dobj.fleetDrillStatus();
    ok("fleetDrillStatus: with no fleet drill ever run returns null", none.active === false && none.campaign === null);

    await storage.put(FLEET_DRILL_LAST_KEY, { campaignId: "Cl", startedAt: 1, startedBy: null, total: 1, pending: [], inFlight: {}, passed: 1, failed: 0, failedSample: [], done: true, finishedAt: 9 });
    const last = await dobj.fleetDrillStatus();
    ok("fleetDrillStatus: with no active campaign returns the last finished one (active:false)", last.active === false && last.campaign?.campaignId === "Cl");

    await storage.put(FLEET_DRILL_ACTIVE_KEY, { campaignId: "Ca", startedAt: 1, startedBy: null, total: 2, pending: ["w"], inFlight: {}, passed: 0, failed: 0, failedSample: [], done: false });
    const active = await dobj.fleetDrillStatus();
    ok("fleetDrillStatus: an active campaign takes precedence (active:true)", active.active === true && active.campaign?.campaignId === "Ca");
  }

  // ========================================================================================
  // requirePostureRiskAccept + acceptPostureRisk + unacceptPostureRisk (direct, full branch fan-out)
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();

    // requirePostureRiskAccept: a non-owner (viewer) is refused; an owner (capabilities-undefined -> can()) passes.
    ok("requirePostureRiskAccept: a viewer is refused", await threw(() => dobj.acceptPostureRisk({ checkId: "beacon-off", reason: "x" }, viewer)));
    ok("requirePostureRiskAccept: a null caller is refused", await threw(() => dobj.acceptPostureRisk({ checkId: "beacon-off", reason: "x" }, null)));

    // checkId guards: not a string, fails the id pattern, and pattern-valid-but-unknown are each rejected.
    ok("acceptPostureRisk: a non-string checkId is rejected", await threw(() => dobj.acceptPostureRisk({ checkId: 123 as unknown as string, reason: "r" }, ownerAccess)));
    ok("acceptPostureRisk: a checkId failing the id pattern is rejected", await threw(() => dobj.acceptPostureRisk({ checkId: "Bad Id!", reason: "r" }, ownerAccess)));
    ok("acceptPostureRisk: a pattern-valid but unknown checkId is rejected", await threw(() => dobj.acceptPostureRisk({ checkId: "not-a-real-check", reason: "r" }, ownerAccess)));

    // reason guards: whitespace-only (empty after trim) and a control-character reason are each rejected.
    ok("acceptPostureRisk: a whitespace-only reason is rejected", await threw(() => dobj.acceptPostureRisk({ checkId: "beacon-off", reason: "   " }, ownerAccess)));
    ok("acceptPostureRisk: a reason with a control character is rejected", await threw(() => dobj.acceptPostureRisk({ checkId: "beacon-off", reason: "bad\u0000reason" }, ownerAccess)));

    // Success as an attributable owner-with-sourceIp: the record carries the owner email.
    const acc1 = await dobj.acceptPostureRisk({ checkId: "beacon-off", reason: "  documented in the runbook  " }, ownerAccessIp);
    ok("acceptPostureRisk: an owner accept succeeds", acc1.ok === true);
    const rec1 = await storage.get<RiskAccept>(`${POSTURE_ACCEPT_PREFIX}beacon-off`);
    ok("acceptPostureRisk: the record carries the owner email and the trimmed reason", rec1?.acceptedBy === "owner@acme.au" && rec1?.reason === "documented in the runbook");

    // Success as a bare-token owner: acceptedBy is null (not attributable).
    await dobj.acceptPostureRisk({ checkId: "media-diversity", reason: "two media attested" }, ownerToken);
    const rec2 = await storage.get<RiskAccept>(`${POSTURE_ACCEPT_PREFIX}media-diversity`);
    ok("acceptPostureRisk: a bare-token owner records acceptedBy:null", rec2?.acceptedBy === null);

    // listRiskAccepts reflects both records.
    const accepts = (await dobj.listRiskAccepts()).map((a) => a.checkId).sort();
    ok("listRiskAccepts returns the stored risk-accept records", JSON.stringify(accepts) === JSON.stringify(["beacon-off", "media-diversity"]));

    // unacceptPostureRisk: a non-owner is refused; a missing/empty checkId is rejected.
    ok("unacceptPostureRisk: a viewer is refused", await threw(() => dobj.unacceptPostureRisk({ checkId: "beacon-off" }, viewer)));
    ok("unacceptPostureRisk: an empty checkId is rejected", await threw(() => dobj.unacceptPostureRisk({ checkId: "" }, ownerAccess)));

    // unaccept of an existing record by an attributable owner -> removed:true (audit appended).
    const un1 = await dobj.unacceptPostureRisk({ checkId: "beacon-off" }, ownerAccessIp);
    ok("unacceptPostureRisk: removing an existing accept returns removed:true", un1.removed === true && (await storage.get(`${POSTURE_ACCEPT_PREFIX}beacon-off`)) === undefined);

    // unaccept of an existing record by a bare-token owner -> removed:true (actorEmail/subject null path).
    const un2 = await dobj.unacceptPostureRisk({ checkId: "media-diversity" }, ownerToken);
    ok("unacceptPostureRisk: a bare-token owner can remove an accept", un2.removed === true);

    // unaccept of an absent record -> removed:false (no audit appended).
    const un3 = await dobj.unacceptPostureRisk({ checkId: "beacon-off" }, ownerAccess);
    ok("unacceptPostureRisk: removing an absent accept is idempotent (removed:false)", un3.removed === false);
  }

  // ========================================================================================
  // notifyHasFailureRule: false with no rules, true once a qualifying global rule exists
  // ========================================================================================
  {
    const { dobj } = makeScheduler();
    ok("notifyHasFailureRule: false with no notify rules", (await dobj.notifyHasFailureRule()) === false);
    // A rule must reference a real channel, so create one first, then a GLOBAL backup-failure rule.
    const chResp = await fetchDO(dobj, "POST", "/notify/channels", { kind: "webhook", name: "ops", url: "https://hooks.example.au/x", enabled: true }, ownerAccess);
    const chId = ((await chResp.json()) as { id?: string }).id ?? "";
    await fetchDO(dobj, "POST", "/notify/rules", { scope: { kind: "global" }, minSeverity: "warning", events: ["backup-failure"], channelIds: [chId], enabled: true }, ownerAccess);
    ok("notifyHasFailureRule: true once a global backup-failure rule exists", (await dobj.notifyHasFailureRule()) === true);
  }

  // ========================================================================================
  // gatherPostureState: per-downpipe + per-expiry conditional projections (present and absent)
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    // dpA carries every optional recency field + a "verified" seal verdict + two destinations (a primary +
    // one replica; primaryDestinationId takes destinationIds[0], so destinationIds carries both).
    await storage.put("dp:A", dpState("A", { lastRestoreTestAt: AT, lastRestoreTestOk: true, lastSealVerify: { status: "verified", at: AT } as unknown as NonNullable<DownpipeState["lastSealVerify"]> }, { restoreTestCadenceSeconds: 604800, destinationIds: ["d2", "d3"] }));
    // dpB carries none of those + a NON-verified seal verdict + no destinations.
    await storage.put("dp:B", dpState("B", { lastSealVerify: { status: "suspect", at: AT } as unknown as NonNullable<DownpipeState["lastSealVerify"]> }));
    // Expiry items: one ephemeral-with-cleanup (carries lifecycleClass + cleanupState) and one bare.
    await storage.put(`${EXPIRY_PREFIX}e1`, { id: "e1", label: "Spent attach token", kind: "token", source: "observed", lifecycleClass: "ephemeral", cleanupState: "pending", expiresAt: "2030-01-01T00:00:00.000Z" });
    await storage.put(`${EXPIRY_PREFIX}e2`, { id: "e2", label: "Functional key", kind: "key", source: "manual", expiresAt: "2030-01-01T00:00:00.000Z" });

    const gathered = await dobj.gatherPostureState(Date.now());
    const a = gathered.downpipes.find((d) => d.id === "A")!;
    const b = gathered.downpipes.find((d) => d.id === "B")!;
    ok("gatherPostureState: a fully-tested downpipe projects cadence + recency + a verified seal verdict", a.restoreTestCadenceSeconds === 604800 && a.lastRestoreTestAt === AT && a.lastRestoreTestOk === true && a.lastSealVerifyOk === true && a.destinationCount === 2);
    ok("gatherPostureState: an untested downpipe omits the recency fields and reports a non-verified seal verdict", b.restoreTestCadenceSeconds === undefined && b.lastRestoreTestAt === undefined && b.lastRestoreTestOk === undefined && b.lastSealVerifyOk === false && b.destinationCount === 0);
    const e1 = gathered.expiry.find((e) => e.label === "Spent attach token")!;
    const e2 = gathered.expiry.find((e) => e.label === "Functional key")!;
    ok("gatherPostureState: an ephemeral expiry item carries its lifecycleClass + cleanupState", e1.lifecycleClass === "ephemeral" && e1.cleanupState === "pending");
    ok("gatherPostureState: a bare expiry item omits lifecycleClass + cleanupState", e2.lifecycleClass === undefined && e2.cleanupState === undefined);
  }

  // ========================================================================================
  // computePostureReport: minimal (conservative defaults) vs rich (every override + prior snapshot)
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    // Minimal: no slice, no worm, no callerEmail, no destinations, no owners.
    const { report: rMin, regressions: regMin } = await dobj.computePostureReport({});
    ok("computePostureReport: a minimal call computes a report and (first time) no regressions", Array.isArray(rMin.checks) && rMin.checks.length > 0 && regMin.length === 0);
    ok("computePostureReport: the snapshot is persisted on first compute", (await storage.get(POSTURE_SNAPSHOT_KEY)) !== undefined);
  }
  {
    const { storage, dobj } = makeScheduler();
    // Seed two owners (two-owners passes + recoveryBreakGlassReady right-operand true), a plaintext + a wrapped
    // destination (the isWrappedSecret filter), the org policy (requireChangeNumber on) and an emergency marker.
    await storage.put("role:o1@acme.au", { email: "o1@acme.au", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-01-01T00:00:00.000Z" });
    await storage.put("role:o2@acme.au", { email: "o2@acme.au", role: "owner", grantedBy: "o1@acme.au", grantedAt: "2026-01-01T00:00:00.000Z" });
    await storage.put(DESTINATIONS_KEY, { list: [{ id: "d1", secretAccessKey: "plaintext-key", endpoint: "https://x.r2", bucket: "b1", region: "auto", accessKeyId: "AK1" }, { id: "d2", secretAccessKey: { v: 1, iv: "aXY", ct: "cZW" }, endpoint: "https://y.r2", bucket: "b2", region: "auto", accessKeyId: "AK2" }], defaultId: "d1" });
    await storage.put(ORG_POLICY_KEY, { requireConfigApproval: false, requireChangeNumber: true });
    await storage.put("change-emergency-marker", { count: 2, lastAt: "2026-02-02T00:00:00.000Z" });

    const richBody = {
      status: { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: true }, tokenFallbackDisabled: true, adminTokenPresent: true },
      authMethod: "access",
      beaconEnabled: true,
      callerEmail: "o1@acme.au",
      worm: { configured: true, mode: "compliance", retentionDays: 30, bucketEnforces: true },
      configWrapKeyConfigured: true,
    };
    const { report: r1 } = await dobj.computePostureReport(richBody);
    const by1 = byId(r1);
    ok("computePostureReport: two seeded owners -> two-owners passes", by1.get("two-owners")?.status === "pass");
    ok("computePostureReport: a plaintext destination under a configured wrap key -> dest-cred-encryption fails", by1.get("dest-cred-encryption")?.status === "fail");
    ok("computePostureReport: the WORM slice drives an immutability check", by1.get("immutability") !== undefined);

    // Second compute on the SAME instance: the prior snapshot is now present (the prior-branch).
    const { report: r2 } = await dobj.computePostureReport(richBody);
    ok("computePostureReport: a second compute reads the prior snapshot and stays stable (no spurious regression)", Array.isArray(r2.checks) && r2.checks.length === r1.checks.length);

    // No stored key holds the left operand of recoveryBreakGlassReady any more (see the standing comment in
    // scheduler-do-limits.ts), so it is not seeded here; writing a key nothing reads would test nothing.
    // The beaconEnabled:false compute below is kept because it is real coverage on its own.
    const { report: r3 } = await dobj.computePostureReport({ beaconEnabled: false });
    ok("computePostureReport: a beacon-disabled body still computes a full report", Array.isArray(r3.checks) && r3.checks.length > 0);
  }

  // ========================================================================================
  // parsePostureStatusSlice: garbled raw -> all-false; full object -> all-true; null op object
  // ========================================================================================
  {
    const { dobj } = makeScheduler();
    const sNull = dobj.parsePostureStatusSlice(undefined);
    ok("parsePostureStatusSlice: a non-object raw degrades every flag to its worse-posture reading", sNull.destConfigured === false && sNull.breakGlassConfigured === false && sNull.operationalConfigured.private === false && sNull.tokenFallbackDisabled === false && sNull.adminTokenPresent === true);
    const sFull = dobj.parsePostureStatusSlice({ destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: true }, tokenFallbackDisabled: true, adminTokenPresent: true });
    ok("parsePostureStatusSlice: a full object reads every flag true (DO-owned fields seeded false)", sFull.destConfigured === true && sFull.breakGlassConfigured === true && sFull.operationalConfigured.public === true && sFull.operationalConfigured.private === true && sFull.tokenFallbackDisabled === true && sFull.adminTokenPresent === true && sFull.bootstrapConsumed === false && sFull.recoveryBreakGlassReady === false);
    const sNoOp = dobj.parsePostureStatusSlice({ operationalConfigured: null });
    ok("parsePostureStatusSlice: a null operationalConfigured falls back to both flags false", sNoOp.operationalConfigured.public === false && sNoOp.operationalConfigured.private === false);
  }

  // ========================================================================================
  // parsePostureWormSlice: undefined raw; null raw; full valid; alternates; every undefined fallback
  // ========================================================================================
  {
    const { dobj } = makeScheduler();
    ok("parsePostureWormSlice: a non-object raw returns undefined", dobj.parsePostureWormSlice("nope") === undefined);
    ok("parsePostureWormSlice: a null raw returns undefined", dobj.parsePostureWormSlice(null) === undefined);

    const full = dobj.parsePostureWormSlice({ configured: true, misconfigured: true, mode: "governance", retentionDays: 7, bucketEnforces: true, probeMode: "compliance", probeDays: 3 })!;
    ok("parsePostureWormSlice: a full valid slice carries every field", full.configured === true && full.misconfigured === true && full.mode === "governance" && full.retentionDays === 7 && full.bucketEnforces === true && full.probeMode === "compliance" && full.probeDays === 3);

    const alt = dobj.parsePostureWormSlice({ mode: "compliance", probeMode: "governance", bucketEnforces: false })!;
    ok("parsePostureWormSlice: the mode alternates resolve and bucketEnforces:false is honoured", alt.mode === "compliance" && alt.probeMode === "governance" && alt.bucketEnforces === false);

    const unknownEnforce = dobj.parsePostureWormSlice({ bucketEnforces: "unknown" })!;
    ok("parsePostureWormSlice: bucketEnforces \"unknown\" is honoured", unknownEnforce.bucketEnforces === "unknown");

    // Every invalid optional drops to undefined: bad modes, non-integer / non-positive days, garbage enforce.
    const dropped = dobj.parsePostureWormSlice({ mode: "bad", probeMode: 5, retentionDays: 1.5, probeDays: 0, bucketEnforces: "maybe" })!;
    ok("parsePostureWormSlice: invalid optionals all drop to undefined (safe not-configured reading)", dropped.mode === undefined && dropped.probeMode === undefined && dropped.retentionDays === undefined && dropped.probeDays === undefined && dropped.bucketEnforces === undefined && dropped.configured === false);

    // defaultRetention: whether the LOCK-ENABLED bucket carries a default retention rule of its own. It is
    // honoured only as a real boolean and only alongside an enforcing bucket, which is the only state the
    // router's probe sets it in, so a forwarded claim of retention on a bucket that does not read as
    // enforcing is dropped rather than carried.
    const retained = dobj.parsePostureWormSlice({ configured: true, bucketEnforces: true, defaultRetention: true })!;
    ok("parsePostureWormSlice: defaultRetention true is carried on an enforcing bucket", retained.defaultRetention === true);
    const unretained = dobj.parsePostureWormSlice({ configured: true, bucketEnforces: true, defaultRetention: false })!;
    ok("parsePostureWormSlice: defaultRetention false is carried, not collapsed into absent", unretained.defaultRetention === false);
    const noVerdict = dobj.parsePostureWormSlice({ configured: true, bucketEnforces: true })!;
    ok("parsePostureWormSlice: an unstated defaultRetention stays absent (cannot-confirm, never false)", noVerdict.defaultRetention === undefined && !("defaultRetention" in noVerdict));
    const mismatched = dobj.parsePostureWormSlice({ configured: true, bucketEnforces: false, defaultRetention: true })!;
    ok("parsePostureWormSlice: defaultRetention is dropped when the bucket does not read as enforcing", mismatched.defaultRetention === undefined);
    const nonBool = dobj.parsePostureWormSlice({ configured: true, bucketEnforces: true, defaultRetention: "yes" })!;
    ok("parsePostureWormSlice: a non-boolean defaultRetention drops to undefined", nonBool.defaultRetention === undefined);
  }

  // ========================================================================================
  // Routed end-to-end (production fetch router): HTTP status mapping for the gated/guarded paths
  // ========================================================================================
  {
    const { storage, dobj } = makeScheduler();
    await storage.put("dp:rt", dpState("rt", {}, { restoreTestCadenceSeconds: 100 }));

    // POST /restore-tests-due (internal) returns the due set.
    const dueResp = await fetchDO(dobj, "POST", "/restore-tests-due", {});
    ok("router: POST /restore-tests-due returns 200 with the due set", dueResp.status === 200 && ((await dueResp.json()) as { due: DownpipeState[] }).due.length === 1);

    // POST /posture computes (200) and persists a snapshot.
    const postureResp = await fetchDO(dobj, "POST", "/posture", { status: { destConfigured: true }, authMethod: "access", beaconEnabled: false });
    ok("router: POST /posture returns 200 and a report+regressions", postureResp.status === 200 && Array.isArray(((await postureResp.json()) as { report: PostureReport }).report.checks));

    // POST /posture/accept: a non-owner is refused (403); an owner accepts (200); an unknown id is 400.
    const accDenied = await fetchDO(dobj, "POST", "/posture/accept", { checkId: "beacon-off", reason: "no" }, viewer);
    ok("router: a non-owner posture accept is refused (403)", accDenied.status === 403);
    const accOk = await fetchDO(dobj, "POST", "/posture/accept", { checkId: "beacon-off", reason: "documented" }, ownerAccess);
    ok("router: an owner posture accept succeeds (200)", accOk.status === 200);
    const accBad = await fetchDO(dobj, "POST", "/posture/accept", { checkId: "not-a-real-check", reason: "x" }, ownerAccess);
    ok("router: an unknown checkId is rejected (400)", accBad.status === 400);
    const unOk = await fetchDO(dobj, "POST", "/posture/unaccept", { checkId: "beacon-off" }, ownerAccess);
    ok("router: an owner posture unaccept returns removed:true (200)", unOk.status === 200 && ((await unOk.json()) as { removed: boolean }).removed === true);

    // POST /fleet-drill/start: a viewer is refused (403); an operator starts (200).
    const fdDenied = await fetchDO(dobj, "POST", "/fleet-drill/start", {}, viewer);
    ok("router: a fleet-drill start without drill.run is refused (403)", fdDenied.status === 403);
    const fdOk = await fetchDO(dobj, "POST", "/fleet-drill/start", {}, operator);
    ok("router: an operator fleet-drill start succeeds (200)", fdOk.status === 200 && ((await fdOk.json()) as { ok: boolean }).ok === true);
    const fdStatus = await fetchDO(dobj, "GET", "/fleet-drill/status");
    ok("router: GET /fleet-drill/status reports the active campaign", fdStatus.status === 200 && ((await fdStatus.json()) as { active: boolean }).active === true);
  }

  // ========================================================================================
  // recordReconcileInventory + reconcileInventory: validate/clamp, per-dest overwrite, cap, read-back
  // (support-pack modes reconcile-orphans-invisible / runlog-corrupt-parse)
  // ========================================================================================
  {
    const { dobj } = makeScheduler();
    ok("reconcileInventory is empty before any reconcile pass", (await dobj.reconcileInventory()).byDest.length === 0);

    // A well-formed signal round-trips; a per-destination re-post OVERWRITES (keyed by destKey).
    await dobj.recordReconcileInventory({ destKey: "dest-a", at: AT, runlogPresent: true, runlogSigVerified: true, committed: 5, orphanedRecoverable: 2, neverReferenced: 1, undetermined: 0, circuitBreakerTripped: false });
    await dobj.recordReconcileInventory({ destKey: "dest-a", at: AT + 1000, runlogPresent: true, runlogSigVerified: true, committed: 6, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, circuitBreakerTripped: false });
    let inv = (await dobj.reconcileInventory()).byDest;
    ok("a per-destination signal round-trips and a re-post overwrites (keyed by destKey)", inv.length === 1 && inv[0]!.destKey === "dest-a" && inv[0]!.committed === 6 && inv[0]!.at === AT + 1000);

    // runlog-sig-stale-window + freshness-rollback-residual: the runlogHealth enum + freshnessResiduals count
    // round-trip on the verified path.
    ok("the verified signal carries runlogHealth=ok + a freshnessResiduals count", inv[0]!.runlogHealth === "ok" && inv[0]!.freshnessResiduals === 0);
    await dobj.recordReconcileInventory({ destKey: "dest-fr", at: AT, runlogPresent: true, runlogSigVerified: true, runlogHealth: "ok", committed: 4, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, freshnessResiduals: 2, circuitBreakerTripped: false });
    const fr = (await dobj.reconcileInventory()).byDest.find((s) => s.destKey === "dest-fr");
    ok("freshnessResiduals (dangling prev-links) round-trips", fr?.freshnessResiduals === 2);

    // The corrupt-RUNLOG health + abstain class round-trip (the runlog-corrupt-parse signal); a body-vs-sig
    // stale window is distinguished by runlogHealth=stale-window (runlog-sig-stale-window).
    await dobj.recordReconcileInventory({ destKey: "dest-b", at: AT, runlogPresent: true, runlogSigVerified: false, runlogHealth: "corrupt", committed: 0, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, circuitBreakerTripped: false, deferred: "runlog-unverifiable" });
    const b = (await dobj.reconcileInventory()).byDest.find((s) => s.destKey === "dest-b");
    ok("the corrupt-RUNLOG health + abstain class round-trip", b?.runlogSigVerified === false && b?.deferred === "runlog-unverifiable" && b?.runlogHealth === "corrupt");
    await dobj.recordReconcileInventory({ destKey: "dest-sw", at: AT, runlogPresent: true, runlogSigVerified: false, runlogHealth: "stale-window", committed: 0, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, circuitBreakerTripped: false, deferred: "runlog-unverifiable" });
    ok("a body-vs-sig stale window round-trips as runlogHealth=stale-window", (await dobj.reconcileInventory()).byDest.find((s) => s.destKey === "dest-sw")?.runlogHealth === "stale-window");

    // Defensive validation: a malformed body clamps a negative/NaN/fractional count, coerces non-booleans
    // to false, drops an out-of-vocabulary abstain class, length-caps the destKey, drops an out-of-vocabulary
    // runlogHealth (falling back to the health the booleans imply), and clamps freshnessResiduals (fail-closed).
    await dobj.recordReconcileInventory({ destKey: "x".repeat(300), at: "nope", runlogPresent: "yes", runlogSigVerified: 1, runlogHealth: "hostile", committed: -5, orphanedRecoverable: Number.NaN, neverReferenced: 2.9, undetermined: 4, freshnessResiduals: -9, circuitBreakerTripped: "true", deferred: "hostile" });
    const m = (await dobj.reconcileInventory()).byDest.find((s) => s.destKey.startsWith("x"));
    ok("a malformed signal is clamped (counts>=0 ints, flags strict-false, out-of-vocab abstain dropped, destKey capped)", m !== undefined && m.destKey.length === 128 && m.committed === 0 && m.orphanedRecoverable === 0 && m.neverReferenced === 2 && m.runlogPresent === false && m.circuitBreakerTripped === false && m.deferred === undefined && typeof m.at === "number");
    ok("an out-of-vocab runlogHealth falls back to the booleans (present=false -> absent) + freshnessResiduals clamps to 0", m?.runlogHealth === "absent" && m?.freshnessResiduals === 0);

    // Cap: after more than RECONCILE_SIGNAL_MAX (32) distinct destinations, only the freshest 32 by `at`
    // are kept (a churning fleet cannot grow the map unbounded).
    const { dobj: dobj2 } = makeScheduler();
    for (let i = 0; i < 40; i++) await dobj2.recordReconcileInventory({ destKey: `d${i}`, at: AT + i, runlogPresent: true, runlogSigVerified: true, committed: i, orphanedRecoverable: 0, neverReferenced: 0, undetermined: 0, circuitBreakerTripped: false });
    const capped = (await dobj2.reconcileInventory()).byDest;
    ok("the map is bounded to the freshest 32 destinations (oldest dropped, newest first)", capped.length === 32 && capped[0]!.destKey === "d39" && capped.every((s) => Number(s.destKey.slice(1)) >= 8));
  }

  // ========================================================================================
  // recordSealFault + sealFaults: kind-gate, round-trip, newest-first order, clamps, cap, route
  // (support-pack seal-integrity modes shard-list-truncated / shard-truncation-stalekeys /
  // lease-lost-abandon / orphan-root-worm-leak / signer-rotation-strands-runs)
  // ========================================================================================
  {
    const { dobj } = makeScheduler();
    ok("sealFaults is empty before any observed fault", (await dobj.sealFaults()).faults.length === 0);

    // A well-formed shard-list-truncated observation round-trips with its found/expected counts.
    await dobj.recordSealFault({ kind: "shard-list-truncated", at: AT, downpipeId: "dp1", runId: "01RUN", found: 968, expected: 970 });
    let faults = (await dobj.sealFaults()).faults;
    ok("a shard-list-truncated observation round-trips with its counts", faults.length === 1 && faults[0]!.kind === "shard-list-truncated" && faults[0]!.found === 968 && faults[0]!.expected === 970 && faults[0]!.runId === "01RUN");

    // Distinct kinds all land and read back NEWEST FIRST (the ring is newest-last, read reversed).
    await dobj.recordSealFault({ kind: "lease-lost-abandon", at: AT + 1, downpipeId: "dp1", runId: "01B" });
    await dobj.recordSealFault({ kind: "orphan-root-reclaim", at: AT + 2, downpipeId: "dp1", runId: "01C", reclaimed: 4, wormBlocked: true });
    faults = (await dobj.sealFaults()).faults;
    ok("distinct kinds accumulate and read back newest-first", faults.length === 3 && faults[0]!.kind === "orphan-root-reclaim" && faults[0]!.wormBlocked === true && faults[0]!.reclaimed === 4 && faults[2]!.kind === "shard-list-truncated");

    // An out-of-vocabulary kind is DROPPED (no-op, never persisted -- fail-closed redaction).
    await dobj.recordSealFault({ kind: "hostile-not-a-kind", at: AT + 3 });
    ok("an out-of-vocabulary kind is dropped (the ring is unchanged)", (await dobj.sealFaults()).faults.length === 3);

    // Defensive clamps: a negative/NaN count clamps, a non-boolean WORM flag coerces to false, an
    // over-length id is capped, and `at` defaults to the DO clock on a malformed value.
    await dobj.recordSealFault({ kind: "stale-shard-rows-cleaned", at: "nope", downpipeId: "d".repeat(300), runId: "01D", cleaned: -7, wormBlocked: 1 });
    const clamped = (await dobj.sealFaults()).faults.find((f) => f.kind === "stale-shard-rows-cleaned");
    ok("a malformed observation is clamped (count>=0, id capped at 128, flag strict-false, at defaulted)", clamped !== undefined && clamped.cleaned === 0 && clamped.downpipeId!.length === 128 && clamped.wormBlocked === false && typeof clamped.at === "number");

    // Cap: after more than SEAL_FAULT_MAX (64) observations, only the freshest 64 are kept (oldest dropped).
    const { dobj: dobj2 } = makeScheduler();
    for (let i = 0; i < 80; i++) await dobj2.recordSealFault({ kind: "lease-lost-abandon", at: AT + i, runId: `r${i}` });
    const ring = (await dobj2.sealFaults()).faults;
    ok("the ring is bounded to the freshest 64 (oldest dropped, newest first)", ring.length === 64 && ring[0]!.runId === "r79" && ring[63]!.runId === "r16");

    // Route round-trip: POST /seal-fault records; GET /seal-faults reads back (exercises the HTTP dispatch).
    const { dobj: dobj3 } = makeScheduler();
    const postResp = await fetchDO(dobj3, "POST", "/seal-fault", { kind: "checkpoint-unwrap-failed", at: AT, downpipeId: "dp1", runId: "01E" });
    ok("POST /seal-fault returns ok", postResp.status === 200 && ((await postResp.json()) as { ok: boolean }).ok === true);
    const getResp = await fetchDO(dobj3, "GET", "/seal-faults");
    const body = (await getResp.json()) as { faults: SealFault[] };
    ok("GET /seal-faults reads the observation back", getResp.status === 200 && body.faults.length === 1 && body.faults[0]!.kind === "checkpoint-unwrap-failed" && body.faults[0]!.runId === "01E");
  }

  console.log(failures === 0 ? "\nVECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

// byId indexes a report's checks for assertions.
function byId(report: PostureReport): Map<string, PostureCheck> {
  return new Map(report.checks.map((c) => [c.id, c]));
}

void main();
