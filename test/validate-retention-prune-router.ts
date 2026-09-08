// Validates the batched-capsule retention-prune ROUTE (src/admin/router-retention-prune.ts) end to
// end, driving the REAL router spoke, a REAL SchedulerDO (in-memory storage, including the dual-control
// PruneApproval state machine) and the REAL planner/apply path (seal/prune.ts planPrune/applyPrune,
// unmodified) over a genuine sealed downpipe/0.1.0 archive in a MockR2 destination. No network, no deploy,
// no cost. Run: node test/validate-retention-prune-router.ts
//
// Proves two load-bearing properties, each both ways:
//   DUAL CONTROL: a single identity plus step-up is not enough to delete archive bytes outright.
//   Proven positive (a request + a DISTINCT approver's approval + a matching apply actually applies,
//   single-use -- reusing a consumed approval is refused) and negative (no approval refuses; a
//   SELF-approval is refused even for an Owner; the bare-token break-glass can neither request nor
//   approve; a REJECTED request cannot be applied) -- section 3.
//   FULL CANDIDATE COVERAGE: planPrune's own invariant only protects a segment referenced by a RETAINED
//   run; an unopenable SUPERSEDED run must not be silently excluded while a sibling superseded run sharing
//   its segment still gets it deleted, which would leave a still-"active" manifest pointing at missing
//   bytes. Proven negative (an incomplete or wrong-master batch refuses OUTRIGHT, naming every unopenable
//   run, before planPrune ever runs) and positive (the complete batch applies correctly) -- sections 5 and
//   6, section 6 driving a four-run shared-segment fixture and directly re-reading the previously-at-risk
//   run's manifest to prove every segment it references still exists.
// Plus: the capability floor (restore.apply, not below drill.run), the candidate route's read-safe floor
// (restore.verify), the enforce-off/no-authority-invented guarantee, the batch-size cap and the malformed-
// master 400s.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { signRunlog, type RunlogEntry } from "../src/format/writer-runlog.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRunWithMaster } from "../src/format/reader.ts";
import { handleRetentionPrune } from "../src/admin/router-retention-prune.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import type { Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState } from "../src/sched/types.ts";
import type { DestPruneState } from "../src/cron/retention-dest-prune.ts";
import { seedBoundRole } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

import { MockStorage } from "./mock-storage.ts";

// ---- MockR2: the raw R2 binding surface buildDestination("r2") reads, the same shape every admin-router
// validator that drives a real destination write uses (validate-cov-admin-router-restore.ts).
class MockR2 {
  store = new Map<string, Uint8Array>();
  // poisonPrefix (reserve-leak proof): when set, list() THROWS for any prefix starting with
  // it, simulating a transient R2 fault mid-listRunTree -- r2.ts's guarded() wraps and re-throws every
  // native R2Bucket error unchanged in shape, so this is a real, reachable failure mode, not a contrived one.
  poisonPrefix: string | null = null;
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => toAB(v), etag: `"${key.length}:${v.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}:${v.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    const b = body instanceof Uint8Array ? body : new Uint8Array(body);
    this.store.set(key, b);
    return { etag: `"${key.length}:${b.length}"` };
  }
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
  async list(opts: { prefix?: string }): Promise<{ objects: Array<{ key: string }>; truncated: boolean }> {
    const prefix = opts.prefix ?? "";
    if (this.poisonPrefix !== null && prefix.startsWith(this.poisonPrefix)) {
      throw new Error("simulated R2 native listing fault (network blip mid-list)");
    }
    return { objects: [...this.store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })), truncated: false };
  }
}
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

function makeRecipient(role: string): RecipientEntry {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } };
}

function makeScheduler(): { storage: MockStorage; scheduler: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const scheduler = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, scheduler };
}

async function seedDownpipe(storage: MockStorage, id: string, name: string, retention: { keepRuns?: number; enforce?: boolean } | undefined): Promise<void> {
  const state = {
    config: { id, name, enabled: true, source: { type: "kv", binding: `SRC_${id}` }, schedule: { cadenceSeconds: 3600 }, ...(retention !== undefined ? { retention } : {}) },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  } as unknown as DownpipeState;
  await storage.put(`dp:${id}`, state);
}

// sealRun writes ONE downpipe/0.1.0 run's objects straight into the MockR2 store (no Destination
// indirection needed for a seed with no concurrent writer). Returns nothing; the caller collects the
// RUNLOG entry separately so several downpipes' entries can be merged into ONE signed RUNLOG document,
// exactly as a shared default destination holds every downpipe's runs in one _RECOVERY/RUNLOG (SPEC 10).
//
// runlogIndex / prevRunId are the freshness fields SIGNED INTO THIS RUN'S ROOT, and they must be the same
// pair the merged RUNLOG below gives this run. A real seal writes both from one value (pipeline.ts signs
// the root from clock.runlogIndex and appends the entry with the same index), so a fixture that signed
// every root at index 1 while its log counted 1..14 was modelling a destination the engine cannot produce:
// the entry and the root disagreed for thirteen of the fourteen runs, which is a rollback signal.
async function sealRun(r2: MockR2, signer: Signer, recipients: RecipientEntry[], master: Uint8Array, downpipeId: string, runId: string, value: string, runlogIndex: number, prevRunId: string | null): Promise<void> {
  const archive = await buildArchive({
    downpipeId,
    downpipeName: downpipeId,
    cadence: "3600s",
    runId,
    master,
    recipients,
    signer,
    records: [{ sourceType: "kv", name: "k", value: utf8(value), namespace: "ns" }],
    windowStart: "2026-06-01T00:00:00.000Z",
    windowEnd: "2026-06-01T00:00:00.000Z",
    createdAt: "2026-06-01T00:00:00.000Z",
    runlogIndex,
    prevRunId,
    skipRunlog: true,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  for (const [key, body] of archive) r2.store.set(key, body);
}

// writeRunlog signs the given entries as ONE document and writes _RECOVERY/RUNLOG + its .sig directly
// (pipeline.ts's own key names), mirroring appendRunlog's final write without its CAS/lock machinery,
// which a fresh single-writer seed does not need.
async function writeRunlog(r2: MockR2, signer: Signer, entries: RunlogEntry[]): Promise<void> {
  const sorted = [...entries].sort((a, b) => a.index - b.index);
  const { runlog, sig } = await signRunlog(sorted, signer.edPrivate, signer.mldsaSecret);
  r2.store.set("_RECOVERY/RUNLOG", runlog);
  r2.store.set("_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig)));
}

function ctx(env: Env, scheduler: DurableObjectStub, caller: Caller, method: string, sub: string, body?: unknown): RouterCtx {
  const url = new URL(`https://engine.example/admin${sub}`);
  const req = new Request(url, { method, ...(body !== undefined ? { body: JSON.stringify(body) } : {}), headers: { "content-type": "application/json" } });
  return {
    req,
    env,
    url,
    scheduler,
    caller,
    sub,
    sourceIp: null,
    runtime: undefined,
    verdict: {} as unknown as RouterCtx["verdict"],
    isOnlyOwner: false,
    roleSource: "token" as unknown as RouterCtx["roleSource"],
    customRole: undefined,
  };
}

async function call(env: Env, scheduler: DurableObjectStub, caller: Caller, method: string, sub: string, body?: unknown): Promise<{ status: number; json: Record<string, unknown> }> {
  const resp = await handleRetentionPrune(ctx(env, scheduler, caller, method, sub, body));
  if (resp === null) return { status: 404, json: { error: "no route" } };
  const text = await resp.text();
  let json: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(text);
    json = parsed !== null && typeof parsed === "object" ? (parsed as Record<string, unknown>) : { raw: parsed };
  } catch {
    json = { raw: text };
  }
  return { status: resp.status, json };
}

const callerOwner: Caller = { method: "access", email: "owner@acme.example", subject: "acc|owner", role: "owner", groups: [] };
// A SECOND, distinct owner identity: the checker every dual-control approval in this file needs (maker !=
// checker on the STABLE subject). Never the same subject as callerOwner.
const callerOwner2: Caller = { method: "access", email: "owner2@acme.example", subject: "acc|owner2", role: "owner", groups: [] };
// operator holds drill.run but NOT restore.apply (identity-rbac.ts ROLE_CAPABILITIES): the exact negative
// control for the claim "gated on restore.apply, not drill.run" -- a drill.run holder without restore.apply
// must still be refused the destructive route.
const callerOperator: Caller = { method: "access", email: "operator@acme.example", subject: "acc|operator", role: "operator", groups: [] };
// A caller whose RESOLVED capability set is deliberately empty (the custom-role shape), used to prove the
// candidate route's restore.verify gate actually denies: restore.verify is granted from the viewer floor up
// to EVERY built-in role, so no built-in role can exercise this denial -- an explicit empty set is the only
// way to drive the real gate() codepath into refusing it.
const callerNoCaps: Caller = { method: "access", email: "empty@acme.example", subject: "acc|empty", role: "viewer", groups: [], capabilities: new Set() };
// The bare-token break-glass fallback: no stable subject, so dual control must refuse it on both legs
// (it can neither raise nor approve a request), mirroring restore's identical refusal.
const callerToken: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
// A SECOND identity for the SAME human as callerOwner -- same verified email, a genuinely distinct
// IdP-bound subject. Only the maker != checker EMAIL floor should refuse this one; the capability gate
// passes (owner) and the subject genuinely differs from callerOwner's.
const callerOwnerSameEmail: Caller = { method: "access", email: "owner@acme.example", subject: "acc|owner-second-identity", role: "owner", groups: [] };

// readLastPrune reads the per-destination prune sidecar row this fixture's env destination folds under
// (the default slot "" -- there is no console destination collection here), through the SAME
// DestStatusView join the console reads. undefined = no pass has recorded anything yet.
async function readLastPrune(scheduler: DurableObjectStub): Promise<DestPruneState | undefined> {
  const r = await scheduler.fetch("https://do/dest-status", { method: "GET" });
  return ((await r.json()) as { lastPrune?: DestPruneState }).lastPrune;
}

// readRetentionSlot reads the latest CRON pass slot (GET /retention-state), which an attended record
// must never supersede.
async function readRetentionSlot(scheduler: DurableObjectStub): Promise<unknown> {
  const r = await scheduler.fetch("https://do/retention-state", { method: "GET" });
  return ((await r.json()) as { record?: unknown }).record ?? null;
}

// requestAndApprove drives the real /retention-prune/request then /retention-prune/approve routes (never a
// hand-computed planHash in the test, so the test can never disagree with the router about the binding) and
// returns the approved planHash, or throws with the failing step's body for a clear test failure.
async function requestAndApprove(env: Env, scheduler: DurableObjectStub, downpipeId: string, requester: Caller, approver: Caller, reason: string): Promise<string> {
  const reqResp = await call(env, scheduler, requester, "POST", "/retention-prune/request", { downpipeId, reason });
  if (reqResp.status !== 200) throw new Error(`prune request failed: ${JSON.stringify(reqResp)}`);
  const planHash = String(reqResp.json.planHash ?? "");
  const apResp = await call(env, scheduler, approver, "POST", "/retention-prune/approve", { planHash });
  if (apResp.status !== 200) throw new Error(`prune approve failed: ${JSON.stringify(apResp)}`);
  return planHash;
}

async function main(): Promise<void> {
  console.log("validate-retention-prune-router: batched-capsule prune route (candidate + apply)");

  // ---- shared fixture: ONE signer, ONE fixed master, ONE MockR2 destination holding TWO downpipes' runs,
  // each shaped like validate-prune.ts's PART B (a unique run 1, then runs 2+3 sharing a value so they
  // content-address to the SAME seg object -- the shared-segment safety case). ------------------------
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const recipients = [makeRecipient("break-glass"), makeRecipient("operational")];
  const master = rand(32);
  const wrongMaster = rand(32); // a structurally-valid but FOREIGN 32-byte value: never this archive's master

  const r2 = new MockR2();
  const baseEnv = (): Env => ({ SCHEDULER: {} as unknown as DurableObjectNamespace, DEST_KIND: "r2", DEST_R2: r2 as unknown as R2Bucket, SIGNER_PRIVATE: signerPrivateB64 }) as unknown as Env;
  const { storage, scheduler } = makeScheduler();

  // The dual-control identities hold their grants in the DO's OWN role table, not only on the forwarded
  // caller header. The prune routes trust the router-forwarded role; the SPEND-TIME identity binding at the
  // reserve deliberately does not, because there is no caller at a reserve to trust -- it re-resolves the
  // recorded maker and checker from their immutable subjects against the live tables. Without the grants a
  // prune approved by two identities the table has never heard of would be refused, correctly, and this file
  // would be proving the wrong refusal.
  for (const c of [callerOwner, callerOwner2, callerOperator, callerOwnerSameEmail]) {
    await seedBoundRole(storage, c.subject!, c.email, c.role);
  }

  // dp_green: retention.enforce TRUE. Will be pruned CORRECTLY (the GREEN proof).
  await seedDownpipe(storage, "dp_green", "Green", { keepRuns: 1, enforce: true });
  await sealRun(r2, signer, recipients, master, "dp_green", "01ARZ3NDEKTSV4RRFFQ69G5FA0", "value-one", 1, null);
  await sealRun(r2, signer, recipients, master, "dp_green", "01ARZ3NDEKTSV4RRFFQ69G5FA1", "shared-value", 2, "01ARZ3NDEKTSV4RRFFQ69G5FA0");
  await sealRun(r2, signer, recipients, master, "dp_green", "01ARZ3NDEKTSV4RRFFQ69G5FA2", "shared-value", 3, "01ARZ3NDEKTSV4RRFFQ69G5FA1");

  // dp_abstain: retention.enforce TRUE too, but the batch the operator submits will be INCOMPLETE / WRONG
  // (the RED proof: the refusal must actually hold, never a guess-and-delete).
  await seedDownpipe(storage, "dp_abstain", "Abstain", { keepRuns: 1, enforce: true });
  await sealRun(r2, signer, recipients, master, "dp_abstain", "01ARZ3NDEKTSV4RRFFQ69G5FB0", "value-one", 4, null);
  await sealRun(r2, signer, recipients, master, "dp_abstain", "01ARZ3NDEKTSV4RRFFQ69G5FB1", "shared-value", 5, "01ARZ3NDEKTSV4RRFFQ69G5FB0");
  await sealRun(r2, signer, recipients, master, "dp_abstain", "01ARZ3NDEKTSV4RRFFQ69G5FB2", "shared-value", 6, "01ARZ3NDEKTSV4RRFFQ69G5FB1");

  // dp_preview: retention configured but enforce ABSENT (dry-run posture; the "no authority invented" proof).
  await seedDownpipe(storage, "dp_preview", "Preview", { keepRuns: 1 });
  await sealRun(r2, signer, recipients, master, "dp_preview", "01ARZ3NDEKTSV4RRFFQ69G5FC0", "value-one", 7, null);
  await sealRun(r2, signer, recipients, master, "dp_preview", "01ARZ3NDEKTSV4RRFFQ69G5FC1", "value-two", 8, "01ARZ3NDEKTSV4RRFFQ69G5FC0");

  // dp_x: a four-run shared-segment fixture: keepRuns:1 retains ONLY run 4 (newest); runs 1, 2, 3 are
  // ALL superseded. Runs 2 and 3 share "shared-value" -> content-addressed to the SAME segment object. The
  // hazard this guards: a batch supplying masters for the retained run 4 and superseded run 2 (openable)
  // but OMITTING superseded run 3 (which shares run 2's segment) would delete that shared segment while
  // run 3's RUNLOG entry stayed "active" and its manifest still referenced it -- a live, still-active run
  // left pointing at bytes that no longer exist. Mandatory 100% candidate coverage before any delete
  // closes it: run 3 is a CANDIDATE (it is superseded, not retained, but every candidate must open now),
  // so its omission refuses the whole call before planPrune ever runs.
  await seedDownpipe(storage, "dp_x", "X", { keepRuns: 1, enforce: true });
  await sealRun(r2, signer, recipients, master, "dp_x", "01ARZ3NDEKTSV4RRFFQ69G5FX0", "unique-one", 9, null);
  await sealRun(r2, signer, recipients, master, "dp_x", "01ARZ3NDEKTSV4RRFFQ69G5FX1", "shared-value", 10, "01ARZ3NDEKTSV4RRFFQ69G5FX0");
  await sealRun(r2, signer, recipients, master, "dp_x", "01ARZ3NDEKTSV4RRFFQ69G5FX2", "shared-value", 11, "01ARZ3NDEKTSV4RRFFQ69G5FX1");
  await sealRun(r2, signer, recipients, master, "dp_x", "01ARZ3NDEKTSV4RRFFQ69G5FX3", "unique-four", 12, "01ARZ3NDEKTSV4RRFFQ69G5FX2");

  // dp_leak: a reservation-leak fixture. keepRuns:1 retains run 2 (newest), supersedes run 1. No shared
  // segment involved; this is purely about the reservation lifecycle when planPrune's OWN step
  // (listRunTree -> dest.list()) throws.
  await seedDownpipe(storage, "dp_leak", "Leak", { keepRuns: 1, enforce: true });
  await sealRun(r2, signer, recipients, master, "dp_leak", "01ARZ3NDEKTSV4RRFFQ69G5FY0", "one", 13, null);
  await sealRun(r2, signer, recipients, master, "dp_leak", "01ARZ3NDEKTSV4RRFFQ69G5FY1", "two", 14, "01ARZ3NDEKTSV4RRFFQ69G5FY0");

  await writeRunlog(r2, signer, [
    { index: 1, runId: "01ARZ3NDEKTSV4RRFFQ69G5FA0", downpipeId: "dp_green", time: "2026-06-01T00:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
    { index: 2, runId: "01ARZ3NDEKTSV4RRFFQ69G5FA1", downpipeId: "dp_green", time: "2026-06-02T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FA0", status: "active" },
    { index: 3, runId: "01ARZ3NDEKTSV4RRFFQ69G5FA2", downpipeId: "dp_green", time: "2026-06-03T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FA1", status: "active" },
    { index: 4, runId: "01ARZ3NDEKTSV4RRFFQ69G5FB0", downpipeId: "dp_abstain", time: "2026-06-01T00:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
    { index: 5, runId: "01ARZ3NDEKTSV4RRFFQ69G5FB1", downpipeId: "dp_abstain", time: "2026-06-02T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FB0", status: "active" },
    { index: 6, runId: "01ARZ3NDEKTSV4RRFFQ69G5FB2", downpipeId: "dp_abstain", time: "2026-06-03T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FB1", status: "active" },
    { index: 7, runId: "01ARZ3NDEKTSV4RRFFQ69G5FC0", downpipeId: "dp_preview", time: "2026-06-01T00:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
    { index: 8, runId: "01ARZ3NDEKTSV4RRFFQ69G5FC1", downpipeId: "dp_preview", time: "2026-06-02T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FC0", status: "active" },
    { index: 9, runId: "01ARZ3NDEKTSV4RRFFQ69G5FX0", downpipeId: "dp_x", time: "2026-06-01T00:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
    { index: 10, runId: "01ARZ3NDEKTSV4RRFFQ69G5FX1", downpipeId: "dp_x", time: "2026-06-02T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FX0", status: "active" },
    { index: 11, runId: "01ARZ3NDEKTSV4RRFFQ69G5FX2", downpipeId: "dp_x", time: "2026-06-03T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FX1", status: "active" },
    { index: 12, runId: "01ARZ3NDEKTSV4RRFFQ69G5FX3", downpipeId: "dp_x", time: "2026-06-04T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FX2", status: "active" },
    { index: 13, runId: "01ARZ3NDEKTSV4RRFFQ69G5FY0", downpipeId: "dp_leak", time: "2026-06-01T00:00:00.000Z", recordCount: 1, prevRunId: null, status: "active" },
    { index: 14, runId: "01ARZ3NDEKTSV4RRFFQ69G5FY1", downpipeId: "dp_leak", time: "2026-06-02T00:00:00.000Z", recordCount: 1, prevRunId: "01ARZ3NDEKTSV4RRFFQ69G5FY0", status: "active" },
  ]);

  // ============================================================================================
  // 1. CANDIDATE: the current retained/superseded split + non-secret capsules for every run in it.
  // ============================================================================================
  const cand = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/candidate", { downpipeId: "dp_green" });
  ok("candidate returns 200", cand.status === 200);
  ok("candidate retains the newest run only (keepRuns:1)", Array.isArray(cand.json.retainedRunIds) && (cand.json.retainedRunIds as string[]).length === 1 && (cand.json.retainedRunIds as string[])[0] === "01ARZ3NDEKTSV4RRFFQ69G5FA2");
  ok("candidate supersedes the other two", Array.isArray(cand.json.supersededRunIds) && (cand.json.supersededRunIds as string[]).length === 2);
  ok("candidate echoes the downpipe's OWN stored enforce (true), never a client claim", (cand.json.policy as { enforce?: boolean } | undefined)?.enforce === true);
  ok("candidate serves a capsule for every candidate run (3)", Array.isArray(cand.json.capsules) && (cand.json.capsules as unknown[]).length === 3);
  ok("candidate route is refused for a caller with NO capabilities (the restore.verify floor is real)", (await call(baseEnv(), scheduler, callerNoCaps, "POST", "/retention-prune/candidate", { downpipeId: "dp_green" })).status === 403);
  ok("candidate 404s on an unknown downpipe id", (await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/candidate", { downpipeId: "no-such-dp" })).status === 404);

  // ============================================================================================
  // 2. CAPABILITY FLOOR: apply is refused for operator (drill.run, but NOT restore.apply) -- proves the
  // route sits ABOVE the drill.run floor, never below it.
  // ============================================================================================
  const opDenied = await call(baseEnv(), scheduler, callerOperator, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: [] });
  ok("apply is refused 403 for a drill.run-only caller (operator) -- restore.apply is the real floor", opDenied.status === 403);
  ok("nothing was touched by the denied attempt (run 1's tree still present)", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FA0/root.manifest.json")) !== null);

  const greenBatch = [
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FA0", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FA1", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FA2", masterB64: b64urlEncode(master) },
  ];

  // ============================================================================================
  // 3. DUAL CONTROL: a single identity plus step-up is NOT enough to
  // actually delete, even with a correct, complete batch and enforce already on.
  // ============================================================================================
  // 3a. Apply with NO approval at all is refused "not-approved" (403), and nothing is touched.
  const noApproval = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch });
  ok("apply with no prune approval at all is refused 403 (not-approved)", noApproval.status === 403 && noApproval.json.mode === "not-approved" && noApproval.json.error === "prune not approved");
  // downpipeId MUST ride on a "not-approved" 403, same as every other mode: the console's PruneApplyResult
  // requires it as a non-optional field (isPruneApplyResult), and the notApprovedPanel it renders (the
  // dual-control UI) reads it back to raise the follow-on approval request. Omitted once, caught only by a
  // console-side type mismatch rather than here -- pinned so it cannot regress silently.
  ok("no-approval refusal's body carries downpipeId (the console's PruneApplyResult needs it)", noApproval.json.downpipeId === "dp_green");
  ok("no-approval refusal deleted nothing (run 1's tree still present)", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FA0/root.manifest.json")) !== null);

  // 3b. The bare-token break-glass (no stable subject) can neither raise nor approve a request.
  const tokenReq = await call(baseEnv(), scheduler, callerToken, "POST", "/retention-prune/request", { downpipeId: "dp_green", reason: "token cannot request" });
  ok("the bare-token caller cannot raise a prune request (no stable subject)", tokenReq.status >= 400);

  // 3c. A self-approval (same subject requests and approves) is refused even for an Owner.
  const selfReq = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/request", { downpipeId: "dp_green", reason: "self-approval attempt" });
  ok("a real request is raised (200, carries a planHash)", selfReq.status === 200 && typeof selfReq.json.planHash === "string" && (selfReq.json.planHash as string).startsWith("sha384:"));
  const selfReqPlanHash = String(selfReq.json.planHash);
  const selfApprove = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/approve", { planHash: selfReqPlanHash });
  ok("SELF-APPROVAL is refused even for the same Owner (maker != checker on the STABLE subject)", selfApprove.status >= 400);
  const selfApplyAttempt = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch });
  ok("a self-approval attempt leaves the plan UNAPPROVED, so apply still refuses", selfApplyAttempt.status === 403 && selfApplyAttempt.json.mode === "not-approved");
  ok("the refused self-approval attempt deleted nothing", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FA0/root.manifest.json")) !== null);

  // 3c-2. The SAME human, requesting under one IdP-bound subject and approving under a SECOND,
  // sharing one verified email, is refused too -- the subject-only check above would have missed this
  // (the subjects genuinely differ). This closes a same-email dual-control bypass, proven here end to end
  // through the real router + DO.
  const sameEmailReq = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/request", { downpipeId: "dp_green", reason: "same-email bypass attempt" });
  ok("a real request is raised for the same-email case (200, carries a planHash)", sameEmailReq.status === 200 && typeof sameEmailReq.json.planHash === "string");
  const sameEmailPlanHash = String(sameEmailReq.json.planHash);
  const sameEmailApprove = await call(baseEnv(), scheduler, callerOwnerSameEmail, "POST", "/retention-prune/approve", { planHash: sameEmailPlanHash });
  ok("same email, DIFFERENT subject is STILL refused as a self-approval", sameEmailApprove.status >= 400);
  const sameEmailApplyAttempt = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch });
  ok("the same-email approval attempt leaves the plan UNAPPROVED, so apply still refuses", sameEmailApplyAttempt.status === 403 && sameEmailApplyAttempt.json.mode === "not-approved");
  ok("the refused same-email attempt deleted nothing", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FA0/root.manifest.json")) !== null);
  // Control: a genuinely distinct human (different email AND different subject) CAN still approve the SAME
  // request -- proving the fix did not also break legitimate dual control.
  const sameEmailRealApprove = await call(baseEnv(), scheduler, callerOwner2, "POST", "/retention-prune/approve", { planHash: sameEmailPlanHash });
  ok("CONTROL: a genuinely distinct approver still approves the same request (200)", sameEmailRealApprove.status === 200);
  // Reject it (rather than leaving it approved/dangling) so the subsequent GREEN section's own
  // request+approve flow is unaffected by this one.
  const sameEmailCleanup = await call(baseEnv(), scheduler, callerOwner2, "POST", "/retention-prune/reject", { planHash: sameEmailPlanHash, rejectReason: "policy" });
  ok("cleanup: the now-approved test record is rejected so it does not linger", sameEmailCleanup.status === 200);

  // 3d. Reject: a distinct approver may refuse a request outright; apply then still refuses (no approval).
  const rejectReq = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/request", { downpipeId: "dp_green", reason: "will be rejected" });
  const rejectPlanHash = String(rejectReq.json.planHash);
  const rejectResp = await call(baseEnv(), scheduler, callerOwner2, "POST", "/retention-prune/reject", { planHash: rejectPlanHash, rejectReason: "policy" });
  ok("a distinct approver may REJECT a pending prune request", rejectResp.status === 200);
  const afterRejectApply = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch });
  ok("apply after a REJECT is still refused (not-approved)", afterRejectApply.status === 403 && afterRejectApply.json.mode === "not-approved");

  // 3e. The approvals inbox lists the pending/rejected records for an Approver.
  const inbox = await call(baseEnv(), scheduler, callerOwner2, "GET", "/retention-prune/approvals");
  ok("GET /retention-prune/approvals returns 200 for an Approver", inbox.status === 200 && Array.isArray(inbox.json));

  // ============================================================================================
  // 4. GREEN: request -> a DISTINCT approver approves -> the CORRECT, COMPLETE batch actually applies,
  // exactly matching the plan, and the SHARED segment (still referenced by the retained run) survives.
  // ============================================================================================
  const preview = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch, previewOnly: true });
  ok("previewOnly:true reports the plan without deleting and needs NO approval", preview.status === 200 && preview.json.mode === "preview" && preview.json.supersededRuns === 2);
  ok("previewOnly:true really deleted nothing (run 1's tree still present)", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FA0/root.manifest.json")) !== null);
  ok("a previewOnly rehearsal of an ENFORCED downpipe records NO pass record (no sidecar row)", (await readLastPrune(scheduler)) === undefined);

  await requestAndApprove(baseEnv(), scheduler, "dp_green", callerOwner, callerOwner2, "quarterly cleanup");
  const applied = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch });
  ok("the correct, complete, APPROVED batch APPLIES (mode applied)", applied.status === 200 && applied.json.mode === "applied");
  ok("applied superseded exactly 2 runs", applied.json.supersededRuns === 2);
  ok("applied deleted run 1's run-tree", applied.json.runTreeObjects !== undefined && (applied.json.runTreeObjects as number) > 0);
  ok("applied deleted at least run 1's unique orphan segment", (applied.json.orphanSegs as number) >= 1);
  ok("run 1's run-tree is actually gone from the destination", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FA0/root.manifest.json")) === null);
  ok("run 3 (retained)'s run-tree survives", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FA2/root.manifest.json")) !== null);
  {
    // the attended apply posts the SAME pass-record shape the cron posts (the caller drift this
    // build closes), scoped to the one downpipe, and the DO folds it into the destination's sidecar row.
    const lp = await readLastPrune(scheduler);
    ok("the applied attended prune folded into the destination sidecar (lastOutcome applied)", lp?.lastOutcome.outcome === "applied");
    ok("lastApplied carries the COMMITTED reclaim (objects) + superseded count", lp?.lastApplied !== undefined && lp.lastApplied.reclaimed === (applied.json.runTreeObjects as number) + (applied.json.orphanSegs as number) && lp.lastApplied.supersededRuns === 2);
    ok("the attended record never supersedes the latest CRON pass slot (retention-state stays null)", (await readRetentionSlot(scheduler)) === null);
  }

  // A second apply attempt reusing the SAME (now-consumed, single-use) approval is refused again -- single
  // use is proven, not merely claimed.
  const reuseAttempt = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch });
  ok("re-using a CONSUMED approval is refused (single-use dual control)", reuseAttempt.status === 403 && reuseAttempt.json.mode === "not-approved");
  // A FRESH request+approve for the NEW (post-apply) plan -- now supersedes nothing -- reaches a genuine
  // idempotent no-op, and releases its approval rather than leaving it dangling.
  await requestAndApprove(baseEnv(), scheduler, "dp_green", callerOwner, callerOwner2, "confirm nothing left to prune");
  const noop = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_green", batch: greenBatch });
  ok("a second apply over the same downpipe (fresh approval, unchanged plan) is an idempotent no-op", noop.status === 200 && noop.json.mode === "no-op");
  {
    const lp = await readLastPrune(scheduler);
    ok("the no-op advances lastOutcome without erasing lastApplied (the two-halves invariant)", lp?.lastOutcome.outcome === "no-op" && lp?.lastApplied?.supersededRuns === 2);
  }

  // ============================================================================================
  // 5. RED -- THE REFUSAL ACTUALLY HOLDS: an INCOMPLETE batch (a
  // SUPERSEDED run's master OMITTED, even though it is NOT the retained run) refuses the WHOLE call
  // BEFORE planPrune ever runs; NOTHING is deleted, not even the runs whose masters WERE supplied. This
  // closes the empirically-proven exploit: the OLD behaviour would ABSTAIN only when a RETAINED run
  // could not open, and would silently EXCLUDE an unopenable SUPERSEDED run while still deleting a
  // segment it shared with a sibling superseded run that DID open -- deleting live data out from under
  // a still-"active" manifest. No approval needed for these: coverage is checked before dual control.
  // ============================================================================================
  const incompleteBatch = [
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FB0", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FB1", masterB64: b64urlEncode(master) },
    // 01ARZ3NDEKTSV4RRFFQ69G5FB2 (the RETAINED run) is deliberately OMITTED.
  ];
  const incomplete = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_abstain", batch: incompleteBatch });
  ok("an incomplete batch is refused OUTRIGHT (mode incomplete-batch), never a guessed delete", incomplete.status === 200 && incomplete.json.mode === "incomplete-batch");
  ok("the refusal NAMES the run(s) that could not be opened", Array.isArray(incomplete.json.missingRunIds) && (incomplete.json.missingRunIds as string[]).includes("01ARZ3NDEKTSV4RRFFQ69G5FB2"));
  ok("incomplete-batch deleted NOTHING at all: run FB0's run-tree (which WAS in the batch) still survives", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FB0/root.manifest.json")) !== null);
  ok("incomplete-batch deleted NOTHING: run FB1's run-tree still survives", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FB1/root.manifest.json")) !== null);
  ok("the incomplete-batch response reports COUNTS from the split, not from an applied plan", incomplete.json.supersededRuns === 2 && incomplete.json.retainedRuns === 1);
  {
    // Read the RUNLOG back directly and PARSE it (never a raw-text guess): both FB0 and FB1 must still
    // read "active" (planPrune never ran, so supersedeRunlog never touched them) -- the real proof
    // "nothing superseded" means what it says.
    const runlogRaw = await r2.get("_RECOVERY/RUNLOG");
    const runlogBytes = runlogRaw ? new Uint8Array(await runlogRaw.arrayBuffer()) : new Uint8Array(0);
    const runlogEntries = parseRunlog(runlogBytes);
    const fb0 = runlogEntries.find((e) => e.runId === "01ARZ3NDEKTSV4RRFFQ69G5FB0");
    ok("incomplete-batch left FB0's RUNLOG entry active (nothing superseded, planPrune never ran)", fb0?.status === "active");
  }
  ok("a refused (incomplete-batch) call records no pass outcome (sidecar unchanged, still no-op)", (await readLastPrune(scheduler))?.lastOutcome.outcome === "no-op");

  // Same refusal, a DIFFERENT deliberate break: a structurally-valid but WRONG (foreign) master for the
  // retained run, instead of omitting it. openRunWithMaster's key-commitment check fails it closed, which
  // the coverage precheck treats identically to an unreadable run -- the SAME refusal, never a false "it
  // opened fine".
  const wrongBatch = [
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FB0", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FB1", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FB2", masterB64: b64urlEncode(wrongMaster) },
  ];
  const wrongResult = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_abstain", batch: wrongBatch });
  ok("a WRONG (foreign) master for the retained run ALSO refuses outright, never opens under it", wrongResult.status === 200 && wrongResult.json.mode === "incomplete-batch");
  ok("the wrong-master refusal names the run it could not open", Array.isArray(wrongResult.json.missingRunIds) && (wrongResult.json.missingRunIds as string[]).includes("01ARZ3NDEKTSV4RRFFQ69G5FB2"));
  ok("the wrong-master refusal also deleted nothing", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FB0/root.manifest.json")) !== null);

  // ============================================================================================
  // 6. THE ADVERSARIAL REVIEW'S EXACT FOUR-RUN SHARED-SEGMENT FIXTURE (dp_x), proven BOTH ways.
  // ============================================================================================
  // 6a. RED: the EXACT exploit batch (retained FX3 + superseded FX1 openable + superseded FX0 openable,
  // superseded FX2 OMITTED even though it is not the retained run) is refused outright, never deletes.
  const exploitBatch = [
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FX3", masterB64: b64urlEncode(master) }, // retained
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FX1", masterB64: b64urlEncode(master) }, // superseded, openable, shares FX2's segment
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FX0", masterB64: b64urlEncode(master) }, // superseded, openable, unique
    // FX2 (superseded, shares FX1's segment) deliberately OMITTED -- the exact reviewer reproduction.
  ];
  const exploitResult = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_x", batch: exploitBatch });
  ok("the reviewer's exact exploit batch is refused (incomplete-batch), the shared segment is NEVER touched", exploitResult.status === 200 && exploitResult.json.mode === "incomplete-batch");
  ok("the refusal names FX2 (the omitted superseded run sharing FX1's segment)", Array.isArray(exploitResult.json.missingRunIds) && (exploitResult.json.missingRunIds as string[]).includes("01ARZ3NDEKTSV4RRFFQ69G5FX2"));
  ok("FX2's run-tree survives (still active, still consistent with its RUNLOG entry)", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FX2/root.manifest.json")) !== null);
  // Read FX2 back with its correct master: it must still open AND every segment it references must still
  // be present -- the exact property the reviewer's repro disproved before this fix.
  {
    const verifier = verifierFrom(await loadSigner(signerPrivateB64));
    const store = { get: async (k: string) => { const r = await r2.get(k); if (!r) throw new Error(`missing ${k}`); return new Uint8Array(await r.arrayBuffer()); } };
    const run = await openRunWithMaster(store, "01ARZ3NDEKTSV4RRFFQ69G5FX2", master, verifier, { verifyFreshness: false, allowStale: true });
    const segRefs: string[] = [];
    for (const rec of run.records) for (const seg of rec.segments) segRefs.push(seg.object);
    run.dispose();
    let allPresent = true;
    for (const s of segRefs) if (!(await r2.get(s))) allPresent = false;
    ok("FX2 opens with its correct master and EVERY segment it references is still present (the exploit is closed)", allPresent && segRefs.length > 0);
  }

  // 6b. GREEN: the COMPLETE batch (all four masters), approved, applies correctly -- FX0/FX1/FX2 all
  // superseded (their RUNLOG entries flip, so nothing "active" is left pointing at the deleted shared
  // segment), FX3 (retained) survives untouched.
  const completeBatch = [
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FX0", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FX1", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FX2", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FX3", masterB64: b64urlEncode(master) },
  ];
  await requestAndApprove(baseEnv(), scheduler, "dp_x", callerOwner, callerOwner2, "prune dp_x with the complete batch");
  const xApplied = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_x", batch: completeBatch });
  ok("the COMPLETE dp_x batch applies (mode applied)", xApplied.status === 200 && xApplied.json.mode === "applied");
  ok("all 3 superseded runs (FX0, FX1, FX2) are marked superseded", xApplied.json.supersededRuns === 3);
  ok("FX2's run-tree is deleted TOO (its RUNLOG entry is consistently superseded, not left dangling active)", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FX2/root.manifest.json")) === null);
  ok("FX3 (retained)'s run-tree survives", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FX3/root.manifest.json")) !== null);
  {
    const lp = await readLastPrune(scheduler);
    ok("dp_x's applied prune advances the shared destination row (lastApplied superseded 3)", lp?.lastOutcome.outcome === "applied" && lp?.lastApplied?.supersededRuns === 3);
  }

  // ============================================================================================
  // 7. NO AUTHORITY INVENTED: a downpipe whose STORED retention.enforce is absent (dry-run posture) never
  // deletes, even with a complete, correct batch, no previewOnly override, and NO approval at all (none
  // is needed, and none is possible to abuse: enforce-off can never reach the delete path).
  // ============================================================================================
  const previewBatch = [
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FC0", masterB64: b64urlEncode(master) },
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FC1", masterB64: b64urlEncode(master) },
  ];
  const enforceOff = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_preview", batch: previewBatch });
  ok("a downpipe with enforce OFF only ever previews, regardless of the request, with NO approval", enforceOff.status === 200 && enforceOff.json.mode === "preview");
  ok("enforce-off deleted nothing", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FC0/root.manifest.json")) !== null);
  {
    // enforce-off IS the cron's dry-run posture, so this attended pass records it honestly -- and it
    // must not erase the reclaim half a sibling downpipe's earlier apply put on the shared destination.
    const lp = await readLastPrune(scheduler);
    ok("an enforce-off attended pass records the honest dry-run outcome", lp?.lastOutcome.outcome === "dry-run");
    ok("the dry-run did not erase the last reclaim (lastApplied survives from dp_x's apply)", lp?.lastApplied?.supersededRuns === 3);
  }

  // ============================================================================================
  // 8. INPUT HYGIENE: a malformed master is a plain 400, and an oversized batch is refused before any work.
  // ============================================================================================
  const badB64 = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_preview", batch: [{ runId: "01ARZ3NDEKTSV4RRFFQ69G5FC0", masterB64: "not-valid-base64url!!" }] });
  ok("a malformed masterB64 is a 400, never a 500 or a silent skip", badB64.status === 400);
  const shortMaster = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_preview", batch: [{ runId: "01ARZ3NDEKTSV4RRFFQ69G5FC0", masterB64: b64urlEncode(rand(16)) }] });
  ok("a master that decodes to the wrong length (not 32 bytes) is a 400", shortMaster.status === 400);
  const oversized = { downpipeId: "dp_preview", batch: Array.from({ length: 201 }, () => ({ runId: "01ARZ3NDEKTSV4RRFFQ69G5FC0", masterB64: b64urlEncode(rand(32)) })) };
  const overResp = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", oversized);
  ok("a batch over the 200-run cap is refused 400 before any work", overResp.status === 400);

  // ============================================================================================
  // 9. RESERVATION LEAK ON THROW: a transient R2 fault INSIDE planPrune's own step
  // (listRunTree -> dest.list(), a real, reachable failure mode -- r2.ts's guarded() re-throws every
  // native R2Bucket error unchanged) must not strand the dual-control reservation "applying". Before the
  // fix, only applyPrune's own call was release-guarded; planPrune's call sat OUTSIDE any guarded region,
  // so a throw there propagated uncaught with the reservation stuck until the 30-minute
  // PRUNE_APPLY_LEASE_MS lease self-healed it, refusing an immediate honest retry of an already-approved
  // plan. Proven both ways: the throw still happens (nothing here papers over the real fault), the
  // approval reads back "approved" (not stuck "applying") immediately afterwards, and an un-poisoned
  // retry succeeds without a fresh round of dual control.
  // ============================================================================================
  const leakPlanHash = await requestAndApprove(baseEnv(), scheduler, "dp_leak", callerOwner, callerOwner2, "prove the reservation releases on a throw");
  r2.poisonPrefix = "run/01ARZ3NDEKTSV4RRFFQ69G5FY0/";
  const leakBatch = [
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FY1", masterB64: b64urlEncode(master) }, // retained
    { runId: "01ARZ3NDEKTSV4RRFFQ69G5FY0", masterB64: b64urlEncode(master) }, // superseded
  ];
  let leakThrew = false;
  try {
    await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_leak", batch: leakBatch });
  } catch {
    leakThrew = true;
  }
  ok("the poisoned dest.list() fault still propagates as a throw (the real fault is not masked)", leakThrew);
  r2.poisonPrefix = null;
  const leakInboxAfterThrow = await call(baseEnv(), scheduler, callerOwner2, "GET", "/retention-prune/approvals");
  const leakRecordAfterThrow = (leakInboxAfterThrow.json as unknown as Array<{ planHash: string; status: string }>).find((r) => r.planHash === leakPlanHash);
  ok("the reservation reads back APPROVED (not stuck applying) immediately after the throw", leakRecordAfterThrow?.status === "approved");
  const leakRetry = await call(baseEnv(), scheduler, callerOwner, "POST", "/retention-prune/apply", { downpipeId: "dp_leak", batch: leakBatch });
  ok("an IMMEDIATE retry with the SAME already-approved plan succeeds -- no 30-minute lease wait, no fresh dual control", leakRetry.status === 200 && leakRetry.json.mode === "applied");
  ok("the retry actually deleted run FY0's tree", (await r2.get("run/01ARZ3NDEKTSV4RRFFQ69G5FY0/root.manifest.json")) === null);

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nRETENTION PRUNE ROUTER VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
