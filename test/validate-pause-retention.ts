// validate-pause-retention: PAUSE MEANS PAUSE. The cron retention pass must not delete a PAUSED
// downpipe's data, and the pack must be able to tell "retention stood down because you paused it"
// from "retention found nothing to delete".
//
// THE RISK THIS GUARDS AGAINST. runRetentionPrunes must never select a downpipe for pruning purely on
// `s.config.retention !== undefined`; it must also honour `config.enabled`. Otherwise, with `enforce` set,
// it would keep deleting run trees on the cron's own cadence after the operator had paused the downpipe,
// and that downpipe's LAST remaining backup would become eligible the moment its window elapsed.
// `enabled: false` is called "Paused" on every console surface an operator reads, and the documented
// account exit tells a departing customer to pause every downpipe and then stop watching. Pausing must be
// at least as safe as deleting: deleting a downpipe takes it out of GET /downpipes so it is never selected
// again, and pausing must carry the same guarantee.
//
// IT IS DRIVEN, NOT READ. Every cell below calls the REAL exported cron pass, runRetentionPrunes, over a
// REAL SchedulerDO (in-memory storage), a REAL R2-shaped binding holding REAL downpipe/0.1.0 archives
// sealed by the REAL writer, with REAL keys, and then COUNTS THE OBJECTS THAT ARE GONE. Nothing here
// greps a predicate or asserts on a plan: a cell passes because bytes did or did not disappear from a
// store. No network, no estate, no deploy, no cost.
//
// THE POPULATION IS ASSERTED, because "nothing was deleted after the pause" is also true of a run with
// nothing to delete. Every paused cell is paired with an IDENTICAL fixture whose only difference is
// `enabled: true`, and that twin's deletions are counted and required to be non-zero. A pass in which
// the enabled twin deleted nothing is a FAILURE, not a quiet green: it would mean the fixture, not the
// filter, was doing the retaining.
//
// Run: node test/validate-pause-retention.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { runRetentionPrunes } from "../src/cron/retention-pass.ts";
import type { DestPruneState } from "../src/cron/retention-dest-prune.ts";
import { RETENTION_OUTCOMES, type RetentionPassRecord } from "../src/cron/retention-record.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { signRunlog, type RunlogEntry } from "../src/format/writer-runlog.ts";
import { loadSigner } from "../src/keys-env.ts";
import { runTreePrefix } from "../src/seal/prune.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import type { DownpipeState } from "../src/sched/types.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

import { MockStorage } from "./mock-storage.ts";

// ---- MockR2: the raw R2 binding surface buildDestination("r2") reads. The pass builds its OWN
// destination from env + the DO's dest config, so this is the layer the real deletes land on. ----------
class MockR2 {
  store = new Map<string, Uint8Array>();
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
    return { objects: [...this.store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })), truncated: false };
  }
}
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
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

// seedDownpipe writes ONE downpipe state into the DO exactly as the admin route would, with `enabled`
// as given. `enabled` is the ONLY field that differs between a paused fixture and its twin.
async function seedDownpipe(storage: MockStorage, id: string, enabled: boolean, retention: { keepRuns?: number; keepDays?: number; enforce?: boolean } | undefined): Promise<void> {
  const state = {
    config: { id, name: id, enabled, source: { type: "kv", binding: `SRC_${id}` }, schedule: { cadenceSeconds: 3600 }, ...(retention !== undefined ? { retention } : {}) },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: false,
  } as unknown as DownpipeState;
  await storage.put(`dp:${id}`, state);
}

// sealRun writes ONE real downpipe/0.1.0 run's objects into the store through the REAL writer.
async function sealRun(r2: MockR2, signer: Signer, recipients: RecipientEntry[], master: Uint8Array, downpipeId: string, runId: string, value: string, runlogIndex: number, prevRunId: string | null, createdAt: string): Promise<void> {
  const archive = await buildArchive({
    downpipeId,
    downpipeName: downpipeId,
    cadence: "3600s",
    runId,
    master,
    recipients,
    signer,
    records: [{ sourceType: "kv", name: "k", value: utf8(value), namespace: "ns" }],
    windowStart: createdAt,
    windowEnd: createdAt,
    createdAt,
    runlogIndex,
    prevRunId,
    skipRunlog: true,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  for (const [key, body] of archive) r2.store.set(key, body);
}

async function writeRunlog(r2: MockR2, signer: Signer, entries: RunlogEntry[]): Promise<void> {
  const sorted = [...entries].sort((a, b) => a.index - b.index);
  const { runlog, sig } = await signRunlog(sorted, signer.edPrivate, signer.mldsaSecret);
  r2.store.set("_RECOVERY/RUNLOG", runlog);
  r2.store.set("_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig)));
}

// runTreeKeys is every object physically under a run's tree, which is what the prune deletes. The
// prefix comes from the ENGINE's own runTreePrefix rather than a literal in this file, so a naming drift
// between the two can never make "the tree is gone" read true for a prune that never ran.
function runTreeKeys(r2: MockR2, runId: string): string[] {
  return [...r2.store.keys()].filter((k) => k.startsWith(runTreePrefix(runId)));
}

const RUNS = ["01ARZ3NDEKTSV4RRFFQ69G5FA0", "01ARZ3NDEKTSV4RRFFQ69G5FA1", "01ARZ3NDEKTSV4RRFFQ69G5FA2"];

// ---- the fixture ----------------------------------------------------------------------------------
// ONE downpipe carrying retention keepRuns:1 enforce:true, and THREE sealed runs, so exactly two runs
// are over the cap and their trees are eligible for deletion. `enabled` is the only knob the two arms
// of every cell differ on.
interface Rig {
  r2: MockR2;
  env: Env;
  scheduler: DurableObjectStub;
  storage: MockStorage;
  objectsBefore: number;
}

async function buildRig(downpipeId: string, enabled: boolean): Promise<Rig> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const recipients = [breakGlass.entry, op.entry];
  const master = rand(32);

  const r2 = new MockR2();
  const { storage, scheduler } = makeScheduler();
  await seedDownpipe(storage, downpipeId, enabled, { keepRuns: 1, enforce: true });

  // Runs 1 and 2 carry DISTINCT values so each owns its own content-addressed segment and is a clean
  // orphan once superseded; run 3 is the one the cap retains.
  const entries: RunlogEntry[] = [];
  const values = ["value-one", "value-two", "value-three"];
  for (let i = 0; i < 3; i++) {
    const at = `2026-06-0${i + 1}T00:00:00.000Z`;
    await sealRun(r2, signer, recipients, master, downpipeId, RUNS[i]!, values[i]!, i + 1, i === 0 ? null : RUNS[i - 1]!, at);
    entries.push({ index: i + 1, runId: RUNS[i]!, downpipeId, time: at, recordCount: 1, prevRunId: i === 0 ? null : RUNS[i - 1]!, status: "active" });
  }
  await writeRunlog(r2, signer, entries);

  const env = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
  } as unknown as Env;

  return { r2, env, scheduler, storage, objectsBefore: r2.store.size };
}

// readRecord pulls the pass record the DO persisted (GET /retention-state), which is the same body the
// support pack projects. A pass that never posted one answers null.
async function readRecord(scheduler: DurableObjectStub): Promise<RetentionPassRecord | null> {
  const r = await scheduler.fetch("https://do/retention-state", { method: "GET" });
  const j = (await r.json()) as { record?: RetentionPassRecord | null };
  return j.record ?? null;
}

// readDestPrune reads the per-destination prune sidecar row this rig's env destination folds under (the
// default slot "" -- no console destination collection is seeded), through the SAME DestStatusView join
// the console reads. undefined = no pass has recorded anything yet.
async function readDestPrune(scheduler: DurableObjectStub): Promise<DestPruneState | undefined> {
  const r = await scheduler.fetch("https://do/dest-status", { method: "GET" });
  return ((await r.json()) as { lastPrune?: DestPruneState }).lastPrune;
}

async function main(): Promise<void> {
  console.log("validate-pause-retention: PAUSE MEANS PAUSE (the cron prune stands down on a paused downpipe)\n");

  // ---- PAUSE.0 THE POPULATION. The ENABLED twin must actually delete, or every "nothing was deleted"
  // below is the fixture retaining rather than the filter. This arm is the control for all of them. ----
  console.log("PAUSE.0 the population: the ENABLED twin really does delete (else the cells below prove nothing)");
  const live = await buildRig("dp_enabled", true);
  const liveTree1Before = runTreeKeys(live.r2, RUNS[0]!).length;
  const liveTree2Before = runTreeKeys(live.r2, RUNS[1]!).length;
  ok("the fixture has run-tree objects to lose (runs 1 and 2 are both populated)", liveTree1Before > 0 && liveTree2Before > 0);
  await runRetentionPrunes(live.env, live.scheduler);
  const liveDeleted = live.objectsBefore - live.r2.store.size;
  ok(`the ENABLED downpipe's prune DELETED objects (${liveDeleted} gone of ${live.objectsBefore})`, liveDeleted > 0);
  ok("the ENABLED downpipe's over-cap run 1 tree is GONE", runTreeKeys(live.r2, RUNS[0]!).length === 0);
  ok("the ENABLED downpipe's over-cap run 2 tree is GONE", runTreeKeys(live.r2, RUNS[1]!).length === 0);
  ok("the ENABLED downpipe's retained run 3 tree SURVIVES", runTreeKeys(live.r2, RUNS[2]!).length > 0);
  const liveRec = await readRecord(live.scheduler);
  ok("the ENABLED downpipe is recorded as applied", liveRec?.downpipes.find((d) => d.id === "dp_enabled")?.outcome === "applied");
  ok("the ENABLED pass counts no paused downpipes", liveRec?.downpipesPaused === 0);
  // the cron's applied row names its destination bucket ("" = the default) and the DO folds the
  // record into the per-destination sidecar the DestinationStatus view joins.
  ok("the applied cron row carries its destination key ('' = default)", liveRec?.downpipes.find((d) => d.id === "dp_enabled")?.destKey === "");
  // The record's timestamp is epoch milliseconds and must SURVIVE sanitisation: the count clamp's 1e9
  // ceiling used to crush it to, which the sidecar would render to a customer as a date.
  ok("the pass record's timestamp survives as epoch milliseconds (not crushed by the count clamp)", (liveRec?.at ?? 0) > 1_600_000_000_000);
  {
    const dp = await readDestPrune(live.scheduler);
    ok("the cron pass folded a per-destination sidecar row (lastOutcome applied)", dp?.lastOutcome.outcome === "applied");
    ok("lastApplied counts the reclaimed objects and the 2 superseded runs", (dp?.lastApplied?.reclaimed ?? 0) > 0 && dp?.lastApplied?.supersededRuns === 2);
    ok("both sidecar halves carry the honest epoch-millisecond timestamp", (dp?.lastApplied?.at ?? 0) > 1_600_000_000_000 && (dp?.lastOutcome.at ?? 0) > 1_600_000_000_000);
  }

  // ---- PAUSE.1 THE PROPERTY. The IDENTICAL fixture, paused. Not one byte may go. -------------------
  console.log("\nPAUSE.1 a PAUSED downpipe's data is not deleted");
  const paused = await buildRig("dp_paused", false);
  ok("the paused fixture is byte-for-byte the same shape (same object count as the enabled twin)", paused.objectsBefore === live.objectsBefore);
  await runRetentionPrunes(paused.env, paused.scheduler);
  const pausedDeleted = paused.objectsBefore - paused.r2.store.size;
  ok(`the PAUSED downpipe's prune deleted NOTHING (${pausedDeleted} gone of ${paused.objectsBefore})`, pausedDeleted === 0);
  ok("the paused downpipe's over-cap run 1 tree SURVIVES", runTreeKeys(paused.r2, RUNS[0]!).length === liveTree1Before);
  ok("the paused downpipe's over-cap run 2 tree SURVIVES", runTreeKeys(paused.r2, RUNS[1]!).length === liveTree2Before);
  ok("the paused downpipe's RUNLOG is untouched (no entry marked superseded)", paused.r2.store.has("_RECOVERY/RUNLOG"));

  // ---- PAUSE.2 THE STAND-DOWN IS VISIBLE. Silence is the other half of the defect: a pack that shows
  // nothing cannot tell "you paused it" from "retention never saw it". ------------------------------
  console.log("\nPAUSE.2 the stand-down is RECORDED, not silent");
  const rec = await readRecord(paused.scheduler);
  ok("the pass POSTED a record even though it deleted nothing", rec !== null);
  ok("the record counts the paused downpipe", rec?.downpipesPaused === 1);
  ok("the record still counts it among the downpipes carrying retention", rec?.downpipesWithRetention === 1);
  const row = rec?.downpipes.find((d) => d.id === "dp_paused");
  ok("the paused downpipe has a ROW (its absence would be indistinguishable from retention never seeing it)", row !== undefined);
  ok("its outcome is the first-class `paused`", row?.outcome === "paused");
  ok("its counts are all zero (nothing planned, nothing deleted)", row?.supersededRuns === 0 && row?.runTreeObjects === 0 && row?.orphanSegs === 0);
  ok("`paused` is a member of the closed outcome vocabulary", (RETENTION_OUTCOMES as readonly string[]).includes("paused"));
  ok("the paused row still names its destination ('' = default), so the stand-down is attributable", row?.destKey === "");
  {
    const dp = await readDestPrune(paused.scheduler);
    ok("an all-paused destination folds to the honest `paused` outcome with NO reclaim half", dp?.lastOutcome.outcome === "paused" && dp?.lastApplied === undefined);
  }

  // ---- PAUSE.3 A MIXED FLEET. The paused one must not take the enabled one down with it: a filter that
  // stopped the whole pass would also pass PAUSE.1, and would be a different, quieter defect. ---------
  console.log("\nPAUSE.3 a MIXED fleet: the paused downpipe stands down and the enabled one still prunes");
  const mixed = await buildRig("dp_live", true);
  // A second downpipe in the SAME bucket, paused, carrying retention, with no runs of its own: it must
  // be stood down and recorded without stopping dp_live's prune.
  await seedDownpipe(mixed.storage, "dp_frozen", false, { keepRuns: 1, enforce: true });
  await runRetentionPrunes(mixed.env, mixed.scheduler);
  const mixedRec = await readRecord(mixed.scheduler);
  ok("the ENABLED downpipe in a mixed fleet still deleted its over-cap trees", runTreeKeys(mixed.r2, RUNS[0]!).length === 0 && runTreeKeys(mixed.r2, RUNS[1]!).length === 0);
  ok("the ENABLED downpipe's retained run still survives", runTreeKeys(mixed.r2, RUNS[2]!).length > 0);
  ok("the mixed pass records BOTH downpipes", mixedRec?.downpipes.length === 2);
  ok("the paused one is recorded `paused`", mixedRec?.downpipes.find((d) => d.id === "dp_frozen")?.outcome === "paused");
  ok("the enabled one is recorded `applied`", mixedRec?.downpipes.find((d) => d.id === "dp_live")?.outcome === "applied");
  ok("the pass counts 2 with retention and 1 paused", mixedRec?.downpipesWithRetention === 2 && mixedRec?.downpipesPaused === 1);
  {
    const dp = await readDestPrune(mixed.scheduler);
    ok("the mixed destination coarsens to the ACTING outcome (applied), never the paused sibling's", dp?.lastOutcome.outcome === "applied" && (dp?.lastApplied?.reclaimed ?? 0) > 0);
  }

  // ---- PAUSE.4 AN ABSENT `enabled` FIELD RETAINS. Every ambiguity in the prune resolves towards keeping
  // bytes, so a state record that carries no switch at all must be treated as paused, never as enabled.
  console.log("\nPAUSE.4 a state record with NO `enabled` field is treated as paused (ambiguity retains)");
  const legacy = await buildRig("dp_legacy", true);
  {
    const raw = (await legacy.storage.get("dp:dp_legacy")) as { config: Record<string, unknown> };
    delete raw.config.enabled;
    await legacy.storage.put("dp:dp_legacy", raw);
  }
  await runRetentionPrunes(legacy.env, legacy.scheduler);
  ok("a downpipe with no `enabled` field deleted nothing", legacy.objectsBefore - legacy.r2.store.size === 0);
  ok("and it is recorded `paused` rather than silently skipped", (await readRecord(legacy.scheduler))?.downpipes.find((d) => d.id === "dp_legacy")?.outcome === "paused");

  console.log(failures === 0 ? `\nPAUSE-RETENTION PASS (${checks} checks)` : `\n${failures} FAILURE(S) of ${checks} checks`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
