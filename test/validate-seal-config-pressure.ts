// Prove the SEAL subsystem's two remaining support-pack blind spots are now RECORDED at the fault site and are
// REDACTION-SAFE (NO-CUSTODY: a closed enum, a count, a clamped int, a boolean or an operator label -- never a
// raw message, a stack, a secret, a token, a key, an endpoint, a bucket or a customer value). No network, no
// deploy, no real Durable Object platform.
//   node test/validate-seal-config-pressure.ts
//
// The two gaps this closes:
//   A failed run never named the missing PREREQUISITE. Every run of a downpipe starts failing after a
//         wrangler deploy wipes a source binding, a discovery token is rotated away, SIGNER_PRIVATE is dropped
//         or pasted wrong, or the owner narrows the discovery scope -- and the row said only "source binding
//         error" / "run failed". The engine KNEW which binding at the throw site and threw it away into a
//         message string the redaction layer (correctly) refuses to carry.
//         -> the throw sites raise a TYPED ConfigFaultError (same message, same throw, unchanged behaviour)
//            carrying a CLOSED code + the offending binding / env-var NAME taken from the CONFIG. The run path
//            classifies it by TYPE (never by reading the message) and records a "config-fault" ring entry.
//   Retry / throttle-park / RUNLOG-park / strike pressure was invisible until terminal failure: the retry
//         counters live in a closure that returns, and the ladders live in the RunSealDO doc that cleanup()
//         deletes. A run that rode out weeks of 503s before finally dying looked exactly like one that failed on
//         a clean estate, and 8 strikes with ONE cause looked exactly like 8 strikes with eight.
//         -> withRetry ticks a per-isolate meter (subsystem-labelled), the RunSealDO folds it into the run doc
//            at every persist point (so it survives an eviction) and emits ONE bounded "run-pressure" entry when
//            the run resolves -- on SUCCESS as well as failure, because the run that succeeded under pressure is
//            precisely the run-up the "backups suddenly started failing" ticket needs.
//
// PART A: every config-fault throw site is TYPED with a closed code + the binding/env-var name.
// PART B: the RunSealDO records the config fault on the REAL fault path (a run whose SIGNER_PRIVATE a
//         redeploy dropped), and the failed row it posts is byte-for-byte what it was before.
// PART C: REDACTION -- a customer secret + object key planted in the fault message reach NO recorded byte,
//         and a hostile "binding name" (a value, a URL, a token) is DROPPED by the sanitiser, never persisted.
// PART D: withRetry counts the retries it takes, attributed to a CLOSED subsystem vocabulary.
// PART E: a run that STRIKES OUT records its pressure (retries, parks, strikes, ordered strike classes).
// PART F: a run that SUCCEEDS under pressure records it too, and a clean run records NOTHING.
// PART G: the sustained-throttle give-up names WHO throttled, and the swallowed resume-probe flap is
//         counted instead of vanishing.
// PART H  both: everything the ring persists survives sanitiseSealFault (the scheduler DO's own chokepoint) as
//         closed enums / clamped ints only, and drifted members are dropped rather than coerced.

import { RunSealDO } from "../src/seal/runstate.ts";
import { zeroCounts } from "../src/seal/checkpoint.ts";
import { MAX_SLICE_FAILURES } from "../src/seal/runstate-helpers.ts";
import { buildAdapter } from "../src/seal/adapters.ts";
import { CONFIG_FAULT_CODES, ConfigFaultError, configFaultOf, isConfigFaultName } from "../src/seal/config-fault.ts";
import { RETRY_SUBSYSTEMS, SEAL_ATTEMPT_CLASSES, ATTEMPT_CLASSES_MAX, dominantSubsystem, resetRetryMeter, peekRetryMeter, sealAttemptClass, throttledSubsystemOf } from "../src/seal/run-pressure.ts";
import { withRetry } from "../src/seal/retry.ts";
import { sanitiseSealFault, SEAL_FAULT_KINDS, type SealFault } from "../src/seal/seal-faults.ts";
import { resetSealFaultDropTally } from "../src/seal/seal-fault-post.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DP = "dp_prod";
const RUN = "01BX5ZZKBKACTAV9WEVGEMMVRY";

// The customer-owned values planted INSIDE every raw fault below: exactly where a raw message would leak into
// the pack if a recording site failed to coarsen. Neither may reach a recorded byte, anywhere, ever.
const SECRET = "sk-live-CUSTOMER-TOKEN-abc123";
const CUSTOMER_KEY = "kv/tenants/acme/billing-2026.json";
const DEST_FAULT = `PUT https://acct.r2.cloudflarestorage.com/prod-bucket/${CUSTOMER_KEY} failed: status 500 token=${SECRET}`;
const THROTTLE_FAULT = `PUT https://acct.r2.cloudflarestorage.com/prod-bucket/${CUSTOMER_KEY} failed: status 503 SlowDown token=${SECRET}`;

// ---- doubles ------------------------------------------------------------------------------------

function makeDOState(): { state: DurableObjectState; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
  const state = {
    storage: {
      async get(key: string): Promise<unknown> {
        return storage.get(key);
      },
      async put(a: string | Record<string, unknown>, b?: unknown): Promise<void> {
        if (typeof a === "string") storage.set(a, b);
        else for (const [k, v] of Object.entries(a)) storage.set(k, v);
      },
      async delete(key: string | string[]): Promise<boolean | number> {
        if (Array.isArray(key)) {
          let n = 0;
          for (const k of key) if (storage.delete(k)) n += 1;
          return n;
        }
        return storage.delete(key);
      },
      async deleteAll(): Promise<void> {
        storage.clear();
      },
      async list<T>(opts?: { prefix?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
        const prefix = opts?.prefix ?? "";
        let keys = [...storage.keys()].filter((k) => k.startsWith(prefix)).sort();
        if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
        const out = new Map<string, T>();
        for (const k of keys.slice(0, opts?.limit ?? keys.length)) out.set(k, storage.get(k) as T);
        return out;
      },
      async setAlarm(): Promise<void> {},
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, storage };
}

interface Call {
  path: string;
  body?: Record<string, unknown>;
}

// makeScheduler records every DO call. It is ALSO the ring: /seal-fault bodies are run through the REAL
// sanitiser (sanitiseSealFault -- the exact function the scheduler DO's recordSealFault applies before it
// persists) so this validator asserts on what would actually be STORED, never on the wire body alone.
function makeScheduler(): { stub: DurableObjectStub; calls: Call[]; ring: SealFault[] } {
  const calls: Call[] = [];
  const ring: SealFault[] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (url.pathname === "/seal-fault" && body !== undefined) {
        const f = sanitiseSealFault(body, Date.now());
        if (f !== null) ring.push(f);
      }
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: true }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls, ring };
}

function makeEnv(sched: DurableObjectStub, vars: Record<string, string> = {}): Env {
  return {
    SCHEDULER: { idFromName: () => ({}), get: () => sched } as unknown as DurableObjectNamespace,
    RUNSEAL: { idFromName: (name: string) => ({ name }), get: () => ({ fetch: async () => new Response("{}") }) } as unknown as DurableObjectNamespace,
    ...vars,
  } as unknown as Env;
}

function strandedDest(n: number): Destination {
  return { multipartAbortFailures: () => n } as unknown as Destination;
}

// A serial (sliced) RunDoc, `strikes` strikes into the hard-fault ladder.
function serialDoc(opts?: { strikes?: number; throttleParks?: number; pressure?: unknown }): Record<string, unknown> {
  return {
    config: { id: DP, name: "prod" },
    checkpoint: { downpipeId: DP, runId: RUN, runlogIndex: 7, counts: zeroCounts() },
    attempt: opts?.strikes ?? 0,
    ...(opts?.throttleParks !== undefined ? { throttleAttempt: opts.throttleParks } : {}),
    ...(opts?.pressure !== undefined ? { pressure: opts.pressure } : {}),
    destinationId: "dest_primary",
  };
}

const faultsOf = (ring: SealFault[], kind: string): SealFault[] => ring.filter((f) => f.kind === kind);
const completes = (calls: Call[]): Record<string, unknown>[] => calls.filter((c) => c.path === "/complete").map((c) => c.body ?? {});
// The whole recorded record, as JSON: nothing customer-owned may appear ANYWHERE in it.
const clean = (v: unknown): boolean => {
  const s = JSON.stringify(v);
  return !s.includes(SECRET) && !s.includes(CUSTOMER_KEY) && !s.includes("cloudflarestorage") && !s.includes("prod-bucket");
};

// ---- PART A: every config-fault throw site is typed --------------------------------------------

function partA(): void {
  console.log("\nPART A: every run-blocking config fault is TYPED with a closed code + the binding name:");
  const st = (source: Record<string, unknown>): DownpipeState => ({ config: { id: DP, name: "prod", source } } as unknown as DownpipeState);

  // The highest-impact failure mode: a wrangler deploy overwrote the bindings, so the configured source binding is gone.
  let caught: unknown;
  try {
    buildAdapter({} as Env, st({ type: "kv", binding: "KV_BILLING" }));
  } catch (e) {
    caught = e;
  }
  const missing = configFaultOf(caught);
  ok("a wiped source binding is code source-binding-missing and NAMES the binding", missing?.code === "source-binding-missing" && missing?.bindingName === "KV_BILLING");
  ok("the message and throw are UNCHANGED (the coarse row classification still sees it)", caught instanceof Error && /source binding KV_BILLING is not present in the environment/.test((caught as Error).message));

  // The confused-deputy guard: one of the engine's OWN bindings named as a source. Security-significant, and it
  // must never be indistinguishable from a typo.
  let reserved: unknown;
  try {
    buildAdapter({ SCHEDULER: {} } as unknown as Env, st({ type: "kv", binding: "SCHEDULER" }));
  } catch (e) {
    reserved = e;
  }
  ok("a reserved binding is code reserved-binding and names it", configFaultOf(reserved)?.code === "reserved-binding" && configFaultOf(reserved)?.bindingName === "SCHEDULER");

  // A secrets downpipe whose Secrets Store binding is gone.
  let sec: unknown;
  try {
    buildAdapter({} as Env, st({ type: "secrets", secrets: [{ name: "STRIPE", binding: "SECRETS_PROD" }] }));
  } catch (e) {
    sec = e;
  }
  ok("a missing secret binding is code secret-binding-missing and names it", configFaultOf(sec)?.code === "secret-binding-missing" && configFaultOf(sec)?.bindingName === "SECRETS_PROD");

  // An API-discovery source whose read-only discovery token was rotated away.
  let tok: unknown;
  try {
    buildAdapter({} as Env, st({ type: "cf-config", accountId: "acct_1" }));
  } catch (e) {
    tok = e;
  }
  ok("a rotated-away discovery token is code discovery-token-missing", configFaultOf(tok)?.code === "discovery-token-missing");
  ok("the discovery-token fault carries NO name (there is no operator label to carry)", configFaultOf(tok)?.bindingName === undefined);

  // An API-discovery source with no accountId in its stored config: the code rides, the ACCOUNT ID never does.
  // (the token resolves, so the NEXT prerequisite is the one that fails: the stored config has no accountId)
  let acct: unknown;
  try {
    buildAdapter({} as Env, st({ type: "workers" }), "cf-discovery-token");
  } catch (e) {
    acct = e;
  }
  ok("an absent accountId is code account-id-missing and carries no id", configFaultOf(acct)?.code === "account-id-missing" && configFaultOf(acct)?.bindingName === undefined);

  ok("configFaultOf classifies by TYPE: an ordinary throw is NOT a config fault", configFaultOf(new Error(DEST_FAULT)) === null);
  ok("every emitted code is a member of the CLOSED vocabulary", [caught, reserved, sec, tok, acct].every((e) => (CONFIG_FAULT_CODES as readonly string[]).includes(configFaultOf(e)?.code ?? "")));
}

// ---- PART B: the DO records it on the real fault path -------------------------------------------

async function partB(): Promise<void> {
  console.log("\nPART B: the seal DO records the config fault on the REAL run path:");
  const { stub, calls, ring } = makeScheduler();
  // SIGNER_PRIVATE absent: the exact post-redeploy state where every run of every downpipe fails at once.
  const { state, storage } = makeDOState();
  storage.set("doc", serialDoc({ strikes: MAX_SLICE_FAILURES - 1 }));
  const seal = new RunSealDO(state, makeEnv(stub));
  await (seal as unknown as { alarm(): Promise<void> }).alarm();

  const cf = faultsOf(ring, "config-fault")[0];
  ok("a dropped SIGNER_PRIVATE is recorded as config-fault / signer-missing", cf?.configCode === "signer-missing");
  ok("the record names the env var (an operator label, never its value)", cf?.bindingName === "SIGNER_PRIVATE");
  ok("the record is joinable to the failed run (downpipe id + run id)", cf?.downpipeId === DP && cf?.runId === RUN);
  ok("the run STILL fails loudly: the strike ladder resolved the row", completes(calls).length === 1 && completes(calls)[0]!.status === "failed");
  ok("config-fault is a member of the closed ring vocabulary", (SEAL_FAULT_KINDS as readonly string[]).includes("config-fault"));
}

// ---- PART C: redaction -------------------------------------------------------------------------

function partC(): void {
  console.log("\nPART C: REDACTION -- customer bytes never reach a config-fault record:");
  // A ConfigFaultError whose MESSAGE embeds the customer's secret and object key (the shape a real dest/source
  // fault carries). The recorded record must contain the code and the name and NOTHING of the message.
  const e = new ConfigFaultError("source-binding-missing", `source binding KV_BILLING is not present: ${DEST_FAULT}`, "KV_BILLING");
  const f = configFaultOf(e)!;
  ok("the classifier returns ONLY the closed code + the operator label", JSON.stringify(f) === JSON.stringify({ code: "source-binding-missing", bindingName: "KV_BILLING" }));
  ok("no byte of the planted secret / object key survives classification", clean(f));

  const rec = sanitiseSealFault({ kind: "config-fault", downpipeId: DP, runId: RUN, configCode: f.code, bindingName: f.bindingName }, 1)!;
  ok("the persisted record is clean of every planted customer value", clean(rec));

  // A hostile / drifted call site that tried to pass a VALUE as the "name": the sanitiser's operator-label gate
  // is the chokepoint, and it DROPS it. This is the property that makes the one non-enum field safe.
  const hostile = sanitiseSealFault({ kind: "config-fault", configCode: "source-binding-missing", bindingName: `token=${SECRET}` }, 1)!;
  ok("a secret smuggled into bindingName is DROPPED by the sanitiser", hostile.bindingName === undefined && clean(hostile));
  const key = sanitiseSealFault({ kind: "config-fault", configCode: "source-binding-missing", bindingName: CUSTOMER_KEY }, 1)!;
  ok("a customer object key smuggled into bindingName is DROPPED", key.bindingName === undefined && clean(key));
  const url = sanitiseSealFault({ kind: "config-fault", configCode: "env-missing", bindingName: "https://acct.r2.cloudflarestorage.com/prod-bucket" }, 1)!;
  ok("an endpoint smuggled into bindingName is DROPPED", url.bindingName === undefined && clean(url));
  ok("the ConfigFaultError constructor itself refuses a non-label name", new ConfigFaultError("env-missing", "x", `token=${SECRET}`).bindingName === undefined);
  ok("the operator-label gate accepts only bare identifiers", isConfigFaultName("KV_BILLING") && isConfigFaultName("SIGNER_PRIVATE") && !isConfigFaultName("kv/tenants/acme") && !isConfigFaultName("a b") && !isConfigFaultName("x".repeat(65)));

  const drift = sanitiseSealFault({ kind: "config-fault", configCode: "not-a-real-code" }, 1)!;
  ok("a drifted code is DROPPED, never carried as text", drift.configCode === undefined);
}

// ---- PART D: the retry meter -------------------------------------------------------------------

async function partD(): Promise<void> {
  console.log("\nPART D: withRetry counts the retries it takes, by CLOSED subsystem:");
  resetRetryMeter();
  let calls = 0;
  await withRetry(
    async () => {
      calls += 1;
      if (calls < 3) throw new Error("PUT failed: status 503 SlowDown");
      return "done";
    },
    { attempts: 5, baseMs: 0, subsystem: "destination" },
  );
  const m = peekRetryMeter();
  ok("two ridden-out 503s count as two retries", m.retries === 2);
  ok("the retries are attributed to the destination", m.bySubsystem.destination === 2);

  await withRetry(
    async () => {
      throw new Error("fetch failed");
    },
    { attempts: 2, baseMs: 0, subsystem: "source-api" },
  ).catch(() => {});
  const m2 = peekRetryMeter();
  ok("a source-side retry is attributed to the source API", m2.bySubsystem["source-api"] === 1 && m2.retries === 3);
  ok("the dominant subsystem is the one that ate the most retries", dominantSubsystem({ retries: 3, bySubsystem: m2.bySubsystem, probeFlaps: 0, attemptClasses: [] }) === "destination");

  // A fault the classifier does NOT ride out (auth) must not be counted as a retry: it fails on attempt 1.
  resetRetryMeter();
  await withRetry(
    async () => {
      throw new Error("PUT failed: status 403 AccessDenied");
    },
    { attempts: 5, baseMs: 0, subsystem: "destination" },
  ).catch(() => {});
  ok("a permanent (auth) fault is NOT counted as retry pressure", peekRetryMeter().retries === 0);
  ok("every subsystem key is a member of the CLOSED vocabulary", Object.keys(m2.bySubsystem).every((k) => (RETRY_SUBSYSTEMS as readonly string[]).includes(k)));
  resetRetryMeter();
}

// ---- PART E: a strike-out records its pressure --------------------------------------------------

async function partE(): Promise<void> {
  console.log("\nPART E: a run that STRIKES OUT records the pressure that preceded it:");
  resetRetryMeter();
  resetSealFaultDropTally();
  const { stub, calls, ring } = makeScheduler();
  const seal = new RunSealDO(makeDOState().state, makeEnv(stub));
  // Seven strikes already on the ladder, each recorded with its coarse class; this eighth strikes the run out.
  const doc = serialDoc({
    strikes: MAX_SLICE_FAILURES - 1,
    pressure: { retries: 41, bySubsystem: { destination: 39, "source-api": 2 }, probeFlaps: 3, attemptClasses: ["transient", "throttle", "transient", "destination", "destination", "destination", "destination"] },
  });
  await (seal as unknown as { handleHardFault(s: DurableObjectStub, d: unknown, m: string, dest?: Destination): Promise<void> }).handleHardFault(stub, doc, DEST_FAULT, strandedDest(0));

  const p = faultsOf(ring, "run-pressure")[0];
  ok("the terminal run emits ONE run-pressure record", faultsOf(ring, "run-pressure").length === 1);
  ok("it carries the retries the run actually spent", p?.retries === 41);
  ok("it attributes them to the closed subsystem vocabulary", p?.retriesBySubsystem?.destination === 39 && p?.retriesBySubsystem?.["source-api"] === 2);
  ok("it names the subsystem that ate the most retries", p?.throttledSubsystem === "destination");
  ok("it carries the strike count", p?.strikes === MAX_SLICE_FAILURES);
  ok("it carries the swallowed probe flaps (silent until now)", p?.probeFlaps === 3);
  ok("it carries the ordered strike causes, capped at the ladder ceiling", (p?.attemptClasses?.length ?? 0) <= ATTEMPT_CLASSES_MAX && (p?.attemptClasses ?? []).every((c) => (SEAL_ATTEMPT_CLASSES as readonly string[]).includes(c)));
  ok("it records the outcome", p?.outcome === "failed");
  ok("it is joinable to the failed run row", p?.downpipeId === DP && p?.runId === RUN && completes(calls)[0]!.status === "failed");
  ok("REDACTION: no byte of the planted secret / object key / bucket / endpoint rides", clean(p));
}

// ---- PART F: success under pressure, and silence when clean --------------------------------------

async function partF(): Promise<void> {
  console.log("\nPART F: a run that SUCCEEDS under pressure records it; a clean run records nothing:");
  resetRetryMeter();
  const { stub, ring } = makeScheduler();
  const seal = new RunSealDO(makeDOState().state, makeEnv(stub));
  const observe = (d: unknown, outcome: "ok" | "failed") => (seal as unknown as { observeRunPressure(s: DurableObjectStub, d: unknown, o: "ok" | "failed"): Promise<void> }).observeRunPressure(stub, d, outcome);

  await observe(serialDoc({ throttleParks: 22, pressure: { retries: 118, bySubsystem: { destination: 118 }, probeFlaps: 0, attemptClasses: [], throttledSubsystem: "destination" } }), "ok");
  const p = faultsOf(ring, "run-pressure")[0];
  ok("a run that rode out a long throttle and SUCCEEDED is recorded", p?.outcome === "ok" && p?.retries === 118);
  ok("its park count survives the doc cleanup that used to erase it", p?.throttleParks === 22);

  // The steady state of a healthy fleet: nothing spent, nothing recorded. The ring must stay quiet.
  const before = ring.length;
  await observe(serialDoc(), "ok");
  ok("a CLEAN run records nothing at all (the ring stays quiet on a healthy fleet)", ring.length === before);
}

// ---- PART G: throttle attribution + probe flaps ---------------------------------------------------

async function partG(): Promise<void> {
  console.log("\nPART G: the sustained-throttle give-up names WHO throttled:");
  resetRetryMeter();
  const { stub, calls, ring } = makeScheduler();
  const seal = new RunSealDO(makeDOState().state, makeEnv(stub, { DEST_THROTTLE_MAX_YIELDS: "3" }));
  const doc = serialDoc({ throttleParks: 2 }); // one park short of the ceiling: this one gives up
  await (seal as unknown as { handleThrottle(s: DurableObjectStub, d: unknown, m: string, dest?: Destination): Promise<void> }).handleThrottle(stub, doc, THROTTLE_FAULT, strandedDest(0));

  const p = faultsOf(ring, "run-pressure")[0];
  ok("the give-up row still says 'destination unavailable (sustained throttling)'", completes(calls)[0]!.error === "destination unavailable (sustained throttling)");
  ok("the pressure record names the DESTINATION as the throttling subsystem", p?.throttledSubsystem === "destination");
  ok("it carries the full park count the run waited out", p?.throttleParks === 3);
  ok("REDACTION: the throttle message's secret / key / bucket reach no recorded byte", clean(p) && clean(completes(calls)[0]));

  // The classifier reads a message ONLY to select a closed member, and returns the enum -- never the text.
  ok("a RUNLOG throttle is attributed to the scheduler", throttledSubsystemOf("RUNLOG write failed: status 503") === "scheduler");
  ok("a Cloudflare account-API throttle is attributed to the source API", throttledSubsystemOf("Cloudflare API GET /accounts failed: status 429") === "source-api");
  ok("every returned subsystem is a closed member", [THROTTLE_FAULT, "RUNLOG", "Cloudflare API"].every((m) => (RETRY_SUBSYSTEMS as readonly string[]).includes(throttledSubsystemOf(m))));
  ok("the strike classifier returns a closed member and never the text", (SEAL_ATTEMPT_CLASSES as readonly string[]).includes(sealAttemptClass(new Error(DEST_FAULT))) && clean(sealAttemptClass(new Error(DEST_FAULT))));
  ok("a config fault strikes as class `config` (a TYPE match: no message is read)", sealAttemptClass(new ConfigFaultError("source-binding-missing", DEST_FAULT, "KV_BILLING")) === "config");
}

// ---- PART H: the sanitiser is the chokepoint -----------------------------------------------------

function partH(): void {
  console.log("\nPART H: everything the ring persists is a closed enum, a clamped int or an operator label:");
  const rec = sanitiseSealFault(
    {
      kind: "run-pressure",
      downpipeId: DP,
      runId: RUN,
      outcome: "failed",
      retries: -5, // malformed: must clamp to 0 AND raise the countsMalformed sentinel
      retriesBySubsystem: { destination: 9, "not-a-subsystem": 4, [CUSTOMER_KEY]: 11 },
      throttleParks: 1e12, // over-ceiling: clamped, not a malformation
      strikes: 8,
      probeFlaps: 2,
      throttledSubsystem: "the-moon",
      attemptClasses: ["throttle", "not-a-class", CUSTOMER_KEY, "auth", "auth", "auth", "auth", "auth", "auth", "auth"],
    },
    1,
  )!;
  ok("a negative count clamps to 0 and is FLAGGED as not-a-measurement", rec.retries === 0 && rec.countsMalformed === true);
  ok("an over-ceiling count is clamped (a real measurement, not flagged as malformed)", rec.throttleParks === 1_000_000_000);
  ok("a drifted subsystem key is DROPPED from the tally", rec.retriesBySubsystem?.destination === 9 && Object.keys(rec.retriesBySubsystem ?? {}).length === 1);
  ok("a drifted throttledSubsystem is DROPPED, never coerced", rec.throttledSubsystem === undefined);
  ok("drifted attempt classes are DROPPED and the list is capped at the ladder ceiling", (rec.attemptClasses ?? []).every((c) => (SEAL_ATTEMPT_CLASSES as readonly string[]).includes(c)) && (rec.attemptClasses?.length ?? 0) <= ATTEMPT_CLASSES_MAX);
  ok("a customer object key smuggled into ANY vocabulary field reaches no recorded byte", clean(rec));
  ok("a drifted outcome is DROPPED", sanitiseSealFault({ kind: "run-pressure", outcome: "maybe" }, 1)!.outcome === undefined);
  ok("run-pressure is a member of the closed ring vocabulary", (SEAL_FAULT_KINDS as readonly string[]).includes("run-pressure"));
}

async function main(): Promise<void> {
  partA();
  await partB();
  partC();
  await partD();
  await partE();
  await partF();
  await partG();
  partH();
  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
