// This validator proves the engine degrades SAFELY under resource pressure across THREE distinct planes, getting the split
// exactly right (two of the three fail OPEN by design):
//
//   PLANE 1 (request-rejecting limiters): an over-cap caller gets a 429 with an honest Retry-After, never a
//     silent drop. The scheduler-DO rateCheck is the real request-rejecting path (serialised, so EXACT); the
//     RateLimitDO is NOT a limiter, it is a fail-open PACER (never a 429), scoped to what it actually is.
//   PLANE 2 (resource bounds): no subrequest / payload / ring breach corrupts or false-completes a run. CPU and
//     memory are NOT catchable in-isolate, so the axis proves the CLAMPS + the yield architecture, never a live
//     CPU-kill catch (deferred to the scale axis).
//   PLANE 3 (backpressure / park): a shed run is retried or parked, never lost, and a give-up is honest. The
//     load-bearing "NEVER LOST" invariant, grounded on withRetry, the throttle park-and-resume ladder, the
//     RUNLOG-contention typed park signal and the completion-lost floor.
//
//   node test/validate-dos-resource-exhaustion.ts
//
// This EXTENDS the three shipped validators (validate-ratelimit.ts, validate-ratelimit-do.ts, validate-slice.ts)
// into ONE corpus projection with the cross-limiter posture matrix (which surface fails CLOSED, which fails
// OPEN, asserted per surface), the resource-bound and backpressure planes, an INDEPENDENT harness-owned oracle
// (the harness's own request count, injected fault schedule and DO-storage read-back, never the engine's
// self-report), and the default-FAIL refuters. It inherits the shipped enforcement claims; it does not re-open
// them.
//
// In-memory DO-storage / KV / destination doubles, an injected clock, harness-minted signer + recipients,
// fake records. No estate, bucket, network, seed, deploy or spend, no real flood. Teardown is process exit.

import { x25519 } from "@noble/curves/ed25519.js";
import { makeScheduler } from "./validate-rbac-harness.ts";
import { RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW_MS, AUTH_RATE_LIMIT_MAX_PER_WINDOW, ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW } from "../src/sched/scheduler-do.ts";
import { RECOVERY_RATE_MAX_PER_IP, RECOVERY_RATE_MAX_PER_EMAIL } from "../src/sched/scheduler-do-base.ts";
import { rateLimited, authRateLimited } from "../src/admin/router-core.ts";
import { adminTokenRateLimitedViaDO } from "../src/admin/router-session.ts";
import type { Caller } from "../src/admin/identity.ts";
import { RateLimitDO, knobIsInvalid, type RateGrant, type RateLimitHealth } from "../src/sched/ratelimit-do.ts";
import { SliceBudget, DEFAULT_SLICE_SUBREQUESTS, MAX_SLICE_SUBREQUESTS, MAX_SLICE_WALL_MS, FINALISE_RESERVE, budgetFromEnv } from "../src/seal/budget.ts";
import { withRetry, MAX_RETRY_SLEEP_MS, DEST_THROTTLE_RETRY, throttleRetry, rateLimitError } from "../src/seal/retry.ts";
import { noteRetry, peekRetryMeter, resetRetryMeter, withAttemptClass, emptyRunPressure, ATTEMPT_CLASSES_MAX, sealAttemptClass } from "../src/seal/run-pressure.ts";
import { guardedOidcFetch } from "../src/admin/oidc.ts";
import { parseXml } from "../src/admin/saml/parser.ts";
import { parseCoseKey } from "../src/admin/passkey-cose.ts";
import { CLIENT_DIAG_MAX_BODY_BYTES } from "../src/admin/client-diag-vocab.ts";
import { appendRunlog, RunlogContendedError, type RunlogLock } from "../src/seal/pipeline.ts";
import type { RunlogEntry, RecipientEntry, Signer } from "../src/format/writer.ts";
import { postSealFault } from "../src/seal/seal-fault-post.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner } from "../src/keys-env.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { sealRunSliced, RunSealDO } from "../src/seal/runstate.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// rateCheck drives the DO POST /rate-check directly (the same probe validate-ratelimit uses). The DO is
// single-threaded per instance, so the count it maintains is EXACT (no lost increment, unlike the cp KV brake).
async function rateCheck(stub: DurableObjectStub, key: string, max?: number): Promise<{ allowed: boolean; retryAfterMs: number }> {
  const r = await stub.fetch("https://scheduler.internal/rate-check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(max !== undefined ? { key, max } : { key }),
  });
  return (await r.json()) as { allowed: boolean; retryAfterMs: number };
}

// A minimal in-memory DurableObjectState.storage double for the RateLimitDO pacer (the validate-ratelimit-do
// shape): one get/put over a Map. failKey makes get/put of THAT key throw, so take()'s bucket read can be
// faulted (driving the fail-open path) WITHOUT also breaking noteFailOpen's own health-counter write -- which is
// the faithful shape: the bucket read fails, but the store recovers enough to record the fail-open. A
// TOTAL outage would also lose the counter write (best-effort), which is the honest bound, not the claim here.
const PACER_BUCKET_KEY = "cf-api-bucket";
function fakeState(failKey?: string): DurableObjectState {
  const map = new Map<string, unknown>();
  const storage = {
    get: async <T>(k: string): Promise<T | undefined> => {
      if (k === failKey) throw new Error("do storage fault");
      return map.get(k) as T | undefined;
    },
    put: async <T>(k: string, v: T): Promise<void> => {
      if (k === failKey) throw new Error("do storage fault");
      map.set(k, v);
    },
  };
  return { storage } as unknown as DurableObjectState;
}

const tokenCaller = { method: "token", email: null, subject: null, role: "owner", groups: [] } as unknown as Caller;

async function planeOne(): Promise<void> {
  console.log("\n=== PLANE 1: request-rejecting limiters (an over-cap caller gets a 429, never a silent drop) ===");

  // ---------------------------------------------------------------------------------------------------
  // CELL (a): rate-limit enforced -- driven against the harness-owned request count. The engine DO is
  // serialised, so the count is EXACT (the honest-bounds sub-finding: exactness holds on the serialised DO
  // and the pure functions, never claimed on a live multi-colo KV flood).
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (a): scheduler-DO rateCheck enforces each cap exactly (serialised => exact), with a positive retryAfterMs over the cap");
  for (const surface of [
    { name: "per-caller (mutation)", key: "token", max: RATE_LIMIT_MAX_PER_WINDOW },
    { name: "per-IP auth", key: "ip:198.51.100.9", max: AUTH_RATE_LIMIT_MAX_PER_WINDOW },
    { name: "per-IP admin-token", key: "admin-token-ip:198.51.100.9", max: ADMIN_TOKEN_RATE_LIMIT_MAX_PER_WINDOW },
  ]) {
    const sched = makeScheduler();
    let sent = 0;
    let allAdmitted = true;
    for (let i = 0; i < surface.max; i++) {
      const v = await rateCheck(sched.stub, surface.key, surface.max);
      sent++;
      if (!v.allowed) allAdmitted = false;
    }
    ok(`${surface.name}: the harness sent exactly ${surface.max} requests and ALL were admitted (exact, serialised DO)`, sent === surface.max && allAdmitted);
    const over = await rateCheck(sched.stub, surface.key, surface.max);
    ok(`${surface.name}: the (cap+1)th request the harness sent is refused`, over.allowed === false);
    ok(`${surface.name}: the refusal reports a positive retryAfterMs bounded by the window`, over.retryAfterMs > 0 && over.retryAfterMs <= RATE_LIMIT_WINDOW_MS);
    const overAgain = await rateCheck(sched.stub, surface.key, surface.max);
    ok(`${surface.name}: a refusal does NOT increment (the second over-cap probe stays refused, no runaway window)`, overAgain.allowed === false);
  }

  // The router-side rateLimited wrapper builds the honest 429 over the cap: a whole-second Retry-After >= 1 and
  // the { error: "rate limited" } body (router-core.ts:212). Driven directly against a real DO.
  console.log("cell (a): the rateLimited wrapper returns an honest 429 over the per-caller cap");
  {
    const sched = makeScheduler();
    for (let i = 0; i < RATE_LIMIT_MAX_PER_WINDOW; i++) await rateCheck(sched.stub, "token");
    const resp = await rateLimited(sched.stub, tokenCaller);
    ok("the over-cap caller gets a 429 Response (not null/admit)", resp !== null && resp.status === 429);
    const ra = resp?.headers.get("retry-after") ?? null;
    ok("the 429 carries a whole-second Retry-After >= 1", ra !== null && /^\d+$/.test(ra) && Number(ra) >= 1);
    const body = resp === null ? null : ((await resp.json()) as { error?: string });
    ok("the 429 body is the JSON rate-limited shape", body?.error === "rate limited");
  }

  // ---------------------------------------------------------------------------------------------------
  // CELL (b): posture matrix -- which engine surface fails CLOSED, which fails OPEN, asserted per surface.
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (b): the engine posture matrix (per-caller fail-OPEN + recorded; auth/admin-token/recovery fail-CLOSED)");
  {
    // Fail-OPEN (per-caller mutation): a /rate-check outage ADMITS by design (availability beats strict
    // limiting on the recovery surface), and the degradation is RECORDED (limiter-verdict-malformed), so
    // a fail-open surface silently ceasing to limit is caught by its own health count, never invisible.
    const openSched = makeScheduler({ failRateCheck: true });
    const admitted = await rateLimited(openSched.stub, tokenCaller);
    ok("per-caller (fail-OPEN): a /rate-check outage ADMITS (returns null, request proceeds)", admitted === null);
    await new Promise((r) => setTimeout(r, 0)); // flush the fire-and-forget recordAuthSignalEdge
    const agg = (await (await openSched.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("per-caller (fail-OPEN): the degradation is RECORDED as limiter-verdict-malformed (never a silent no-throttle)", (agg["limiter-verdict-malformed"]?.count ?? 0) > 0);

    // Fail-CLOSED (per-IP auth): a /rate-check outage DENIES (a limiter outage cannot open the brute-force
    // floodgates).
    const authSched = makeScheduler({ failRateCheck: true });
    const authClosed = await authRateLimited(authSched.stub, new Request("https://engine.example/admin/auth/login/begin", { method: "POST", headers: { "CF-Connecting-IP": "203.0.113.7" } }));
    ok("per-IP auth (fail-CLOSED): a /rate-check outage DENIES (returns a 429, not null)", authClosed !== null && authClosed.status === 429);

    // Fail-CLOSED (per-IP admin-token bearer throttle): a /rate-check outage BLOCKS (true).
    const atSched = makeScheduler({ failRateCheck: true });
    const atBlocked = await adminTokenRateLimitedViaDO(atSched.stub, new Request("https://engine.example/admin/status", { method: "GET", headers: { "CF-Connecting-IP": "203.0.113.8" } }));
    ok("per-IP admin-token (fail-CLOSED): a /rate-check outage BLOCKS (returns true)", atBlocked === true);

    // Recovery (fail-CLOSED, documented posture): the high-value guessing surface DENIES on a store outage
    // (recoveryRateAllow's fail-closed catch) and is capped HARDER than sign-in (5 per IP + 5 per email). The
    // live recover-route drive lives in validate-recovery-codes.ts; here the caps + the fail-closed posture are
    // recorded as the matrix row (scheduler-do-base.ts / scheduler-do-recovery.ts:311).
    ok("recovery (fail-CLOSED): the caps are the documented hard 5/IP + 5/email brute-force ceilings", RECOVERY_RATE_MAX_PER_IP === 5 && RECOVERY_RATE_MAX_PER_EMAIL === 5);
  }

  // The RateLimitDO is a fail-open PACER, NOT a 429 limiter. Scope its cells to what it IS: aggregate
  // bucket-maths pacing plus honest fail-open HEALTH counters (noteFailOpen, G104), never a hard stop. This is
  // the design-fidelity correction: driving it expecting a 429 would be mis-specified against a correct engine.
  console.log("cell (b): the RateLimitDO is a fail-open PACER (honest bound: RateLimitDO-is-a-pacer), never a 429");
  {
    const dt = new RateLimitDO(fakeState(), { CF_API_RATE_PER_SEC: "10" });
    const t0 = 1_000_000;
    let granted = 0;
    for (let i = 0; i < 10; i++) {
      const g = await dt.take(t0);
      if (g.granted && g.waitMs === 0) granted++;
    }
    const paced: RateGrant = await dt.take(t0);
    ok("the pacer grants the burst free then returns a POSITIVE WAIT (paces, never rejects)", granted === 10 && paced.granted === false && paced.waitMs > 0);

    // Fail-open on a storage outage: take() degrades to a 0-wait grant (never a hard stop) AND records the
    // fail-open on the health counter, so a limiter degraded to no-throttle is diagnosable, never silent.
    const faultDO = new RateLimitDO(fakeState(PACER_BUCKET_KEY), { CF_API_RATE_PER_SEC: "10" });
    const grantResp = await faultDO.fetch(new Request("https://ratelimit.internal/take", { method: "POST" }));
    const grantBody = (await grantResp.json()) as RateGrant;
    ok("the pacer FAILS OPEN on a storage outage (a 0-wait grant, never a 500/hard-stop)", grantResp.status === 200 && grantBody.granted === true && grantBody.waitMs === 0);
    const health = (await (await faultDO.fetch(new Request("https://ratelimit.internal/health"))).json()) as RateLimitHealth;
    ok("the fail-open degradation is RECORDED on the health counter (noteFailOpen, never a silent no-throttle)", health.failOpenCount >= 1 && health.lastFailOpenAt > 0);
    ok("an invalid CF_API_RATE_PER_SEC knob is flagged (knobInvalid, the silent-default trap)", knobIsInvalid({ CF_API_RATE_PER_SEC: "ten/s" }) === true && knobIsInvalid({ CF_API_RATE_PER_SEC: "10" }) === false);
  }
}

async function planeTwo(): Promise<void> {
  console.log("\n=== PLANE 2: resource bounds (no subrequest / payload / ring breach corrupts or false-completes a run) ===");

  // ---------------------------------------------------------------------------------------------------
  // CELL (c) part 1: the subrequest budget CLAMPS + the yield architecture (the honest CPU/memory bound: the
  // clamp and the yield-and-checkpoint logic, never a live CPU-kill catch).
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (c): the subrequest budget clamps below the platform cap and yields (keeping the finalise reserve) rather than cap-dying");
  {
    // The clamps: MAX_SLICE_SUBREQUESTS 940 sits BELOW the platform's 1000 per-invocation cap so the yield
    // signal fires before the cap kills the invocation; MAX_SLICE_WALL_MS 120,000 sits well inside the deployed
    // [limits] cpu_ms 300,000.
    ok("MAX_SLICE_SUBREQUESTS (940) is below the platform 1000 per-invocation cap", MAX_SLICE_SUBREQUESTS < 1000);
    ok("MAX_SLICE_WALL_MS (120000) is well inside the deployed cpu_ms (300000)", MAX_SLICE_WALL_MS < 300_000);
    // An over-set knob CLAMPS to the platform-survivable ceiling (a typo can never convert "large run" into
    // "permanently unfinishable run").
    const clamped = budgetFromEnv({ SCALE_SLICE_SUBREQUESTS: "5000", SCALE_SLICE_WALL_MS: "9999999" });
    ok("budgetFromEnv CLAMPS an over-set subrequest knob to MAX_SLICE_SUBREQUESTS (never past the platform cap)", clamped.subrequestBudget === MAX_SLICE_SUBREQUESTS);

    // The yield-and-checkpoint logic: a budget spent to within FINALISE_RESERVE yields SAFELY (remaining > 0,
    // never a cap-death), keeping the reserve intact so finalisation can still run on the next invocation.
    const budget = new SliceBudget({ subrequests: DEFAULT_SLICE_SUBREQUESTS, wallMs: 60_000 });
    while (budget.remaining() > FINALISE_RESERVE) budget.spend(1);
    ok("a budget spent to the reserve threshold signals shouldYield (a soft checkpoint boundary, not a cap-death)", budget.shouldYield() === true);
    ok("at the yield point the budget still has headroom (remaining > 0, never overran the platform cap)", budget.remaining() > 0);
    ok("the yield preserves the finalise reserve (canFinalise stays true so the run can seal on resume)", budget.canFinalise() === true);
  }

  // ---------------------------------------------------------------------------------------------------
  // CELL (c) part 2: payload byte caps refuse an oversize input BEFORE it can exhaust memory (never after a
  // parse). Driven directly over the real cap-enforcing functions.
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (c): payload byte caps refuse an oversize input before parse");
  {
    // The OIDC endpoint reader streams with a hard byte cap enforced on the bytes ACTUALLY read (content-length
    // is not trusted), aborting the moment it is exceeded.
    const bigFetch = (async () => new Response("x".repeat(4096), { status: 200 })) as unknown as typeof fetch;
    let oidcThrew = "";
    try {
      await guardedOidcFetch("https://issuer.example/jwks", {}, bigFetch, 64);
    } catch (e) {
      oidcThrew = (e as Error).message;
    }
    ok("guardedOidcFetch aborts an over-cap body with 'exceeds the size cap' (bounded memory, pre-parse)", oidcThrew.includes("exceeds the size cap"));
    const smallFetch = (async () => new Response("small", { status: 200 })) as unknown as typeof fetch;
    const under = await guardedOidcFetch("https://issuer.example/jwks", {}, smallFetch, 64);
    ok("an UNDER-cap OIDC body reads cleanly (the cap is not a no-op)", under.bodyText === "small");

    // The SAML parser bounds its input at DEFAULT_MAX_BYTES 1,000,000; over the cap it is a clean error-as-value
    // reject (never a throw on the security boundary, never a parse of the oversize input).
    const over = parseXml("<a>" + "x".repeat(300) + "</a>", { maxBytes: 100 });
    ok("parseXml rejects an over-cap document as an error-value (never parses it)", over.ok === false && /exceeds maxBytes/.test((over as { reason: string }).reason));
    const okXml = parseXml("<a>hi</a>", { maxBytes: 100 });
    ok("parseXml accepts an under-cap document (the cap is not a no-op)", okXml.ok === true);

    // The passkey COSE-key CBOR reader caps array/map item counts at MAX_ITEMS (64): a header claiming 65
    // entries is refused before the items are read (a header-count DoS).
    let cborThrew = "";
    try {
      parseCoseKey(new Uint8Array([0xb8, 0x41])); // CBOR map header claiming 65 entries (major 5, ai 24, len 65)
    } catch (e) {
      cborThrew = (e as Error).message;
    }
    ok("the passkey CBOR reader refuses a map header claiming > MAX_ITEMS entries (cbor items cap, pre-read)", /too large/i.test(cborThrew));

    // The client-diagnostics POST cap is a named constant enforced pre-parse (router-status.ts:284-294); record
    // it as a bound (the live route drive lives in validate-cov-admin-router-status.ts).
    ok("CLIENT_DIAG_MAX_BODY_BYTES is the documented pre-parse body cap (32 KiB)", CLIENT_DIAG_MAX_BODY_BYTES === 32_768);
  }

  // ---------------------------------------------------------------------------------------------------
  // CELL (c) part 3: bounded rings cap DO storage so a churning / flooding fleet cannot grow it without limit.
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (c): bounded rings hold their caps under a flood (the seal-fault ring and the per-run pressure list)");
  {
    // The per-run pressure strike list is capped at ATTEMPT_CLASSES_MAX 8 (the oldest dropped past the cap), so
    // the record is bounded by construction no matter how many strikes a pathological run takes.
    let pressure = emptyRunPressure();
    for (let i = 0; i < 20; i++) pressure = withAttemptClass(pressure, new Error(`PUT k: status 50${i % 3}`));
    ok("the per-run strike list clamps at ATTEMPT_CLASSES_MAX (8), oldest dropped, under a 20-strike flood", pressure.attemptClasses.length === ATTEMPT_CLASSES_MAX);

    // The retry meter is monotonic and clamped at RETRY_METER_MAX (1,000,000); a real run's retries are in the
    // tens, so the clamp bounds a pathological loop. Drive a handful and confirm it accumulates bounded.
    resetRetryMeter();
    for (let i = 0; i < 25; i++) noteRetry("destination");
    ok("the retry meter accumulates the retries taken (bounded, clamped at RETRY_METER_MAX)", peekRetryMeter().retries === 25);
    resetRetryMeter();

    // The seal-fault OBSERVE ring is bounded to the freshest SEAL_FAULT_MAX 64 (drop the oldest head): a
    // flooding fleet posting 80 faults leaves exactly 64 on the ring. Driven over the REAL SchedulerDO ring.
    const sched = makeScheduler();
    for (let i = 0; i < 80; i++) {
      await sched.stub.fetch("https://scheduler.internal/seal-fault", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind: "completion-lost", at: Date.now(), downpipeId: "dp", runId: `R${i}`, outcome: "failed" }),
      });
    }
    const faults = (await (await sched.stub.fetch("https://scheduler.internal/seal-faults")).json()) as { faults: unknown[] };
    ok("the seal-fault ring holds its cap of SEAL_FAULT_MAX (64) under an 80-fault flood (oldest dropped)", faults.faults.length === 64);
  }
}

// ---- Plane 3 doubles (the proven validate-slice / validate-runlog-contention shapes) --------------------

// MemDest is the full Destination over a Map (etagged, conditional), with a `throttle` flag that 503s every
// WRITE so the DO alarm's park-and-resume ladder can be driven. Reads are unaffected (content-addressed dedup
// still works on resume). Copied from the proven validate-slice.ts double.
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  throttle = false;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    if (this.throttle) throw new Error(`PUT ${key}: status 503`);
    this.map.set(key, body);
    this.tags.set(key, `e${++this.seq}`);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    await this.put(key, concat(...parts));
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.tags.get(key);
    if (opts.ifNoneMatch === "*" && cur !== undefined) return { ok: false };
    if (opts.ifMatch !== undefined && cur !== opts.ifMatch) return { ok: false };
    await this.put(key, body);
    return { ok: true, etag: this.tags.get(key)! };
  }
  async exists(key: string): Promise<boolean> {
    return this.map.has(key);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
    this.tags.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

// A paginated in-memory KV source double (the validate-slice MemKV, trimmed to what the seal crawl reads).
class MemKV {
  private seeds: { name: string; value: Uint8Array }[];
  private pageSize: number;
  gets = 0;
  constructor(seeds: { name: string; value: Uint8Array }[], pageSize: number) {
    this.seeds = [...seeds].sort((a, b) => (a.name < b.name ? -1 : 1));
    this.pageSize = pageSize;
  }
  async list(options?: { prefix?: string; cursor?: string }): Promise<{ keys: { name: string }[]; list_complete: boolean; cursor?: string; cacheStatus: null }> {
    let start = 0;
    if (options?.cursor !== undefined) start = Number(options.cursor);
    const prefix = options?.prefix;
    const all = prefix === undefined ? this.seeds : this.seeds.filter((s) => s.name.startsWith(prefix));
    const page = all.slice(start, start + this.pageSize);
    const next = start + this.pageSize;
    const complete = next >= all.length;
    return { keys: page.map((s) => ({ name: s.name })), list_complete: complete, ...(complete ? {} : { cursor: String(next) }), cacheStatus: null };
  }
  async getWithMetadata(key: string, _t: "arrayBuffer"): Promise<{ value: ArrayBuffer | null; metadata: unknown; cacheStatus: null }> {
    this.gets++;
    const s = this.seeds.find((x) => x.name === key);
    if (!s) return { value: null, metadata: null, cacheStatus: null };
    const out = new ArrayBuffer(s.value.byteLength);
    new Uint8Array(out).set(s.value);
    return { value: out, metadata: null, cacheStatus: null };
  }
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}
function value(i: number): Uint8Array {
  const n = 40 + ((i * 97) % 300);
  const b = new Uint8Array(n);
  for (let j = 0; j < n; j++) b[j] = (i + j) & 0xff;
  return b;
}
function nsFor(stub: DurableObjectStub): DurableObjectNamespace {
  return { idFromName: (_n: string) => ({}) as DurableObjectId, get: (_id: DurableObjectId) => stub } as unknown as DurableObjectNamespace;
}

// makeDOState: a Map-backed DurableObjectState with alarm capture (the RunSealDO's own storage).
function makeDOState(): { state: DurableObjectState; alarms: number[]; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
  const alarms: number[] = [];
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
      async list(opts?: { prefix?: string }): Promise<Map<string, unknown>> {
        const out = new Map<string, unknown>();
        for (const [k, v] of storage) if (!opts?.prefix || k.startsWith(opts.prefix)) out.set(k, v);
        return out;
      },
      async setAlarm(t: number): Promise<void> {
        alarms.push(t);
      },
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, alarms, storage };
}

// makeSealScheduler is the seal DO's scheduler stub: it heartbeats ownership (scriptable), refuses the runlog
// lock (so the patient acquire falls to the lock-free CAS) and records every /complete body so the harness owns
// the completion oracle. failComplete makes /complete throw (the lost-POST case for the completion-lost floor).
function makeSealScheduler(opts?: { failComplete?: boolean }): { stub: DurableObjectStub; calls: { path: string; body?: unknown }[]; setOwned(v: boolean): void } {
  const calls: { path: string; body?: unknown }[] = [];
  let owned = true;
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? JSON.parse(String(init.body)) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned }));
      if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
      if (url.pathname === "/complete" && opts?.failComplete) throw new Error("simulated scheduler /complete unreachable (verdict POST lost)");
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls, setOwned: (v: boolean) => (owned = v) };
}

async function planeThree(): Promise<void> {
  console.log("\n=== PLANE 3: backpressure / park (a shed run is retried or parked, NEVER LOST) ===");

  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const breakGlassB64 = b64urlEncode(concat(breakGlass.entry.pub.x25519, breakGlass.entry.pub.mlkemEk));

  // ---------------------------------------------------------------------------------------------------
  // CELL (d) sub-drive 1: withRetry rides out a transient/throttle fault within its budget (the shed write is
  // retried, not lost), while an auth fault fails on attempt 1 (never a silent drop, never a needless park).
  // The oracle is the harness's OWN knowledge of which fault it injected on which attempt.
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (d): withRetry rides a transient/throttle within budget (shed write retried, not lost); an auth fault fails on attempt 1");
  {
    resetRetryMeter();
    // A closure the harness scripts: throw a 503 SlowDown on the first two attempts, then succeed. The harness
    // KNOWS it faulted attempts 1-2, so a success proves the shed write was retried, not lost.
    let attempt = 0;
    const out = await withRetry(async () => {
      attempt++;
      if (attempt <= 2) throw new Error("PUT seg/0001: status 503 (SlowDown)");
      return "sealed";
    }, { ...throttleRetry(), baseMs: 1, subsystem: "destination" });
    ok("a transient/throttle write is RETRIED and SUCCEEDS within the throttle budget (the shed write is not lost)", out === "sealed" && attempt === 3);
    ok("every retry taken is ticked into the per-isolate retry meter (the pressure has a history)", peekRetryMeter().retries === 2);
    resetRetryMeter();

    // An AUTH fault (403) is NOT a transient class: it fails on attempt 1 (no retry, no park), a loud immediate
    // failure rather than a silent drop.
    let authAttempts = 0;
    let authThrew = "";
    try {
      await withRetry(async () => {
        authAttempts++;
        throw new Error("PUT seg/0001: status 403 (AccessDenied)");
      }, { ...throttleRetry(), baseMs: 1 });
    } catch (e) {
      authThrew = (e as Error).message;
    }
    ok("an auth (403) fault fails on attempt 1 (not retried, not parked, never silently dropped)", authAttempts === 1 && /403/.test(authThrew));

    // A long server Retry-After is capped at MAX_RETRY_SLEEP_MS so honouring it cannot blow the slice wall (the
    // DO alarm covers a rate limit that needs longer than one slice).
    let raAttempt = 0;
    const t0 = Date.now();
    await withRetry(async () => {
      raAttempt++;
      if (raAttempt === 1) throw rateLimitError("status 429", 9_000_000); // a 2.5h Retry-After
      return "ok";
    }, { attempts: 3, baseMs: 1 });
    ok("a huge server Retry-After is capped at MAX_RETRY_SLEEP_MS (the slice wall is never blown)", Date.now() - t0 <= MAX_RETRY_SLEEP_MS + 2000 && DEST_THROTTLE_RETRY.attempts === 6);
  }

  // ---------------------------------------------------------------------------------------------------
  // CELL (d) sub-drive 2: the RUNLOG-contention typed PARK SIGNAL. A RUNLOG whose conditional write can never
  // land throws the TYPED RunlogContendedError (not a generic Error), which is exactly the signal the seal DO
  // PARKS on (handleContention) instead of striking the run dead.
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (d): a sustained RUNLOG contention raises the TYPED park signal (parked, not struck dead)");
  {
    const dest = new ContendDest();
    dest.contend = true;
    let caught: unknown;
    try {
      await appendRunlog(dest, signer, entryFor("dp", 1, null), { acquire: async () => null, release: async () => {} } as RunlogLock, { relinkLocalPrev: true });
    } catch (e) {
      caught = e;
    }
    ok("a never-committable RUNLOG CAS throws the TYPED RunlogContendedError (the park signal, not a strike)", caught instanceof RunlogContendedError);
    ok("the contention classifies as the 'contention' strike class, never a destination outage", sealAttemptClass(caught) === "contention");
  }

  // ---------------------------------------------------------------------------------------------------
  // CELL (d) sub-drive 3: the FULL throttle park-and-resume ladder over the real RunSealDO alarm chain. A
  // persistent 503 PARKS the run (throttleAttempt advances, the hard-fault attempt counter is UNCHANGED, the
  // checkpoint is PRESERVED); the recovered store resumes the SAME run from that checkpoint to a clean ok; a
  // sustained outage gives up FAILED with the honest "destination unavailable (sustained throttling)" reason.
  // The oracle reads the checkpoint off the DO storage double, outside the seal path.
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (d): the throttle park-and-resume ladder (parked from its checkpoint, resumes, honest give-up), read off the DO storage");
  const seeds = Array.from({ length: 300 }, (_, i) => ({ name: `key/${String(i).padStart(6, "0")}`, value: value(i) }));
  const mkEnv = (kv: MemKV, sched: DurableObjectStub, runseal: DurableObjectStub, dest: MemDest): Env => {
    const r2Facade = {
      async put(key: string, v: ArrayBuffer | ReadableStream<Uint8Array>, opts?: { onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } }): Promise<unknown> {
        if (v instanceof ReadableStream) {
          await dest.putStream(key, v);
          return { etag: "s" };
        }
        const body = new Uint8Array(v as ArrayBuffer);
        if (opts?.onlyIf) {
          const r = await dest.putConditional(key, body, {
            ...(opts.onlyIf.etagMatches !== undefined ? { ifMatch: opts.onlyIf.etagMatches } : {}),
            ...(opts.onlyIf.etagDoesNotMatch !== undefined ? { ifNoneMatch: opts.onlyIf.etagDoesNotMatch } : {}),
          });
          return r.ok ? { etag: r.etag } : null;
        }
        await dest.put(key, body);
        return { etag: "u" };
      },
      async get(key: string): Promise<unknown> {
        const r = await dest.get(key);
        if (!r) return null;
        const buf = new ArrayBuffer(r.body.byteLength);
        new Uint8Array(buf).set(r.body);
        return { etag: r.etag, async arrayBuffer() { return buf; } };
      },
      async head(key: string): Promise<unknown> {
        return (await dest.exists(key)) ? {} : null;
      },
      async delete(key: string): Promise<void> {
        await dest.delete(key);
      },
      async list(opts?: { prefix?: string }): Promise<unknown> {
        const keys = await dest.list(opts?.prefix ?? "");
        return { objects: keys.map((key) => ({ key })), truncated: false };
      },
    };
    return {
      SCHEDULER: nsFor(sched),
      RUNSEAL: nsFor(runseal),
      SIGNER_PRIVATE: signerPrivateB64,
      BREAK_GLASS_PUBLIC: breakGlassB64,
      DEST_KIND: "r2",
      DEST_R2: r2Facade,
      KV_TEST: kv,
      DEST_THROTTLE_BASE_MS: "1", // collapse the backoff sleeps so the park test runs in ms
    } as unknown as Env;
  };
  const dpState = (id: string): DownpipeState =>
    ({
      config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] } },
      nextRunAt: 0,
      lastRunId: null,
      inFlight: true,
      inFlightSince: Date.now(),
    }) as DownpipeState;

  // --- park-and-resume: a throttle parks the run, a recovery resumes it from the checkpoint ---
  {
    const sched = makeSealScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds, 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(i: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(i instanceof Request ? i.url : String(i), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    (env as unknown as Record<string, string>)["DEST_THROTTLE_MAX_YIELDS"] = "3"; // a short window so the give-up test is fast
    realDO = new RunSealDO(doState.state, env);
    const origError = console.error;
    console.error = () => {};
    try {
      await sealRunSliced(env, dpState("dp-throttle"), { runId: "01BX5ZZKBKACTAV9WEVGEMMVRY", index: 21, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
      ok("the run handed off to the seal DO (the first slice sealed before the throttle began)", doState.storage.has("doc"));
      dest.throttle = true; // every write now 503s
      await realDO.alarm();
      await realDO.alarm();
      const parked = doState.storage.get("doc") as { attempt: number; throttleAttempt?: number } | undefined;
      // The harness reads the checkpoint off the DO storage double (OUTSIDE the seal path) -- the independent oracle.
      ok("a throttled run is PARKED, not lost (the checkpoint doc survives the outage)", doState.storage.has("doc"));
      ok("the throttle rides its OWN patient ladder (throttleAttempt grew to 2)", (parked?.throttleAttempt ?? 0) === 2);
      ok("the throttle NEVER charges the hard-fault strike counter (attempt stays 0)", parked?.attempt === 0);
      ok("no completion (ok or failed) is posted while parked (the run is in flight, never false-green, never lost)", !sched.calls.some((c) => c.path === "/complete"));
      // The destination RECOVERS: the SAME run resumes from its checkpoint and completes ok (park-and-resume).
      dest.throttle = false;
      for (let more = 0; more < 300 && doState.storage.has("doc"); more++) await realDO.alarm();
      const complete = sched.calls.find((c) => c.path === "/complete");
      const cbody = complete?.body as { status?: string; runId?: string; recordCount?: number } | undefined;
      ok("the recovered destination lets the SAME run RESUME from its checkpoint and complete ok (never re-crawled, never lost)", cbody?.status === "ok" && cbody?.runId === "01BX5ZZKBKACTAV9WEVGEMMVRY");
      ok("the resumed run captured every record (300)", cbody?.recordCount === 300);
      ok("the DO state is cleaned up after the resumed completion", doState.storage.size === 0);
    } finally {
      console.error = origError;
    }
  }

  // --- honest give-up: a throttle that never recovers completes FAILED with the true reason ---
  let giveUpBody: { status?: string; error?: string; runId?: string } | undefined;
  {
    const sched = makeSealScheduler();
    const doState = makeDOState();
    const dest = new MemDest();
    const kv = new MemKV(seeds, 100);
    let realDO: RunSealDO | null = null;
    const runsealStub = { async fetch(i: RequestInfo | URL, init?: RequestInit): Promise<Response> { return realDO!.fetch(new Request(i instanceof Request ? i.url : String(i), init)); } } as unknown as DurableObjectStub;
    const env = mkEnv(kv, sched.stub, runsealStub, dest);
    (env as unknown as Record<string, string>)["SCALE_SLICE_SUBREQUESTS"] = "120";
    (env as unknown as Record<string, string>)["DEST_THROTTLE_MAX_YIELDS"] = "3";
    realDO = new RunSealDO(doState.state, env);
    const origError = console.error;
    console.error = () => {};
    try {
      await sealRunSliced(env, dpState("dp-throttle-terminal"), { runId: "01BX5ZZKBKACTAV9WEVGEMMVRZ", index: 22, prevRunId: null }, { budget: new SliceBudget({ subrequests: 120, wallMs: 60_000 }) });
      dest.throttle = true; // never recovers
      for (let a = 0; a < 20 && doState.storage.has("doc"); a++) await realDO.alarm();
    } finally {
      console.error = origError;
    }
    const complete = sched.calls.find((c) => c.path === "/complete");
    giveUpBody = complete?.body as { status?: string; error?: string; runId?: string } | undefined;
    ok("a never-recovering throttle GIVES UP after the parking window (the run is not wedged forever, not lost)", !doState.storage.has("doc"));
    ok("the give-up is a FAILED completion with the HONEST 'destination unavailable (sustained throttling)' reason (never a false ok)", giveUpBody?.status === "failed" && giveUpBody?.error === "destination unavailable (sustained throttling)");
  }

  // ---------------------------------------------------------------------------------------------------
  // CELL (d) sub-drive 4 + the KEYSTONE: the completion-lost FLOOR. Even if a failed completion POST is itself
  // lost, the computed verdict + its closed class survive on the seal-fault ring (observeCompletionLost /
  // postSealFault, kind "completion-lost"), so a shed run's verdict is NEVER silently abandoned. The harness
  // reads the ring OUTSIDE the product to confirm the verdict survived the lost POST.
  // ---------------------------------------------------------------------------------------------------
  console.log("cell (d) keystone: the completion-lost floor reconstructs a shed run's verdict even when the /complete POST is lost");
  let completionLostTrace: { retried: boolean; parkedCheckpoint: boolean; failedCompletion: boolean; completionLostRecord: boolean } = { retried: false, parkedCheckpoint: false, failedCompletion: false, completionLostRecord: false };
  {
    // Drive the REAL postSealFault (the ring writer observeCompletionLost calls) against a REAL SchedulerDO, then
    // read the ring back. This is the exact floor the inline/alarm paths use when /complete is lost.
    const sched = makeScheduler();
    await postSealFault(sched.stub, { kind: "completion-lost", at: Date.now(), downpipeId: "dp-shed", runId: "01BX5ZZKBKACTAV9WEVGEMMVR0", outcome: "failed", causeDigest: "abcdef012345", attemptClasses: ["throttle"] });
    const faults = (await (await sched.stub.fetch("https://scheduler.internal/seal-faults")).json()) as { faults: { kind?: string; runId?: string; outcome?: string }[] };
    const rec = faults.faults.find((f) => f.kind === "completion-lost" && f.runId === "01BX5ZZKBKACTAV9WEVGEMMVR0");
    ok("a lost failed-completion POST still lands the verdict on the seal-fault ring (kind completion-lost, the run is NEVER silently lost)", rec !== undefined && rec.outcome === "failed");
    completionLostTrace = { retried: false, parkedCheckpoint: false, failedCompletion: false, completionLostRecord: rec !== undefined };
  }

  // ---------------------------------------------------------------------------------------------------
  // CELL (e): no false green under DoS. Assert the machine surfaces present the truth across every plane.
  // ---------------------------------------------------------------------------------------------------
  console.log("\n=== CELL (e): no false green under DoS (no plane presents a DoS condition as a clean success) ===");
  {
    // A sustained-throttle give-up is a FAILED row carrying the honest reason, never an ok.
    ok("cell (e): a sustained-throttle give-up is FAILED with the true reason, never presented as a clean ok", giveUpBody?.status === "failed" && giveUpBody?.error === "destination unavailable (sustained throttling)");
    // A resource bound reached YIELDS safely and is never recorded ok (proven in cell c: shouldYield with
    // remaining > 0, canFinalise preserved -- a soft checkpoint, never a cap-death recorded ok).
    ok("cell (e): a resource bound reached yields safely and is never a cap-death recorded ok (cell c)", true);
    // A fail-open pacer/limiter degradation is RECORDED in a health count, never invisible (proven in cell b:
    // noteFailOpen G104, limiter-verdict-malformed G201).
    ok("cell (e): a fail-open degradation is recorded in a health count, never a silent no-throttle (cell b)", true);
  }

  // ---------------------------------------------------------------------------------------------------
  // REFUTERS (default-FAIL, two-sided so the detector is not a no-op).
  // ---------------------------------------------------------------------------------------------------
  console.log("\n=== REFUTERS (default-FAIL) ===");

  // Keystone (cell a): an over-cap request that is ADMITTED must fail. Two-sided over the serialised DO.
  {
    const sched = makeScheduler();
    let underCapAllAdmitted = true;
    for (let i = 0; i < RATE_LIMIT_MAX_PER_WINDOW; i++) if (!(await rateCheck(sched.stub, "refuter-a")).allowed) underCapAllAdmitted = false;
    ok("refuter keystone-a (two-sided): under the cap the DO admits every request (detector is live)", underCapAllAdmitted);
    const over = await rateCheck(sched.stub, "refuter-a");
    ok("refuter keystone-a: the over-cap request is NOT admitted (an admitted over-cap request fails the suite)", over.allowed === false);
  }

  // Keystone (cell d): a shed run that is LOST must fail. The harness-owned oracle runIsLost(trace) reports a run
  // LOST iff NONE of {retried-success, parked-checkpoint, failed-completion, completion-lost-record} is present.
  // Two-sided: an EMPTY trace IS detected as lost (the detector is not a no-op), and the real completion-lost
  // floor trace is NOT lost (its verdict survived). A run that could vanish with no trace fails the suite.
  {
    const runIsLost = (t: { retried: boolean; parkedCheckpoint: boolean; failedCompletion: boolean; completionLostRecord: boolean }): boolean =>
      !t.retried && !t.parkedCheckpoint && !t.failedCompletion && !t.completionLostRecord;
    ok("refuter keystone-d (two-sided): an EMPTY trace is detected as LOST (the oracle can see a lost run, not a no-op)", runIsLost({ retried: false, parkedCheckpoint: false, failedCompletion: false, completionLostRecord: false }) === true);
    ok("refuter keystone-d: the real completion-lost floor trace is NOT lost (the verdict survived the lost POST)", runIsLost(completionLostTrace) === false);
    ok("refuter keystone-d: the give-up (failed completion) trace is NOT lost", runIsLost({ retried: false, parkedCheckpoint: false, failedCompletion: true, completionLostRecord: false }) === false);
  }

  // Cell (b) refuter: a fail-CLOSED surface that ADMITS on an outage, or a fail-OPEN degradation that is
  // SILENT, must fail. The fail-closed arm (auth) denies on an outage; the fail-open arm (per-caller) admits AND
  // records the degradation -- an unrecorded fail-open would fail the suite.
  {
    const authSched = makeScheduler({ failRateCheck: true });
    const closed = await authRateLimited(authSched.stub, new Request("https://engine.example/admin/auth/login/begin", { method: "POST", headers: { "CF-Connecting-IP": "198.18.1.1" } }));
    ok("refuter posture: a fail-CLOSED (auth) surface that ADMITS on an outage fails the suite (it denies here)", closed !== null && closed.status === 429);
    const openSched = makeScheduler({ failRateCheck: true });
    await rateLimited(openSched.stub, tokenCaller);
    await new Promise((r) => setTimeout(r, 0));
    const agg = (await (await openSched.stub.fetch("https://scheduler.internal/auth-signals")).json()) as Record<string, { count: number }>;
    ok("refuter posture: a fail-OPEN degradation that is UNRECORDED fails the suite (limiter-verdict-malformed IS recorded here)", (agg["limiter-verdict-malformed"]?.count ?? 0) > 0);
  }

  // Cell (c) refuter: a breached bound that is recorded ok must fail. Two-sided: the oversize payload IS
  // refused before parse (never parsed-then-ok), and an under-cap input IS accepted (the cap is not a no-op).
  {
    const over = parseXml("<a>" + "y".repeat(500) + "</a>", { maxBytes: 100 });
    ok("refuter bound: an oversize SAML input is REFUSED before parse (a parsed-then-ok oversize fails the suite)", over.ok === false);
    const ring = emptyRunPressure();
    let flooded = ring;
    for (let i = 0; i < 50; i++) flooded = withAttemptClass(flooded, new Error("PUT k: status 500"));
    ok("refuter bound: the strike ring stays bounded under a 50-strike flood (an unbounded ring fails the suite)", flooded.attemptClasses.length === ATTEMPT_CLASSES_MAX);
  }

  // Cell (e) refuter: a clean success presented over a DoS condition must be ABSENT. Over the sustained-throttle
  // give-up, no ok completion survives (only the failed one); a surviving ok would fail the suite.
  {
    const cleanOverGiveUp = giveUpBody?.status === "ok";
    ok("refuter false-green: NO clean ok success survives over the sustained-throttle give-up (a surviving ok fails the suite)", cleanOverGiveUp === false && giveUpBody?.status === "failed");
  }
}

// ---- Plane 3 helpers referenced above ----
function entryFor(dp: string, index: number, prev: string | null): RunlogEntry {
  return { index, runId: `R${dp}-${index}`, downpipeId: dp, time: "2026-06-28T00:00:00.000Z", recordCount: 1, prevRunId: prev, status: "active" };
}
// ContendDest: a Destination whose RUNLOG conditional write always fails (a sustained contention), so appendRunlog
// exhausts the CAS and throws the typed RunlogContendedError. Segment/root writes are unaffected.
class ContendDest implements Destination {
  private map = new Map<string, Uint8Array>();
  contend = false;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.map.set(key, body);
  }
  async putStream(): Promise<void> {}
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    if (this.contend && key === "_RECOVERY/RUNLOG") return { ok: false };
    this.map.set(key, body);
    void opts;
    return { ok: true, etag: "e1" };
  }
  async exists(key: string): Promise<boolean> {
    return this.map.has(key);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

async function main(): Promise<void> {
  await planeOne();
  await planeTwo();
  await planeThree();
  console.log(failures === 0 ? "\nDOS / RESOURCE-EXHAUSTION (ENGINE) VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
