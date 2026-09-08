// Prove scheduled restore tests (contract section 5): the downpipe-config default + due-check +
// recency in the scheduler DO, and the end-to-end cron path (runScheduledRestoreTest) that runs the
// in-account drill, records drill-evidence, tracks lastRestoreTestAt/Ok, and emits restore-test-pass
// (info) / restore-test-fail (critical) -- never a false pass in a break-glass-only posture.
// In-memory doubles only; no network, no deploy, no cost. Run:
//   node test/validate-scheduled-tests.ts
//
// Coverage:
//  addDownpipe: restoreTestCadenceSeconds defaults to weekly (604800) when omitted; an explicit 0
//    (off) and an explicit value are respected; validateConfig bounds it.
//  restoreTestsDue: cadence-off excluded; never-tested included; older-than-cadence included;
//    within-cadence excluded.
//  completeRestoreTest: records lastRestoreTestAt/Ok; no-op for an unknown id; re-upsert preserves
//    recency.
//  runScheduledRestoreTest (the cron path, via the exported test seam):
//    - healthy archive + operational key -> ok recency, in-account evidence (pass note), a
//      restore-test-pass (info) emission, and NO write-back.
//    - tampered archive -> ok:false recency, in-account evidence (fail note), a restore-test-fail
//      (critical) emission.
//    - break-glass-only posture (no operational key) -> ok:false recency, OFFLINE-REHEARSAL evidence,
//      an INFO emission (never a false pass, never a critical false alarm).
//    - no completed run yet -> ok:false recency, in-account evidence (skip note), an INFO emission.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { HEADER_SIZE } from "../src/format/container.ts";
import { STREAM_NONCE_SIZE } from "../src/format/version.ts";
import { loadSigner } from "../src/keys-env.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { SchedulerDO, runScheduledRestoreTest } from "../src/index.ts";
import type { DownpipeConfig, DownpipeState } from "../src/sched/scheduler-do.ts";
import type { Env } from "../src/env.d.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { encodeCaller } from "../src/admin/identity.ts";
import { flipBit } from "./memdest.ts";
import { coarseRestoreTestReasonCode, destAccessReason, RESTORE_TEST_REASON_CODES, REASON_INTEGRITY, REASON_FRESHNESS, REASON_OBJECT_MISSING, REASON_DESTINATION_ACCESS, REASON_ORIGIN_REMOVED, REASON_RECOVERY_CHECK } from "../src/restore-reasons.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

// The DO is INTERNAL: production reaches it ONLY through the router, which always forwards the verified
// caller (CALLER_HEADER). These setup upserts are authorised owner actions, so forward an owner caller on
// every call. This also matters for the scheduledtest.config cadence gate (addDownpipe): an absent caller
// resolves to the viewer floor (fail-closed) and would be refused a cadence change, so a faithful test
// must forward the owner the production router would have forwarded.
const OWNER_CALLER_HEADER = encodeCaller({ method: "token", email: null, subject: null, role: "owner", groups: [] });
function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const init: RequestInit = {
    method,
    headers: {
      "x-downpipe-caller": OWNER_CALLER_HEADER,
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  };
  return dobj.fetch(new Request(url, init));
}

// asStub adapts a bare SchedulerDO into a DurableObjectStub-shaped object whose fetch accepts the
// (url, init) call form the production code uses (scheduler.fetch(doURL(...), { method, body })). The
// real platform stub builds a Request from (url, init); the bare DO's fetch only takes a Request, so
// this adapter bridges the two so runScheduledRestoreTest's internal scheduler.fetch calls reach the DO.
function asStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const req = input instanceof Request ? input : new Request(typeof input === "string" ? input : input.toString(), init);
      return dobj.fetch(req);
    },
  } as unknown as DurableObjectStub;
}

const BASE_SOURCE = { type: "kv" as const, binding: "KV_test", include: [], exclude: [] };
function makeConfig(id: string, overrides: Partial<DownpipeConfig> = {}): DownpipeConfig {
  return { id, name: `Pipe ${id}`, cadenceSeconds: 3600, enabled: true, source: BASE_SOURCE, ...overrides };
}

// makeRecipient builds a hybrid recipient + the 96-byte private identity (same idiom as validate-drill).
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// SpyDestination + R2 adapter (the same pattern validate-drill uses) so runDrill can build a
// Destination from env and we can assert the scheduled test writes nothing back.
class SpyDestination implements Destination {
  private store = new Map<string, Uint8Array>();
  readonly putLog: string[] = [];
  async get(key: string): Promise<GetResult | null> {
    const v = this.store.get(key);
    return v ? { body: v, etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.putLog.push(`put:${key}`);
    this.store.set(key, body);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const reader = body.getReader();
    const parts: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    let n = 0;
    for (const p of parts) n += p.length;
    const merged = new Uint8Array(n);
    let off = 0;
    for (const p of parts) { merged.set(p, off); off += p.length; }
    this.putLog.push(`putStream:${key}`);
    this.store.set(key, merged);
  }
  async putConditional(key: string, body: Uint8Array, _opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    this.putLog.push(`putConditional:${key}`);
    this.store.set(key, body);
    return { ok: true, etag: `"${key.length}"` };
  }
  async exists(key: string): Promise<boolean> {
    return this.store.has(key);
  }
  async delete(key: string): Promise<void> {
    this.putLog.push(`delete:${key}`);
    this.store.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.store.keys()].filter((k) => k.startsWith(prefix));
  }
  seed(archive: Map<string, Uint8Array>): void {
    for (const [k, v] of archive) this.store.set(k, v);
    this.putLog.length = 0;
  }
  tamperSegment(): void {
    let segKey: string | undefined;
    for (const k of this.store.keys()) {
      if (k.startsWith("seg/") && k.endsWith(".seg")) { segKey = k; break; }
    }
    if (!segKey) throw new Error("no segment file found");
    const bytes = this.store.get(segKey)!;
    const copy = new Uint8Array(bytes);
    // First AEAD-encrypted byte: 5-byte container header (4-byte magic + 1-byte version) then the
    // STREAM nonce (see SPEC 7.1, src/format/container.ts and src/format/version.ts).
    const PAYLOAD_START = HEADER_SIZE + STREAM_NONCE_SIZE;
    if (copy.length <= PAYLOAD_START) throw new Error("segment too short");
    flipBit(copy, PAYLOAD_START);
    this.store.set(segKey, copy);
  }
}

function makeR2Adapter(spy: SpyDestination): R2Bucket {
  return {
    async get(key: string): Promise<R2ObjectBody | null> {
      const r = await spy.get(key);
      if (!r) return null;
      const body = r.body;
      return {
        arrayBuffer: async () => {
          const out = new ArrayBuffer(body.byteLength);
          new Uint8Array(out).set(body);
          return out;
        },
        etag: `${key.length}`,
        httpEtag: `"${key.length}"`,
      } as unknown as R2ObjectBody;
    },
    async put(key: string, body: ArrayBuffer | Uint8Array | ReadableStream): Promise<R2Object | null> {
      if (body instanceof ReadableStream) await spy.putStream(key, body);
      else await spy.put(key, body instanceof Uint8Array ? body : new Uint8Array(body as ArrayBuffer));
      return null;
    },
    async head(key: string): Promise<R2Object | null> {
      return (await spy.exists(key)) ? ({ etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2Object) : null;
    },
    list: async () => ({ objects: [], truncated: false, delimitedPrefixes: [] } as unknown as R2Objects),
    delete: async () => { return; },
    // Multipart upload is not exercised by runScheduledRestoreTest; these throws are intentionally
    // out of scope and only satisfy the R2Bucket interface shape.
    createMultipartUpload: async () => { throw new Error("not implemented"); },
    resumeMultipartUpload: () => { throw new Error("not implemented"); },
  } as unknown as R2Bucket;
}

// ---- A captured-fetch harness so we can OBSERVE the restore-test emission ---------------------
// runScheduledRestoreTest routes emissions through the notification model. We configure a webhook
// channel + a global "all" rule in the DO, then stub globalThis.fetch so the webhook deliver POSTs
// into a capture array instead of the network. The webhook payload carries the event + severity +
// detail (the downpipe-event-v1 body), which is exactly the restore-test-pass/fail signal to assert.
interface CapturedPost {
  url: string;
  body: { kind?: string; event?: string; severity?: string; detail?: string };
}

async function configureWebhookCapture(stub: SchedulerDO): Promise<{ captured: CapturedPost[]; restore: () => void }> {
  const captured: CapturedPost[] = [];
  // Configure a webhook channel + a global rule selecting ALL events at info+ so every restore-test
  // emission resolves to this channel. We write the channel/rule directly via the DO's notify routes
  // with an owner caller header so the notify.config re-check passes.
  const ownerHeader = encodeCaller({ method: "token", email: null, subject: null, role: "owner", groups: [] });
  const url = "https://capture.example.au/hook";
  await stub.fetch(new Request("https://scheduler.internal/notify/channels", {
    method: "POST",
    headers: { "content-type": "application/json", "x-downpipe-caller": ownerHeader },
    body: JSON.stringify({ kind: "webhook", name: "capture", url }),
  }));
  // The first channel auto-creates a failure+stale rule; add an explicit ALL rule so info events
  // (restore-test-pass) also route. Read the channel id back to reference it.
  const channels = (await (await fetchDO(stub, "GET", "/notify/channels")).json()) as Array<{ id: string }>;
  const channelId = channels[0]!.id;
  await stub.fetch(new Request("https://scheduler.internal/notify/rules", {
    method: "POST",
    headers: { "content-type": "application/json", "x-downpipe-caller": ownerHeader },
    body: JSON.stringify({ scope: { kind: "global" }, minSeverity: "info", events: "all", channelIds: [channelId], enabled: true }),
  }));

  // Stub globalThis.fetch to capture the webhook POST. Only our capture URL is intercepted; any other
  // fetch (there should be none in this path) returns a benign 200.
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    if (u === url) {
      let body: CapturedPost["body"] = {};
      try {
        body = JSON.parse(String(init?.body ?? "{}")) as CapturedPost["body"];
      } catch { /* ignore */ }
      captured.push({ url: u, body });
      return new Response(null, { status: 200 });
    }
    return realFetch(input, init);
  }) as typeof fetch;
  return { captured, restore: () => { globalThis.fetch = realFetch; } };
}

// ---- addDownpipe: cadence default / explicit / off ----------------------------------------
async function testCadenceConfig(): Promise<void> {
  {
    const { stub } = makeScheduler();
    // Omitted -> defaults to weekly (604800).
    const dsDefault = (await (await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-def"))).json()) as DownpipeState;
    ok("config: omitted cadence defaults to weekly (604800)", dsDefault.config.restoreTestCadenceSeconds === 604800);
    // Explicit 0 -> off (respected).
    const dsOff = (await (await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-off", { restoreTestCadenceSeconds: 0 }))).json()) as DownpipeState;
    ok("config: explicit 0 is respected (off)", dsOff.config.restoreTestCadenceSeconds === 0);
    // Explicit value -> respected.
    const dsVal = (await (await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-val", { restoreTestCadenceSeconds: 86400 }))).json()) as DownpipeState;
    ok("config: explicit cadence is respected (86400)", dsVal.config.restoreTestCadenceSeconds === 86400);
    // validateConfig bounds a non-zero cadence below the floor.
    const bad = await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-bad", { restoreTestCadenceSeconds: 5 }));
    ok("config: a sub-floor non-zero cadence is rejected (400)", bad.status === 400);
    // A negative cadence is rejected.
    const neg = await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-neg", { restoreTestCadenceSeconds: -1 }));
    ok("config: a negative cadence is rejected (400)", neg.status === 400);
  }
}

// ---- restoreTestsDue selection ------------------------------------------------------------
async function testRestoreTestsDue(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    // Cadence ON, never tested, HAS a run -> due.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-never", { restoreTestCadenceSeconds: 604800 }));
    const never = storage.rawGet<DownpipeState>("dp:dp-never")!;
    never.lastRunId = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    await storage.put("dp:dp-never", never);
    // Cadence ON, never tested, NO run yet -> NOT due (nothing to drill; the first successful run
    // requests the first test, so the pre-first-backup deferral false alarm never happens).
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-never-norun", { restoreTestCadenceSeconds: 604800 }));
    // Cadence OFF -> never due.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-offdue", { restoreTestCadenceSeconds: 0 }));
    // Cadence ON, tested recently -> NOT due.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-recent", { restoreTestCadenceSeconds: 604800 }));
    const recent = storage.rawGet<DownpipeState>("dp:dp-recent")!;
    recent.lastRestoreTestAt = Date.now() - 1000; // just now
    recent.lastRunId = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    await storage.put("dp:dp-recent", recent);
    // Cadence ON, tested long ago -> due.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-stale", { restoreTestCadenceSeconds: 604800 }));
    const stale = storage.rawGet<DownpipeState>("dp:dp-stale")!;
    stale.lastRestoreTestAt = Date.now() - (604800 + 60) * 1000; // older than the cadence
    stale.lastRunId = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    await storage.put("dp:dp-stale", stale);

    const { due } = (await (await fetchDO(stub, "POST", "/restore-tests-due")).json()) as { due: DownpipeState[] };
    const ids = new Set(due.map((d) => d.config.id));
    ok("due: never-tested with a run and cadence on is due", ids.has("dp-never"));
    ok("due: never-tested with NO run is not due (first test rides the first backup)", !ids.has("dp-never-norun"));
    ok("due: cadence-off is never due", !ids.has("dp-offdue"));
    ok("due: recently-tested is not due", !ids.has("dp-recent"));
    ok("due: older-than-cadence is due", ids.has("dp-stale"));
  }
}

// ---- completeRestoreTest records recency; no-op on unknown id; re-upsert preserves recency --
async function testCompleteRestoreTest(): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-rec", { restoreTestCadenceSeconds: 604800 }));
    const when = Date.now() - 5000;
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-rec", ok: true, at: when });
    const ds = storage.rawGet<DownpipeState>("dp:dp-rec")!;
    ok("complete: lastRestoreTestAt recorded", ds.lastRestoreTestAt === when);
    ok("complete: lastRestoreTestOk recorded", ds.lastRestoreTestOk === true);

    // Unknown id is a no-op success (no throw, no row created).
    const unknown = await fetchDO(stub, "POST", "/restore-test-complete", { id: "nope", ok: true });
    ok("complete: unknown id is a 200 no-op", unknown.status === 200);
    ok("complete: unknown id created no state", storage.rawGet("dp:nope") === undefined);

    // A re-upsert (editing the config) preserves the recency rather than resetting it.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-rec", { restoreTestCadenceSeconds: 86400 }));
    const after = storage.rawGet<DownpipeState>("dp:dp-rec")!;
    ok("complete: re-upsert preserves lastRestoreTestAt", after.lastRestoreTestAt === when);
    ok("complete: re-upsert preserves lastRestoreTestOk", after.lastRestoreTestOk === true);
    ok("complete: re-upsert applies the new cadence", after.config.restoreTestCadenceSeconds === 86400);
  }

  // restore-test-tick-killed: startRestoreTest stamps the drill in-flight marker; completeRestoreTest CLEARS
  // it on ANY completion; a marker LEFT BEHIND (a start with no completion) is the tick-killed-mid-drill signal.
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-tk", { restoreTestCadenceSeconds: 604800 }));
    const startedAt = Date.now() - 60_000;
    await fetchDO(stub, "POST", "/restore-test-start", { id: "dp-tk", at: startedAt });
    ok("start: the drill in-flight marker is stamped", storage.rawGet<DownpipeState>("dp:dp-tk")!.restoreTestStartedAt === startedAt);
    // A completion CLEARS the marker (the drill finished, not tick-killed).
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-tk", ok: true, at: Date.now() });
    ok("complete clears the drill in-flight marker", storage.rawGet<DownpipeState>("dp:dp-tk")!.restoreTestStartedAt === undefined);
    // A start with NO following completion leaves the marker behind: the pack reads this as tick-killed.
    await fetchDO(stub, "POST", "/restore-test-start", { id: "dp-tk", at: startedAt });
    ok("a start with no completion leaves the marker behind (tick-killed signal)", storage.rawGet<DownpipeState>("dp:dp-tk")!.restoreTestStartedAt === startedAt);
    // Unknown id is a 200 no-op (no state created).
    const unk = await fetchDO(stub, "POST", "/restore-test-start", { id: "nope", at: Date.now() });
    ok("start: unknown id is a 200 no-op", unk.status === 200 && storage.rawGet("dp:nope") === undefined);
  }

  // The windowed deep-verify cursor (INT-1) persists across ticks so a killed tick resumes, and a
  // wrapped tick stamps lastFullPassAt; a malformed cursor is ignored.
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-dv", { restoreTestCadenceSeconds: 604800 }));
    const at1 = Date.now() - 4000;
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-dv", ok: true, at: at1, deepVerify: { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", cursor: 8, records: 20, wrapped: false } });
    const dv1 = storage.rawGet<DownpipeState>("dp:dp-dv")!.deepVerify;
    ok("deepVerify: cursor persisted (resumes next tick)", dv1?.cursor === 8 && dv1?.records === 20 && dv1?.runId === "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    ok("deepVerify: no full pass yet (lastFullPassAt absent)", dv1?.lastFullPassAt === undefined);

    // A wrapping tick advances the cursor and stamps lastFullPassAt.
    const at2 = Date.now() - 2000;
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-dv", ok: true, at: at2, deepVerify: { runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV", cursor: 0, records: 20, wrapped: true } });
    const dv2 = storage.rawGet<DownpipeState>("dp:dp-dv")!.deepVerify;
    ok("deepVerify: a wrapped tick stamps lastFullPassAt", dv2?.lastFullPassAt === at2 && dv2?.cursor === 0);

    // A malformed cursor payload is ignored (the prior cursor stands).
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-dv", ok: true, at: Date.now(), deepVerify: { runId: "", cursor: -3, records: -1, wrapped: false } });
    const dv3 = storage.rawGet<DownpipeState>("dp:dp-dv")!.deepVerify;
    ok("deepVerify: a malformed cursor is ignored (prior stands)", dv3?.cursor === 0 && dv3?.records === 20);
  }

  // The restore-subsystem OOM-risk marker (INFRA isolate-oom-restore): a completed restore test forwards the
  // drill's largest-buffered-record measurement; completeRestoreTest stamps lastRestoreOom, RE-DERIVING overSafe
  // from the two sizes (so a spoofed flag can't ride), on both a pass and a failure. A malformed/absent one is ignored.
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-oom", { restoreTestCadenceSeconds: 604800 }));
    const safe = 32 * 1024 * 1024;
    // Over the memory-safe ceiling: overSafe is re-derived TRUE (a record big enough to risk an isolate OOM).
    const atOver = Date.now() - 3000;
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-oom", ok: true, at: atOver, oom: { maxRecordBytes: 40 * 1024 * 1024, safeBytes: safe, overSafe: false /* deliberately wrong: the DO must re-derive */ } });
    const over = storage.rawGet<DownpipeState>("dp:dp-oom")!.lastRestoreOom;
    ok("oom: a large buffered record stamps lastRestoreOom with overSafe re-derived TRUE", over?.maxRecordBytes === 40 * 1024 * 1024 && over.safeBytes === safe && over.overSafe === true && over.at === atOver);
    // Under the ceiling: the marker still rides (present), overSafe re-derived FALSE.
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-oom", ok: false, at: Date.now(), oom: { maxRecordBytes: 1024, safeBytes: safe, overSafe: true /* wrong again */ } });
    const under = storage.rawGet<DownpipeState>("dp:dp-oom")!.lastRestoreOom;
    ok("oom: a small buffered record stamps the marker with overSafe re-derived FALSE (present, not risky)", under?.maxRecordBytes === 1024 && under.overSafe === false);
    // A malformed marker (zero maxRecordBytes, or a missing safeBytes) is IGNORED — the prior marker stands.
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-oom", ok: true, at: Date.now(), oom: { maxRecordBytes: 0, safeBytes: safe } });
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-oom", ok: true, at: Date.now(), oom: { maxRecordBytes: 2048 } });
    const stands = storage.rawGet<DownpipeState>("dp:dp-oom")!.lastRestoreOom;
    ok("oom: a malformed/absent-ceiling marker is ignored (the prior marker stands)", stands?.maxRecordBytes === 1024);
  }
}

// ---- scheduled-restore-fail-reason (support pack): coarse classifier + DO persistence of reason + streak
async function testRestoreTestFailReason(): Promise<void> {
  // The coarse classifier maps each producer reason to its CLOSED short code; the enriched dest-access form
  // (carrying an S3 <Code>) still maps to dest-access; a config error maps to not-configured; anything else
  // to "other". The raw reason is never propagated.
  ok("classify: integrity -> integrity", coarseRestoreTestReasonCode(REASON_INTEGRITY) === "integrity");
  ok("classify: freshness -> freshness", coarseRestoreTestReasonCode(REASON_FRESHNESS) === "freshness");
  ok("classify: object-missing", coarseRestoreTestReasonCode(REASON_OBJECT_MISSING) === "object-missing");
  ok("classify: dest-access (bare)", coarseRestoreTestReasonCode(REASON_DESTINATION_ACCESS) === "dest-access");
  ok("classify: dest-access (enriched with S3 <Code>)", coarseRestoreTestReasonCode(destAccessReason("PUT seg/0001: status 403 (AccessDenied)")) === "dest-access");
  ok("classify: origin-removed", coarseRestoreTestReasonCode(REASON_ORIGIN_REMOVED) === "origin-removed");
  ok("classify: recovery-check", coarseRestoreTestReasonCode(REASON_RECOVERY_CHECK) === "recovery-check");
  ok("classify: config error -> not-configured", coarseRestoreTestReasonCode("engine not fully configured") === "not-configured");
  ok("classify: unknown reason -> other", coarseRestoreTestReasonCode("something novel") === "other");
  ok("classify: absent -> other", coarseRestoreTestReasonCode(undefined) === "other");

  const { stub, storage } = makeScheduler();
  await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-fr", { restoreTestCadenceSeconds: 604800 }));

  // A real FAILURE (ok:false WITH a reason code) stamps the code + starts the streak at 1.
  await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-fr", ok: false, reason: "integrity", at: Date.now() });
  let ds = storage.rawGet<DownpipeState>("dp:dp-fr")!;
  ok("fail: stores the coarse reason code", ds.lastRestoreTestReason === "integrity");
  ok("fail: starts the consecutive-failure streak at 1", ds.restoreTestConsecutiveFailures === 1);

  // A second consecutive failure increments the streak + updates the latest code.
  await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-fr", ok: false, reason: "dest-access", at: Date.now() });
  ds = storage.rawGet<DownpipeState>("dp:dp-fr")!;
  ok("fail: a second failure increments the streak to 2", ds.restoreTestConsecutiveFailures === 2);
  ok("fail: the code reflects the latest failure", ds.lastRestoreTestReason === "dest-access");

  // A DEFERRAL (ok:false with NO reason: break-glass / no completed run) leaves reason + streak UNTOUCHED.
  await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-fr", ok: false, at: Date.now() });
  ds = storage.rawGet<DownpipeState>("dp:dp-fr")!;
  ok("defer: a reasonless ok:false leaves the streak untouched (neither pass nor fail evidence)", ds.restoreTestConsecutiveFailures === 2 && ds.lastRestoreTestReason === "dest-access");

  // A PASS clears the reason + resets the streak (absent = currently healthy).
  await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-fr", ok: true, at: Date.now() });
  ds = storage.rawGet<DownpipeState>("dp:dp-fr")!;
  ok("pass: clears the reason (absent = healthy)", ds.lastRestoreTestReason === undefined);
  ok("pass: resets the streak", ds.restoreTestConsecutiveFailures === undefined);

  // Once set again, the reason + streak survive a re-upsert (config edit).
  await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-fr", ok: false, reason: "freshness", at: Date.now() });
  await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-fr", { restoreTestCadenceSeconds: 86400 }));
  ds = storage.rawGet<DownpipeState>("dp:dp-fr")!;
  ok("re-upsert: preserves the reason + streak across a config edit", ds.lastRestoreTestReason === "freshness" && ds.restoreTestConsecutiveFailures === 1);
}

// ---- restorability heal: deferral kind + post-backup retest + lastRunId preservation -------
// This covers the full chain: a config edit resets lastRunId, the next scheduled test
// defers "no completed run yet" on a downpipe with a FULL archive, the deferral records
// ok:false, the console reads it as "Last test failed", and the verdict then sits for a whole cadence
// because nothing retests after the next successful backup. These vectors pin each rung.
async function testRestoreTestHeal(): Promise<void> {
  // Deferral-kind lifecycle on completeRestoreTest.
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-heal", { restoreTestCadenceSeconds: 604800 }));
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-heal", ok: false, deferred: "no-run", at: Date.now() });
    let ds = storage.rawGet<DownpipeState>("dp:dp-heal")!;
    ok("heal: a no-run deferral persists its kind", ds.lastRestoreTestDeferred === "no-run");
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-heal", ok: false, deferred: "posture", at: Date.now() });
    ds = storage.rawGet<DownpipeState>("dp:dp-heal")!;
    ok("heal: a posture deferral persists its kind", ds.lastRestoreTestDeferred === "posture");
    // A real failure is real evidence: the deferral kind is cleared (reason discriminates it).
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-heal", ok: false, reason: "integrity", at: Date.now() });
    ds = storage.rawGet<DownpipeState>("dp:dp-heal")!;
    ok("heal: a real failure clears the deferral kind", ds.lastRestoreTestDeferred === undefined);
    // A pass clears it too.
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-heal", ok: false, deferred: "no-run", at: Date.now() });
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-heal", ok: true, at: Date.now() });
    ds = storage.rawGet<DownpipeState>("dp:dp-heal")!;
    ok("heal: a pass clears the deferral kind", ds.lastRestoreTestDeferred === undefined);
    // An out-of-vocabulary kind is treated as absent (closed two-value vocabulary).
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-heal", ok: false, deferred: "weird", at: Date.now() });
    ds = storage.rawGet<DownpipeState>("dp:dp-heal")!;
    ok("heal: an unknown deferral kind is not stored", ds.lastRestoreTestDeferred === undefined);
  }

  // Post-backup retest request: a SUCCESSFUL run while the last test did not pass marks the
  // downpipe due immediately; any restore-test completion consumes the request.
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-retest", { restoreTestCadenceSeconds: 604800 }));
    // Recently "failed" (a deferral or a real failure both record ok:false), so NOT due by age.
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-retest", ok: false, deferred: "no-run", at: Date.now() - 1000 });
    let due = (await (await fetchDO(stub, "POST", "/restore-tests-due")).json()) as { due: DownpipeState[] };
    ok("heal: not due by age after the deferral", !due.due.some((d) => d.config.id === "dp-retest"));
    // A successful run lands.
    const trig = (await (await fetchDO(stub, "POST", "/trigger", { id: "dp-retest" })).json()) as { runId: string; index: number };
    await fetchDO(stub, "POST", "/complete", { id: "dp-retest", runId: trig.runId, index: trig.index });
    let ds = storage.rawGet<DownpipeState>("dp:dp-retest")!;
    ok("heal: a successful run requests a prompt retest", typeof ds.restoreTestRetestAt === "number");
    due = (await (await fetchDO(stub, "POST", "/restore-tests-due")).json()) as { due: DownpipeState[] };
    ok("heal: the retest request makes the downpipe due immediately", due.due.some((d) => d.config.id === "dp-retest"));
    // The next completion consumes the request (pass or not), so it can never loop.
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-retest", ok: true, at: Date.now() });
    ds = storage.rawGet<DownpipeState>("dp:dp-retest")!;
    ok("heal: a completion consumes the retest request", ds.restoreTestRetestAt === undefined);
    due = (await (await fetchDO(stub, "POST", "/restore-tests-due")).json()) as { due: DownpipeState[] };
    ok("heal: after the pass the downpipe is no longer due", !due.due.some((d) => d.config.id === "dp-retest"));
    // A later successful run with a PASSED last test requests nothing.
    const trig2 = (await (await fetchDO(stub, "POST", "/trigger", { id: "dp-retest" })).json()) as { runId: string; index: number };
    await fetchDO(stub, "POST", "/complete", { id: "dp-retest", runId: trig2.runId, index: trig2.index });
    ds = storage.rawGet<DownpipeState>("dp:dp-retest")!;
    ok("heal: a success after a PASSED test requests no retest", ds.restoreTestRetestAt === undefined);
  }

  // Cadence OFF: a successful run never requests a retest (scheduled testing is explicitly off).
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-off", { restoreTestCadenceSeconds: 0 }));
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-off", ok: false, deferred: "no-run", at: Date.now() });
    const trig = (await (await fetchDO(stub, "POST", "/trigger", { id: "dp-off" })).json()) as { runId: string; index: number };
    await fetchDO(stub, "POST", "/complete", { id: "dp-off", runId: trig.runId, index: trig.index });
    const ds = storage.rawGet<DownpipeState>("dp:dp-off")!;
    ok("heal: cadence-off requests no retest", ds.restoreTestRetestAt === undefined);
  }

  // A FAILED run (the empty-runId convention) requests no retest: nothing new to drill.
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-failrun", { restoreTestCadenceSeconds: 604800 }));
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-failrun", ok: false, deferred: "no-run", at: Date.now() });
    const trig = (await (await fetchDO(stub, "POST", "/trigger", { id: "dp-failrun" })).json()) as { runId: string; index: number };
    await fetchDO(stub, "POST", "/complete", { id: "dp-failrun", runId: "", index: trig.index, status: "failed", error: "boom" });
    const ds = storage.rawGet<DownpipeState>("dp:dp-failrun")!;
    ok("heal: a failed run requests no retest", ds.restoreTestRetestAt === undefined);
  }

  // lastRunId preservation across a re-upsert: a SAME-SOURCE edit keeps the latest-run pointer (so
  // the next scheduled test drills the existing archive instead of deferring "no run yet"); a
  // SOURCE change resets it (a different resource honestly has no runs).
  {
    const { stub, storage } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-keep", { restoreTestCadenceSeconds: 604800 }));
    const trig = (await (await fetchDO(stub, "POST", "/trigger", { id: "dp-keep" })).json()) as { runId: string; index: number };
    await fetchDO(stub, "POST", "/complete", { id: "dp-keep", runId: trig.runId, index: trig.index });
    let ds = storage.rawGet<DownpipeState>("dp:dp-keep")!;
    ok("heal: the run advanced lastRunId", ds.lastRunId === trig.runId);
    // Same source, new cadence: the pointer survives.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-keep", { restoreTestCadenceSeconds: 86400 }));
    ds = storage.rawGet<DownpipeState>("dp:dp-keep")!;
    ok("heal: a same-source edit preserves lastRunId", ds.lastRunId === trig.runId);
    // Same source, disabled (the enable/disable toggle round-trips the config): survives too.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-keep", { restoreTestCadenceSeconds: 86400, enabled: false }));
    ds = storage.rawGet<DownpipeState>("dp:dp-keep")!;
    ok("heal: the enable/disable toggle preserves lastRunId", ds.lastRunId === trig.runId);
    // A DIFFERENT source resets the pointer (honest "no runs yet" for the new resource).
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-keep", { restoreTestCadenceSeconds: 86400, source: { ...BASE_SOURCE, binding: "KV_other" } }));
    ds = storage.rawGet<DownpipeState>("dp:dp-keep")!;
    ok("heal: a source change resets lastRunId", ds.lastRunId === null);
  }
}

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

// Fixture carries the signed archive + the signer/operational keys the four E2E drill paths reuse.
interface Fixture {
  archive: Map<string, Uint8Array>;
  signerPrivateB64: string;
  operationalPrivateB64: string;
}

// buildArchiveFixture seals a small KV archive once for the end-to-end drill paths.
async function buildArchiveFixture(): Promise<Fixture> {
  const signerSeed = rand(64);
  const signerPrivateB64 = b64urlEncode(signerSeed);
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);
  const records = [
    { sourceType: "kv", name: "key:a", value: utf8("value-a"), namespace: "ns" },
    { sourceType: "kv", name: "key:b", value: utf8("value-b-longer"), namespace: "ns" },
  ];
  const archive = await buildArchive({
    downpipeId: "dp-test", downpipeName: "scheduled-test", cadence: "3600s", runId: RUN_ID,
    master: rand(32), recipients: [breakGlass.entry, op.entry], signer, records,
    windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  return { archive, signerPrivateB64, operationalPrivateB64 };
}

// ---- E2E: healthy archive + operational key -> PASS (info) + ok recency + evidence + no write ----
async function testE2ePass({ archive, signerPrivateB64, operationalPrivateB64 }: Fixture): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const { captured, restore } = await configureWebhookCapture(stub);
    const spy = new SpyDestination();
    spy.seed(archive);
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2", DEST_R2: makeR2Adapter(spy),
      SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64,
    } as unknown as Env;
    // The downpipe must have a lastRunId so the test has a run to read back.
    await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-test", { restoreTestCadenceSeconds: 604800 }));
    const state = storage.rawGet<DownpipeState>("dp:dp-test")!;
    state.lastRunId = RUN_ID;
    await storage.put("dp:dp-test", state);

    let threw = false;
    try {
      await runScheduledRestoreTest(env, asStub(stub), storage.rawGet<DownpipeState>("dp:dp-test")!);
    } catch { threw = true; }
    ok("e2e-pass: runScheduledRestoreTest did not throw", !threw);
    ok("e2e-pass: drill wrote nothing (read-only)", spy.putLog.length === 0);

    const after = storage.rawGet<DownpipeState>("dp:dp-test")!;
    ok("e2e-pass: lastRestoreTestOk recorded true", after.lastRestoreTestOk === true);
    ok("e2e-pass: lastRestoreTestAt recorded", typeof after.lastRestoreTestAt === "number");
    ok("e2e-pass: a pass carries NO failure reason / streak (healthy)", after.lastRestoreTestReason === undefined && after.restoreTestConsecutiveFailures === undefined);

    const evidence = (await (await fetchDO(stub, "GET", "/drill-evidence")).json()) as Array<{ runId: string; kind: string; note?: string }>;
    const ev = evidence.find((e) => e.runId === "dp-test");
    ok("e2e-pass: an in-account drill-evidence row was recorded", ev !== undefined && ev.kind === "in-account");
    ok("e2e-pass: evidence note says passed", /passed/.test(ev?.note ?? ""));

    const passPost = captured.find((c) => c.body.event === "restore-test-pass");
    ok("e2e-pass: a restore-test-pass emission was delivered", passPost !== undefined);
    ok("e2e-pass: the pass emission severity is info", passPost?.body.severity === "info");
    ok("e2e-pass: no restore-test-fail was emitted", !captured.some((c) => c.body.event === "restore-test-fail"));
    restore();
  }
}

// ---- E2E: tampered archive -> FAIL (critical) + ok:false recency + evidence ----------------
async function testE2eFail({ archive, signerPrivateB64, operationalPrivateB64 }: Fixture): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const { captured, restore } = await configureWebhookCapture(stub);
    try {
      const spy = new SpyDestination();
      spy.seed(archive);
      spy.tamperSegment();
      const env = {
        SCHEDULER: {} as unknown as DurableObjectNamespace,
        DEST_KIND: "r2", DEST_R2: makeR2Adapter(spy),
        SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64,
      } as unknown as Env;
      await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-test", { restoreTestCadenceSeconds: 604800 }));
      const state = storage.rawGet<DownpipeState>("dp:dp-test")!;
      state.lastRunId = RUN_ID;
      await storage.put("dp:dp-test", state);

      await runScheduledRestoreTest(env, asStub(stub), storage.rawGet<DownpipeState>("dp:dp-test")!);

      const after = storage.rawGet<DownpipeState>("dp:dp-test")!;
      ok("e2e-fail: lastRestoreTestOk recorded false", after.lastRestoreTestOk === false);
      // The real drill failure classifies to a CLOSED coarse code (the exact code is the reader's call --
      // unit-tested in testRestoreTestFailReason); the DO persists it + starts the streak, so the pack
      // carries WHY + how-many-in-a-row days after the notify ring / evidence note rolled over.
      ok("e2e-fail: a real failure persists a CLOSED coarse reason code", typeof after.lastRestoreTestReason === "string" && (RESTORE_TEST_REASON_CODES as readonly string[]).includes(after.lastRestoreTestReason));
      ok("e2e-fail: the consecutive-failure streak is 1", after.restoreTestConsecutiveFailures === 1);
      const evidence = (await (await fetchDO(stub, "GET", "/drill-evidence")).json()) as Array<{ runId: string; kind: string; note?: string }>;
      const ev = evidence.find((e) => e.runId === "dp-test");
      ok("e2e-fail: an in-account evidence row with a failed note", ev?.kind === "in-account" && /failed/.test(ev?.note ?? ""));
      const failPost = captured.find((c) => c.body.event === "restore-test-fail");
      ok("e2e-fail: a restore-test-fail emission was delivered", failPost !== undefined);
      ok("e2e-fail: the fail emission severity is critical", failPost?.body.severity === "critical");
      ok("e2e-fail: NO false restore-test-pass was emitted", !captured.some((c) => c.body.event === "restore-test-pass"));
    } finally {
      restore();
    }
  }
}

// ---- E2E: break-glass-only posture (no operational key) -> INFO, never a false pass --------
async function testE2eBreakGlass({ archive, signerPrivateB64 }: Fixture): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const { captured, restore } = await configureWebhookCapture(stub);
    try {
      const spy = new SpyDestination();
      spy.seed(archive);
      const env = {
        SCHEDULER: {} as unknown as DurableObjectNamespace,
        DEST_KIND: "r2", DEST_R2: makeR2Adapter(spy),
        SIGNER_PRIVATE: signerPrivateB64,
        // OPERATIONAL_PRIVATE absent -> break-glass-only posture
      } as unknown as Env;
      await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-test", { restoreTestCadenceSeconds: 604800 }));
      const state = storage.rawGet<DownpipeState>("dp:dp-test")!;
      state.lastRunId = RUN_ID;
      await storage.put("dp:dp-test", state);

      await runScheduledRestoreTest(env, asStub(stub), storage.rawGet<DownpipeState>("dp:dp-test")!);

      const after = storage.rawGet<DownpipeState>("dp:dp-test")!;
      // It is NOT a pass: ok:false recency, so posture/reports show no successful in-account test.
      ok("e2e-bg: lastRestoreTestOk recorded false (NOT a false pass)", after.lastRestoreTestOk === false);
      // A break-glass DEFERRAL is neither pass nor drill-failure: it records NO failure reason / streak.
      ok("e2e-bg: a deferral records no failure reason / streak", after.lastRestoreTestReason === undefined && after.restoreTestConsecutiveFailures === undefined);
      // The deferral KIND is persisted so the console renders "rehearse offline", never "tested and failed".
      ok("e2e-bg: the posture deferral kind is persisted", after.lastRestoreTestDeferred === "posture");
      const evidence = (await (await fetchDO(stub, "GET", "/drill-evidence")).json()) as Array<{ runId: string; kind: string; note?: string }>;
      const ev = evidence.find((e) => e.runId === "dp-test");
      ok("e2e-bg: an OFFLINE-REHEARSAL evidence row was recorded", ev?.kind === "offline-rehearsal");
      ok("e2e-bg: evidence note mentions break-glass-only / offline", /break-glass-only|offline/.test(ev?.note ?? ""));
      // The emission is INFO, never critical (it is a posture, not a downpipe failure).
      const post = captured[0];
      ok("e2e-bg: an emission was delivered", post !== undefined);
      ok("e2e-bg: the emission severity is info (not critical)", post?.body.severity === "info");
      ok("e2e-bg: no restore-test-fail (critical) was emitted", !captured.some((c) => c.body.severity === "critical"));
      ok("e2e-bg: drill wrote nothing", spy.putLog.length === 0);
    } finally {
      restore();
    }
  }
}

// ---- E2E: no completed run yet -> INFO skip note, ok:false recency -------------------------
async function testE2eNoRun({ archive, signerPrivateB64, operationalPrivateB64 }: Fixture): Promise<void> {
  {
    const { stub, storage } = makeScheduler();
    const { captured, restore } = await configureWebhookCapture(stub);
    try {
      const spy = new SpyDestination();
      spy.seed(archive);
      const env = {
        SCHEDULER: {} as unknown as DurableObjectNamespace,
        DEST_KIND: "r2", DEST_R2: makeR2Adapter(spy),
        SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64,
      } as unknown as Env;
      await fetchDO(stub, "POST", "/downpipes", makeConfig("dp-norun", { restoreTestCadenceSeconds: 604800 }));
      // lastRunId is null (never ran).
      await runScheduledRestoreTest(env, asStub(stub), storage.rawGet<DownpipeState>("dp:dp-norun")!);
      const after = storage.rawGet<DownpipeState>("dp:dp-norun")!;
      ok("e2e-norun: lastRestoreTestOk recorded false", after.lastRestoreTestOk === false);
      // The deferral KIND is persisted so the console renders "not yet testable", never "tested and failed".
      ok("e2e-norun: the no-run deferral kind is persisted", after.lastRestoreTestDeferred === "no-run");
      const post = captured[0];
      ok("e2e-norun: an info emission was delivered", post?.body.severity === "info");
      ok("e2e-norun: no critical emission", !captured.some((c) => c.body.severity === "critical"));
      ok("e2e-norun: drill wrote nothing", spy.putLog.length === 0);
    } finally {
      restore();
    }
  }
}

async function main(): Promise<void> {
  await testCadenceConfig();
  await testRestoreTestsDue();
  await testCompleteRestoreTest();
  await testRestoreTestFailReason();
  await testRestoreTestHeal();
  const fx = await buildArchiveFixture();
  await testE2ePass(fx);
  await testE2eFail(fx);
  await testE2eBreakGlass(fx);
  await testE2eNoRun(fx);

  console.log(failures === 0 ? "\nSCHEDULED-RESTORE-TEST VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
