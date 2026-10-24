// Catches that degrade on purpose record a site fault, so the support pack can show that they fired.
//
// Each catch keeps its return value and its control flow: a refused body stays refused, a body that is not JSON
// still returns verbatim, a plan that cannot be hashed is still a mismatch, an unreadable prune shape still
// counts as widening, a RUNLOG that cannot be read is still unreadable or pending. What changes is that the
// fault now reaches the isolate's site-fault ledger. For each site the test drives the real function twice:
// once with no fault (the control, which must record nothing) and once with a planted fault (which must record
// one row under the site's id and keep the old return value).
//
// endpointHost (preflight-probes.ts) and bucketOf (router-runlog.ts) no longer have a catch: they test the
// endpoint with URL.canParse first. Its return values are covered by validate-preflight.ts.
//
// Run: node test/validate-site-fault-handled-sites.ts

import { KeyCeremonyFault } from "../src/admin/attach.ts";
import { readBoundedRequestText } from "../src/admin/inbound-body.ts";
import { type HandoverSummary, handOverTargets, listHandoverTargets } from "../src/admin/rekey-runlog-handover.ts";
import { alertOnImmediateDisarm } from "../src/admin/router-config-version.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
import { settleFailedRekey, withRunlogHandover } from "../src/admin/router-keys.ts";
import { routeRetentionArmedAloneAlert } from "../src/admin/router-notify.ts";
import { openContext } from "../src/admin/router-runlog.ts";
import { withholdMemberInvite } from "../src/admin/router-sources.ts";
import { ingestPullRateLimited } from "../src/admin/support-ingest.ts";
import { fetchRecoveryStatus } from "../src/admin/support-sections-recovery.ts";
import { fetchStatusBaseline } from "../src/admin/support-sections-runs.ts";
import type { SiteFaultId } from "../src/admin/site-fault-legend.ts";
import { peekSiteFaults, SITE_FAULTS_KEY, type SiteFaults } from "../src/admin/site-faults.ts";
import { drive } from "../src/cron/drive.ts";
import { loadPassKeys } from "../src/cron/retention-pass.ts";
import { reconcileAndDue } from "../src/cron/seal-loop-pass.ts";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { type RunlogEntry, type Signer, signRunlog } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { deliverOtlpPush } from "../src/notify/otlp-push-sender.ts";
import { decodeVerifier, encodeVerifier } from "../src/sched/rekey-handover.ts";
import type { SchedulerDOSurface } from "../src/sched/scheduler-do-base.ts";
import { verifiedPlan } from "../src/sched/scheduler-do-restore-approval.ts";
import { type RunlogLock, readFloor } from "../src/seal/pipeline.ts";
import { entryMatchesRoot, makeRunlogReader } from "../src/seal/replicate-runlog.ts";
import { handOverRunlog, precheckRunlog, relinkRunlogAttended } from "../src/seal/runlog-handover.ts";
import { ok, tally } from "./lib/site-fault-proof.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";
import { makeScheduler } from "./validate-scheduler-shared.ts";

const countOf = (id: SiteFaultId): number => peekSiteFaults()[id]?.count ?? 0;

// bigStream sends chunks until it is cancelled. failCancel makes its cancel reject, which is the planted fault.
function bigStream(failCancel: boolean): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    pull(c) {
      c.enqueue(new Uint8Array(64 * 1024));
    },
    cancel() {
      if (failCancel) throw new Error("cancel refused");
    },
  });
}

async function inboundBody(): Promise<void> {
  console.log("admin.inbound-body-cancel (inbound-body.ts readBoundedRequestText):");
  const id = "admin.inbound-body-cancel";
  for (const declared of [true, false]) {
    const shape = declared ? "a declared Content-Length over the cap" : "a chunked body that passes the cap";
    const req = (failCancel: boolean): Request =>
      new Request("https://e.example/admin/auth/x", { method: "POST", body: bigStream(failCancel), headers: declared ? { "content-length": String(1024 * 1024) } : {}, duplex: "half" } as RequestInit);
    const c0 = countOf(id);
    const r0 = await readBoundedRequestText(req(false), 1024);
    ok(`control, ${shape}: refused with null and nothing recorded`, r0 === null && countOf(id) === c0);
    const r1 = await readBoundedRequestText(req(true), 1024);
    ok(`${shape} whose cancel fails: still refused with null`, r1 === null);
    ok(`${shape} whose cancel fails: one row recorded`, countOf(id) === c0 + 1);
  }
}

async function otlpBody(): Promise<void> {
  console.log("notify.otlp-body-cancel (otlp-push-sender.ts readOtlpBodyCapped):");
  const id = "notify.otlp-body-cancel";
  const realFetch = globalThis.fetch;
  const dns = (input: RequestInfo | URL): Response | null =>
    String(input).startsWith("https://cloudflare-dns.com/dns-query?") ? new Response(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }), { status: 200 }) : null;
  try {
    for (const declared of [true, false]) {
      const shape = declared ? "a declared Content-Length over the cap" : "a chunked body that passes the cap";
      const push = async (failCancel: boolean) => {
        globalThis.fetch = (async (input: RequestInfo | URL) => dns(input) ?? new Response(bigStream(failCancel), { status: 200, headers: declared ? { "content-length": String(1024 * 1024) } : {} })) as typeof fetch;
        return deliverOtlpPush("https://otlp.example.com/v1/metrics", "{}", "Authorization", "s");
      };
      const c0 = countOf(id);
      const r0 = await push(false);
      ok(`control, ${shape}: delivered, body class oversized, nothing recorded`, r0.ok === true && r0.code === "otlp-partial-body-oversized" && countOf(id) === c0);
      const r1 = await push(true);
      ok(`${shape} whose cancel fails: the same result as the control`, r1.ok === true && r1.code === "otlp-partial-body-oversized");
      ok(`${shape} whose cancel fails: one row recorded`, countOf(id) === c0 + 1);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
}

async function disarmAlertBody(): Promise<void> {
  console.log("admin.disarm-alert-body (router-config-version.ts alertOnImmediateDisarm):");
  const id = "admin.disarm-alert-body";
  const ctx = { env: {}, scheduler: {}, caller: { method: "access", email: "o@example.com" } } as unknown as RouterCtx;
  const c0 = countOf(id);
  const r0 = await alertOnImmediateDisarm(new Response(JSON.stringify({ ok: true, disarmed: false }), { status: 200 }), ctx, "restore-approval");
  ok("control, a JSON 200 with no disarm: body returned and nothing recorded", r0.status === 200 && (await r0.text()) === '{"ok":true,"disarmed":false}' && countOf(id) === c0);
  const r1 = await alertOnImmediateDisarm(new Response("not json", { status: 200 }), ctx, "restore-approval");
  ok("a 200 body that is not JSON: returned verbatim with status 200", r1.status === 200 && (await r1.text()) === "not json");
  ok("a 200 body that is not JSON: one row recorded", countOf(id) === c0 + 1);
}

async function retentionAlert(): Promise<void> {
  console.log("notify.retention-armed-alone-alert (router-notify.ts routeRetentionArmedAloneAlert):");
  const id = "notify.retention-armed-alone-alert";
  const scheduler = { fetch: async () => new Response(JSON.stringify({ now: [], emission: null }), { status: 200 }) } as unknown as DurableObjectStub;
  const c0 = countOf(id);
  let threw = false;
  try {
    await routeRetentionArmedAloneAlert({} as Env, scheduler, "o@example.com", "dp-1", 1);
  } catch {
    threw = true;
  }
  ok("control, the alert routes: no throw and nothing recorded", !threw && countOf(id) === c0);
  // The planted fault: a downpipe id whose string conversion throws, so the alert fails before it is routed.
  const poison = {
    toString(): string {
      throw new Error("planted");
    },
  } as unknown as string;
  try {
    await routeRetentionArmedAloneAlert({} as Env, scheduler, "o@example.com", poison, 1);
  } catch {
    threw = true;
  }
  ok("an alert that fails: still fails open (no throw to the caller)", !threw);
  ok("an alert that fails: one row recorded", countOf(id) === c0 + 1);
}

function memberInviteBody(): void {
  console.log("admin.member-invite-body (router-sources.ts withholdMemberInvite):");
  const id = "admin.member-invite-body";
  const c0 = countOf(id);
  ok("control, a JSON body with no member invite: null and nothing recorded", withholdMemberInvite(JSON.stringify({ email: "a@example.com", role: "viewer" }), true) === null && countOf(id) === c0);
  ok("a body that is not JSON: still null, so the route forwards it unchanged", withholdMemberInvite("not json", true) === null);
  ok("a body that is not JSON: one row recorded", countOf(id) === c0 + 1);
}

// failingOn answers every DO path with an empty object, except the paths named, which reject as a faulting DO would.
function failingOn(...paths: string[]): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (paths.includes(url.pathname)) throw new Error("planted");
      return Response.json({});
    },
  } as unknown as DurableObjectStub;
}

async function packReadsThatReturnEmpty(): Promise<void> {
  console.log("support.recovery-refusals-read (support-sections-recovery.ts fetchRecoveryRefusals):");
  const rid = "support.recovery-refusals-read";
  const r0 = countOf(rid);
  // The refusal read comes first inside fetchRecoveryStatus, so its row lands before the recovery-status read
  // that follows it, whatever that read does with this double.
  const settle = async (stub: DurableObjectStub): Promise<void> => {
    try {
      await fetchRecoveryStatus(stub, {} as Env);
    } catch {
      /* the status read after the refusal read is not under test */
    }
  };
  await settle(failingOn());
  ok("control, a readable refusal record: nothing recorded", countOf(rid) === r0);
  await settle(failingOn("/recovery-refusals"));
  ok("a refusal record that cannot be read: one row recorded", countOf(rid) === r0 + 1);

  console.log("support.status-baseline-read (support-sections-runs.ts fetchStatusBaseline):");
  const bid = "support.status-baseline-read";
  const b0 = countOf(bid);
  const okBaseline = await fetchStatusBaseline(failingOn());
  ok("control, a readable baseline: nothing recorded", countOf(bid) === b0 && Object.keys(okBaseline).length === 0);
  const failedBaseline = await fetchStatusBaseline(failingOn("/status-baseline"));
  ok("a baseline that cannot be read: still {}", Object.keys(failedBaseline).length === 0);
  ok("a baseline that cannot be read: one row recorded", countOf(bid) === b0 + 1);

  console.log("support.ingest-pull-limiter (support-ingest.ts ingestPullRateLimited):");
  const lid = "support.ingest-pull-limiter";
  const l0 = countOf(lid);
  const admitted = await ingestPullRateLimited({ fetch: async () => Response.json({ allowed: true }) } as unknown as DurableObjectStub, "client-1");
  ok("control, a limiter that answers allow: admitted and nothing recorded", admitted === null && countOf(lid) === l0);
  const refused = await ingestPullRateLimited({ fetch: async () => Response.json({ allowed: false, retryAfterMs: 5000 }) } as unknown as DurableObjectStub, "client-1");
  ok("control, a limiter that answers deny: 429 and nothing recorded", refused?.status === 429 && countOf(lid) === l0);
  // A JSON 500 parses, so the status decides: the refusal and baseline reads record a row for it too.
  const http500 = { fetch: async () => new Response(JSON.stringify({ error: "internal error" }), { status: 500 }) } as unknown as DurableObjectStub;
  const rBefore = countOf(rid);
  try {
    await fetchRecoveryStatus(http500, {} as Env);
  } catch {
    /* the status read after the refusal read is not under test */
  }
  ok("a JSON 500 on the refusal record: one row recorded", countOf(rid) === rBefore + 1);
  const bBefore = countOf(bid);
  await fetchStatusBaseline(http500);
  ok("a JSON 500 on the baseline: one row recorded", countOf(bid) === bBefore + 1);
  const open = await ingestPullRateLimited(failingOn("/rate-check"), "client-1");
  ok("a limiter that cannot answer: still admitted (fails open)", open === null);
  ok("a limiter that cannot answer: one row recorded", countOf(lid) === l0 + 1);
}

async function cronSkips(): Promise<void> {
  console.log("cron.seal-reconcile (seal-loop-pass.ts reconcileAndDue):");
  const sid = "cron.seal-reconcile";
  const s0 = countOf(sid);
  const due = await reconcileAndDue({ fetch: async () => Response.json({ due: [] }) } as unknown as DurableObjectStub);
  ok("control, a scheduler that answers: an empty due set (not null) and nothing recorded", Array.isArray(due) && due.length === 0 && countOf(sid) === s0);
  const skipped = await reconcileAndDue(failingOn("/tick"));
  ok("a scheduler that cannot be reached: still null, so the tick is skipped", skipped === null);
  ok("a scheduler that cannot be reached: one row recorded", countOf(sid) === s0 + 1);

  console.log("cron.retention-keys (retention-pass.ts loadPassKeys):");
  const kid = "cron.retention-keys";
  const k0 = countOf(kid);
  const keys = await loadPassKeys({} as Env, "not-a-key");
  ok("keys that cannot be loaded: still null, so the pass is skipped", keys === null);
  ok("keys that cannot be loaded: one row recorded", countOf(kid) === k0 + 1);

  console.log("cron.engine-account-record (drive.ts drive):");
  const aid = "cron.engine-account-record";
  // The lease is granted; the scheduler then refuses the engine-account write (when failWrite) and every later call.
  const driveEnv = (failWrite: boolean): Env => {
    const stub = {
      async fetch(input: RequestInfo | URL): Promise<Response> {
        const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url).pathname;
        if (path === "/tick-lease/acquire") return Response.json({ acquired: true, token: "t" });
        if (path === "/sources/engine-account-verified" && !failWrite) return Response.json({ accountId: "a".repeat(32) });
        throw new Error("planted");
      },
    };
    return { CF_ACCOUNT_ID: "a".repeat(32), SCHEDULER: { idFromName: () => ({}), get: () => stub } } as unknown as Env;
  };
  const a0 = countOf(aid);
  await drive(driveEnv(false));
  ok("control, a scheduler that takes the engine account: nothing recorded", countOf(aid) === a0);
  await drive(driveEnv(true));
  ok("a scheduler that refuses the engine account: the tick still runs and one row is recorded", countOf(aid) === a0 + 1);
}

async function planHash(): Promise<void> {
  console.log("restore.plan-hash (scheduler-do-restore-approval.ts verifiedPlan):");
  const id = "restore.plan-hash";
  const c0 = countOf(id);
  const r0 = await verifiedPlan({ runId: "run-1", decisions: [] }, "sha384:00", "run-1");
  ok("control, a plan that hashes but does not match: mismatch and nothing recorded", r0 === "mismatch" && countOf(id) === c0);
  // A lone surrogate has no UTF-8 encoding, so canonicalJSON refuses the plan.
  const r1 = await verifiedPlan({ runId: "run-1", note: "\ud800" }, "sha384:00", "run-1");
  ok("a plan that cannot be hashed: still mismatch (refused with 400)", r1 === "mismatch");
  ok("a plan that cannot be hashed: one row recorded", countOf(id) === c0 + 1);
}

async function pruneWidenCheck(): Promise<void> {
  console.log("change-control.prune-widen-check (scheduler-do-change-control.ts widensStoredPrune):");
  const id = "change-control.prune-widen-check";
  const dobj = makeScheduler().stub as unknown as SchedulerDOSurface & { widensStoredPrune(params: unknown): Promise<boolean> };
  const c0 = countOf(id);
  const r0 = await dobj.widensStoredPrune({ id: "dp-1", retention: { enforce: true, keepRuns: 5 } });
  ok("control, a readable shape that arms the prune: widening and nothing recorded", r0 === true && countOf(id) === c0);
  const r0b = await dobj.widensStoredPrune({ id: "dp-1" });
  ok("control, a readable shape with no prune: not widening and nothing recorded", r0b === false && countOf(id) === c0);
  // The planted fault: a retention field whose read throws, so the rule cannot read the shape.
  const params = { id: "dp-1" };
  Object.defineProperty(params, "retention", {
    enumerable: true,
    get() {
      throw new Error("planted");
    },
  });
  const r1 = await dobj.widensStoredPrune(params);
  ok("an unreadable shape: still fails closed as widening", r1 === true);
  ok("an unreadable shape: one row recorded", countOf(id) === c0 + 1);
}

// ---- the RUNLOG re-key, attended and replication sites ----------------------------------------------------

const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const signerB64 = (): string => b64urlEncode(concat(rand(32), rand(32)));
const entryOf = (n: number, prev: string | null): RunlogEntry => ({ index: n, runId: `01ARZ3NDEKTSV4RRFFQ69G5FD${n}`, downpipeId: "dp-1", time: `2026-10-01T0${n}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" });

// A destination holding a RUNLOG of two linked entries signed by s.
async function signedDest(s: Signer): Promise<MemoryDestination> {
  const d = new MemoryDestination();
  const { runlog, sig } = await signRunlog([entryOf(1, null), entryOf(2, entryOf(1, null).runId)], s.edPrivate, s.mldsaSecret);
  await d.put(RUNLOG, runlog);
  await d.put(RUNLOG_SIG, utf8(b64urlEncode(sig)));
  return d;
}

// A destination holding bytes that do not parse, with a .sig by s that verifies them.
async function signedUnparsableDest(s: Signer): Promise<{ dest: MemoryDestination; digest: string }> {
  const d = new MemoryDestination();
  const body = utf8("not a runlog\n");
  await d.put(RUNLOG, body);
  await d.put(RUNLOG_SIG, utf8(b64urlEncode(await hybridSign(s.edPrivate, s.mldsaSecret, body))));
  return { dest: d, digest: hexEncode(await sha384(body)) };
}

// failing wraps a destination so that a get or a put of the named key throws the planted fault.
function failing(d: Destination, op: "get" | "put", key: string): Destination {
  return new Proxy(d, {
    get(t, p, r) {
      if (p === op) {
        return async (k: string, ...rest: unknown[]) => {
          if (k === key) throw new Error("planted");
          return (t[op] as (...a: unknown[]) => Promise<unknown>).call(t, k, ...rest);
        };
      }
      const v = Reflect.get(t, p, r);
      return typeof v === "function" ? v.bind(t) : v;
    },
  });
}

// A scheduler double for the destination reads. configStatus 503 makes the config read fail (the planted fault).
function destScheduler(configStatus: number): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL) => {
      const u = String(input);
      if (u.includes("/destinations")) return new Response(JSON.stringify({ destinations: [{ id: "d1", label: "one" }] }), { status: 200 });
      if (u.includes("/dest-config")) return configStatus === 200 ? new Response(JSON.stringify({ config: null }), { status: 200 }) : new Response("", { status: configStatus });
      if (u.includes("/rekey-handover")) return new Response(JSON.stringify({ open: false }), { status: 200 });
      return new Response("{}", { status: 200 });
    },
  } as unknown as DurableObjectStub;
}

async function runlogPrecheck(): Promise<void> {
  console.log("rekey.runlog-precheck-read and rekey.runlog-precheck-parse (runlog-handover.ts precheckRunlog):");
  const read = "rekey.runlog-precheck-read";
  const parse = "rekey.runlog-precheck-parse";
  const s = await loadSigner(signerB64());
  const v = verifierFrom(s);
  const r0 = await precheckRunlog(await signedDest(s), v);
  ok("control, a RUNLOG that verifies and parses: ok and nothing recorded", r0.ok === true && countOf(read) === 0 && countOf(parse) === 0);
  const sigInvalid = await precheckRunlog(await signedDest(await loadSigner(signerB64())), v);
  ok("control, a RUNLOG signed by another key: sig-invalid and nothing recorded", !sigInvalid.ok && sigInvalid.reason === "sig-invalid" && countOf(read) === 0 && countOf(parse) === 0);
  const r1 = await precheckRunlog(failing(await signedDest(s), "get", RUNLOG), v);
  ok("a RUNLOG read that fails: still refused as unreadable", !r1.ok && r1.reason === "unreadable");
  ok("a RUNLOG read that fails: one row recorded", countOf(read) === 1);
  const r2 = await precheckRunlog((await signedUnparsableDest(s)).dest, v);
  ok("a RUNLOG that verifies and does not parse: still refused as unparsable", !r2.ok && r2.reason === "unparsable");
  ok("a RUNLOG that verifies and does not parse: one row recorded", countOf(parse) === 1);
}

async function runlogHandover(): Promise<void> {
  console.log("rekey.runlog-handover-read (runlog-handover.ts handOverRunlog) and rekey.handover-resign (rekey-runlog-handover.ts handOverTargets):");
  const read = "rekey.runlog-handover-read";
  const resign = "rekey.handover-resign";
  const oldS = await loadSigner(signerB64());
  const newS = await loadSigner(signerB64());
  const r0 = await handOverRunlog(new MemoryDestination(), verifierFrom(oldS), newS);
  ok("control, no RUNLOG: absent and nothing recorded", r0 === "absent" && countOf(read) === 0);
  const r1 = await handOverRunlog(failing(await signedDest(oldS), "get", RUNLOG), verifierFrom(oldS), newS);
  ok("a RUNLOG read that fails: still pending", r1 === "pending");
  ok("a RUNLOG read that fails: one row recorded", countOf(read) === 1);
  const t0 = await handOverTargets([{ id: "d1", label: "one", dest: await signedDest(oldS) }], verifierFrom(oldS), newS);
  ok("control, a RUNLOG under the old key: re-signed and nothing recorded", t0[0]?.outcome === "re-signed" && countOf(resign) === 0);
  const t1 = await handOverTargets([{ id: "d1", label: "one", dest: failing(await signedDest(oldS), "put", RUNLOG_SIG) }], verifierFrom(oldS), newS);
  ok("a re-sign whose .sig write fails: still pending", t1[0]?.outcome === "pending");
  ok("a re-sign whose .sig write fails: one row recorded", countOf(resign) === 1);
}

async function handoverTargets(): Promise<void> {
  console.log("rekey.handover-target-open (rekey-runlog-handover.ts listHandoverTargets):");
  const id = "rekey.handover-target-open";
  const env = {} as Env;
  const t0 = await listHandoverTargets(env, destScheduler(200));
  ok("control, a destination that is not configured: listed with no destination and nothing recorded", t0.length === 1 && t0[0]?.dest === null && countOf(id) === 0);
  const t1 = await listHandoverTargets(env, destScheduler(503));
  ok("a destination whose config read fails: still listed with no destination, so the pre-check refuses it", t1.length === 1 && t1[0]?.dest === null);
  ok("a destination whose config read fails: one row recorded", countOf(id) === 1);
}

async function rekeyRoute(): Promise<void> {
  console.log("rekey.install-response-body (router-keys.ts withRunlogHandover) and rekey.handover-settle (settleFailedRekey):");
  const body = "rekey.install-response-body";
  const settle = "rekey.handover-settle";
  const skipped: HandoverSummary = { outcomes: [], pending: [], heldKeyDiscarded: false, skipped: "outgoing-signer-unreadable" };
  const ctx = (scheduler: DurableObjectStub) => ({ env: {}, scheduler, caller: { method: "access", email: "o@example.com" }, sourceIp: "" }) as unknown as RouterCtx;
  const r0 = await withRunlogHandover(ctx(destScheduler(200)), new Response(JSON.stringify({ ok: true }), { status: 200 }), skipped);
  const j0 = (await r0.json()) as Record<string, unknown>;
  ok("control, a JSON install response: the outcome is added and nothing recorded", j0.ok === true && typeof j0.runlogHandover === "object" && countOf(body) === 0);
  const r1 = await withRunlogHandover(ctx(destScheduler(200)), new Response("not json", { status: 200 }), skipped);
  const j1 = (await r1.json()) as Record<string, unknown>;
  ok("an install response that is not JSON: the response still carries the outcome", typeof j1.runlogHandover === "object" && j1.ok === undefined);
  ok("an install response that is not JSON: one row recorded", countOf(body) === 1);
  const begun = { targets: [], oldVerifier: null };
  const fault = new KeyCeremonyFault("signer", "parse", new Error("bad key"));
  await settleFailedRekey(ctx(destScheduler(200)), begun, fault, "");
  ok("control, a failed install that changed no signer: the hand-over is dropped and nothing recorded", countOf(settle) === 0);
  const down = { fetch: async () => Promise.reject(new Error("planted")) } as unknown as DurableObjectStub;
  let threw = false;
  try {
    await settleFailedRekey(ctx(down), begun, fault, "");
  } catch {
    threw = true;
  }
  ok("a settle whose scheduler call fails: still no throw to the route", !threw);
  ok("a settle whose scheduler call fails: one row recorded", countOf(settle) === 1);
}

async function verifierDecode(): Promise<void> {
  console.log("rekey.verifier-decode (rekey-handover.ts decodeVerifier):");
  const id = "rekey.verifier-decode";
  const v = verifierFrom(await loadSigner(signerB64()));
  ok("control, a held key that decodes: decoded and nothing recorded", decodeVerifier(encodeVerifier(v)) !== null && countOf(id) === 0);
  ok("control, a held key of the wrong length: null and nothing recorded", decodeVerifier({ ed: "AAAA", mldsa: "AAAA" }) === null && countOf(id) === 0);
  ok("a held key that does not decode: still null", decodeVerifier({ ed: "A", mldsa: "AAAA" }) === null);
  ok("a held key that does not decode: one row recorded", countOf(id) === 1);
}

async function runlogRouteBody(): Promise<void> {
  console.log("sched.runlog-route-body (scheduler-do-routing.ts RoutingMixin.routeCore):");
  const id = "sched.runlog-route-body";
  const { storage, stub } = makeScheduler();
  // The DO drains the isolate ledger into its own storage when fetch ends, so both are counted.
  const total = async (): Promise<number> => countOf(id) + ((await storage.get<SiteFaults>(SITE_FAULTS_KEY))?.[id]?.count ?? 0);
  const post = (path: string, b: string) => stub.fetch(new Request(`https://scheduler.internal${path}`, { method: "POST", body: b, headers: { "content-type": "application/json" } }));
  const c0 = await total();
  const r0 = await post("/rekey-handover/begin", "{}");
  ok("control, a JSON body with no held key: 400 and nothing recorded", r0.status === 400 && (await total()) === c0);
  const r1 = await post("/rekey-handover/begin", "not json");
  ok("a body that is not JSON: still 400", r1.status === 400);
  ok("a body that is not JSON: one row recorded", (await total()) === c0 + 1);
}

async function attendedOpen(): Promise<void> {
  console.log("runlog.attended-dest-open (router-runlog.ts openContext):");
  const id = "runlog.attended-dest-open";
  const ctx = (scheduler: DurableObjectStub) => ({ env: { SIGNER_PRIVATE: signerB64() }, scheduler }) as unknown as RouterCtx;
  const r0 = await openContext(ctx(destScheduler(200)), "d1");
  ok("control, a destination that is not configured: 404 and nothing recorded", r0 instanceof Response && r0.status === 404 && countOf(id) === 0);
  const r1 = await openContext(ctx(destScheduler(503)), "d1");
  ok("a destination whose config read fails: still 409", r1 instanceof Response && r1.status === 409);
  ok("a destination whose config read fails: one row recorded", countOf(id) === 1);
}

async function relinkParse(): Promise<void> {
  console.log("runlog.relink-parse (runlog-handover.ts relinkRunlogAttended):");
  const id = "runlog.relink-parse";
  const s = await loadSigner(signerB64());
  const good = await signedDest(s);
  const goodDigest = hexEncode(await sha384((await good.get(RUNLOG))?.body ?? new Uint8Array()));
  const r0 = await relinkRunlogAttended(good, s, "dp-1", goodDigest);
  ok("control, a chain with no anomaly: no-anomaly and nothing recorded", r0 === "no-anomaly" && countOf(id) === 0);
  const bad = await signedUnparsableDest(s);
  const r1 = await relinkRunlogAttended(bad.dest, s, "dp-1", bad.digest);
  ok("a RUNLOG that verifies and does not parse: still refused, nothing written", r1 === "not-verified");
  ok("a RUNLOG that verifies and does not parse: one row recorded", countOf(id) === 1);
}

async function floorRead(): Promise<void> {
  console.log("runlog.floor-read (pipeline.ts readFloor):");
  const id = "runlog.floor-read";
  const lock = (floor: () => Promise<number | undefined>): RunlogLock => ({ acquire: async () => null, release: async () => {}, floor });
  ok("control, a floor that reads: the floor and nothing recorded", (await readFloor(lock(async () => 3))) === 3 && countOf(id) === 0);
  ok("a floor read that fails: still no floor", (await readFloor(lock(async () => Promise.reject(new Error("planted"))))) === undefined);
  ok("a floor read that fails: one row recorded", countOf(id) === 1);
}

async function replicationReads(): Promise<void> {
  console.log("repl.runlog-read, repl.source-runlog-verify (replicate-runlog.ts makeRunlogReader) and repl.root-parse (entryMatchesRoot):");
  const read = "repl.runlog-read";
  const verify = "repl.source-runlog-verify";
  const root = "repl.root-parse";
  const s = await loadSigner(signerB64());
  const reader = () => makeRunlogReader({ runlogs: new Map(), runlogBodies: new Map(), verifiedRunlogs: new Map() }, s);
  const e0 = await reader()("d1", await signedDest(s));
  ok("control, a RUNLOG that reads: two entries and nothing recorded", e0?.length === 2 && countOf(read) === 0);
  const e1 = await reader()("d1", failing(await signedDest(s), "get", RUNLOG));
  ok("a RUNLOG read that fails: still unreadable this pass (null)", e1 === null);
  ok("a RUNLOG read that fails: one row recorded", countOf(read) === 1);
  const v0 = await reader()("d1", await signedDest(await loadSigner(signerB64())), true);
  ok("control, a source RUNLOG signed by another key: refused (null) and nothing recorded", v0 === null && countOf(verify) === 0);
  const v1 = await reader()("d1", failing(await signedDest(s), "get", RUNLOG_SIG), true);
  ok("a source RUNLOG whose .sig read fails: still not used (null)", v1 === null);
  ok("a source RUNLOG whose .sig read fails: one row recorded", countOf(verify) === 1);
  const entry = entryOf(2, null);
  const rootOf = (o: unknown): Uint8Array => utf8(JSON.stringify(o));
  ok("control, a root that matches: true and nothing recorded", entryMatchesRoot(rootOf({ runId: entry.runId, downpipeId: entry.downpipeId, freshness: { runlogIndex: 2 } }), entry) && countOf(root) === 0);
  ok("control, no root: false and nothing recorded", !entryMatchesRoot(null, entry) && countOf(root) === 0);
  ok("a root that does not parse: still false (refused)", !entryMatchesRoot(utf8("not json"), entry));
  ok("a root that does not parse: one row recorded", countOf(root) === 1);
}

async function main(): Promise<void> {
  await inboundBody();
  await otlpBody();
  await disarmAlertBody();
  await retentionAlert();
  memberInviteBody();
  await packReadsThatReturnEmpty();
  await cronSkips();
  await planHash();
  await pruneWidenCheck();
  await runlogPrecheck();
  await runlogHandover();
  await handoverTargets();
  await rekeyRoute();
  await verifierDecode();
  await runlogRouteBody();
  await attendedOpen();
  await relinkParse();
  await floorRead();
  await replicationReads();
  const { failures, checks } = tally();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-site-fault-handled-sites (${failures} failure(s) of ${checks})`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
