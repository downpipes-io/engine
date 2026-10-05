// validate-runlog-floor: the in-account restore, drill, verify and attest refuse a RUNLOG rolled back to an
// older, validly signed copy, and still open every healthy destination.
//
// WHY THIS FILE EXISTS. Each destination holds its own signed _RECOVERY/RUNLOG. A bucket-write adversary can
// put back the copy from an earlier run. That copy verifies and is internally consistent, so only a number held
// outside the bucket can show the log went backwards. The offline reader takes it from the recovery sheet
// (--min-runlog-index). In-account, the dry run and apply (admin/restore.ts) and both drills (admin/drill.ts)
// opened with no pin at all, so they opened the rolled-back destination. /restore/verify and /restore/attest
// pinned the ACCOUNT-GLOBAL runlogCounter, which is allocated at trigger: an in-flight run, a failed run, or a
// run on ANOTHER destination raised it, and healthy proofs were refused.
//
// THE FIX UNDER TEST. sched/runlog-floor.ts keeps, per destination, the highest RUNLOG index the engine
// CONFIRMED it appended there (an ok completion, or a replicate-pass record). Every trust-bearing open reads the
// floor of the destination it is opening (admin/restore-open.ts fetchRunlogFloor) and passes it as
// minRunlogIndex. The reader's own rule then applies (format/freshness.ts): a RUNLOG whose maximum index is
// below the pin is a rollback, and it refuses whatever allowStale says.
//
// WHAT IS GRADED, through the production admin router, a real SchedulerDO over MockStorage, real sealed
// archives, real appendRunlog and the real verifying reader (in-memory destination, no network):
//   A. runs 1-3 sealed to one destination; its RUNLOG put back to the signed copy taken after run 1. The dry
//      run, the manual drill, /restore/verify and /restore/attest of run 1 all refuse as a rollback.
//   B. NEGATIVE CONTROL: run 4 in flight, run 5 failed, and a second destination holding index 6. Every open of
//      run 3 on the first destination succeeds, and so does a scheduled drill. (/restore/verify and
//      /restore/attest refused here while they pinned the raw counter.)
//   C. A shared destination: another downpipe's run 4 lands there. The scheduled drill of this downpipe's
//      latest run refuses once the RUNLOG is put back to before run 4.
//   D. The destination lifecycle, on the DO: a prune keeps the floor honest, a repointed or removed
//      destination loses its floor, a re-added one starts clean, and a run that began before a repoint or a
//      default move, or whose destination was removed mid-run, raises nothing.
// Run: node test/validate-runlog-floor.ts

import { x25519 } from "@noble/curves/ed25519.js";

import { handleAdmin } from "../src/admin/router.ts";
import type { BlindRestoreTest, KeylessAttestationResult, RestorePlan } from "../src/admin/restore-types.ts";
import type { DrillResult } from "../src/admin/drill.ts";
import { encodeCaller } from "../src/admin/identity.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { runScheduledRestoreTest } from "../src/cron/restore-test-pass.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { REASON_FRESHNESS } from "../src/restore-reasons.ts";
import { appendRunlog, supersedeRunlog } from "../src/seal/pipeline.ts";
import { ENV_FLOOR_KEY, RUNLOG_FLOOR_KEY } from "../src/sched/runlog-floor.ts";
import { SchedulerDO, type DownpipeState } from "../src/sched/scheduler-do.ts";
import { MemoryDestination } from "./memdest.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

const NS = "ns_floor";
const DP = "dp_floor";
const DP_B = "dp_floor_b";
const RUN = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FA${n}`;
const RUNLOG_KEY = "_RECOVERY/RUNLOG";
const RUNLOG_SIG_KEY = "_RECOVERY/RUNLOG.sig";
const KVSET: Record<string, string> = { a: "alpha-value", b: "beta-value" };

// The env-backed destination is DEST_R2 over this in-memory store, so every read goes through the production
// destination factory; only the binding is a double.
function r2For(dest: MemoryDestination): R2Bucket {
  return {
    get: async (key: string) => {
      const v = await dest.get(key);
      if (!v) return null;
      return {
        arrayBuffer: async () => {
          const ab = new ArrayBuffer(v.body.byteLength);
          new Uint8Array(ab).set(v.body);
          return ab;
        },
        etag: v.etag,
      };
    },
    head: async (key: string) => ((await dest.get(key)) ? { etag: "x" } : null),
  } as unknown as R2Bucket;
}

// ---- Access JWT (real RS256 verification against a stubbed JWKS), as validate-cov-admin-router-restore.ts ----
const TEAM = "floor-team";
const ISS = `https://${TEAM}.cloudflareaccess.com`;
const AUD = "floor-aud";
const KID = "floor-kid-1";
const OWNER = "owner-floor@acme.example";
const OWNER_CALLER = encodeCaller({ method: "token", email: null, subject: null, role: "owner", groups: [] });

function jwtPart(obj: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
}

interface Rig {
  storage: MockStorage;
  dobj: SchedulerDO;
  stub: DurableObjectStub;
  namespace: DurableObjectNamespace;
}
function makeRig(): Rig {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
  return { storage, dobj, stub, namespace };
}
async function doCall(rig: Rig, method: string, path: string, body?: unknown, caller?: string): Promise<Response> {
  const headers: Record<string, string> = { ...(body !== undefined ? { "content-type": "application/json" } : {}), ...(caller !== undefined ? { "x-downpipe-caller": caller } : {}) };
  return rig.dobj.fetch(new Request(`https://scheduler.internal${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
}
async function floorOf(rig: Rig, id?: string): Promise<number | null> {
  const r = await doCall(rig, "GET", `/runlog-floor${id ? `?id=${encodeURIComponent(id)}` : ""}`);
  if (!r.ok) return null;
  return ((await r.json()) as { floor?: number | null }).floor ?? null;
}

async function main(): Promise<void> {
  const signerPrivateB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  // seal writes one real archive for (downpipe, run n) to dest and appends its entry to dest's own RUNLOG
  // through the production appendRunlog, exactly as the seal path's last step does.
  async function seal(dest: MemoryDestination, downpipeId: string, n: number, prevRunId: string | null): Promise<void> {
    const archive = await buildArchive({
      downpipeId,
      downpipeName: downpipeId,
      cadence: "3600s",
      runId: RUN(n),
      master: rand(32),
      recipients: [breakGlass.entry, op.entry],
      signer,
      records: Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv" as const, name, value: utf8(`${v}-${n}`), namespace: NS })),
      windowStart: "2026-06-07T00:00:00.000Z",
      windowEnd: "2026-06-07T00:00:01.000Z",
      createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: n,
      prevRunId,
      skipRunlog: true,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    });
    for (const [k, b] of archive) await dest.put(k, b);
    await appendRunlog(dest, signer, { index: n, runId: RUN(n), downpipeId, time: "2026-06-07T00:00:01.000Z", recordCount: 2, prevRunId, status: "active" }, undefined, { relinkLocalPrev: true });
  }
  async function snapshotRunlog(dest: MemoryDestination): Promise<[Uint8Array, Uint8Array]> {
    return [(await dest.get(RUNLOG_KEY))!.body, (await dest.get(RUNLOG_SIG_KEY))!.body];
  }
  async function putBack(dest: MemoryDestination, snap: [Uint8Array, Uint8Array]): Promise<void> {
    await dest.put(RUNLOG_KEY, snap[0]);
    await dest.put(RUNLOG_SIG_KEY, snap[1]);
  }

  // A downpipe the DO knows, unpinned (it follows the default), with the KV source the restore plan targets.
  async function addDownpipe(rig: Rig, id: string): Promise<void> {
    const r = await doCall(rig, "POST", "/downpipes", { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${NS}`, namespaceId: NS, include: [], exclude: [] } }, OWNER_CALLER);
    if (!r.ok) throw new Error(`downpipe add failed: ${r.status} ${await r.text()}`);
  }
  // inFlight seeds a run the DO allocated (an in-flight history row), the state trigger() leaves behind.
  async function inFlight(rig: Rig, id: string, n: number, startedAt = new Date().toISOString()): Promise<void> {
    const hist = ((await rig.storage.get(`hist:${id}`)) as Array<Record<string, unknown>> | undefined) ?? [];
    hist.push({ runId: RUN(n), index: n, startedAt, status: "in-flight", prevRunId: null });
    await rig.storage.put(`hist:${id}`, hist);
    const counter = ((await rig.storage.get("runlogCounter")) as number | undefined) ?? 0;
    if (n > counter) await rig.storage.put("runlogCounter", n);
  }
  // complete posts the real /complete the seal drivers post.
  async function complete(rig: Rig, id: string, n: number, opts: { ok?: boolean; destinationId?: string } = {}): Promise<void> {
    const failed = opts.ok === false;
    await doCall(rig, "POST", "/complete", { id, runId: failed ? "" : RUN(n), index: n, status: failed ? "failed" : "ok", ...(opts.destinationId !== undefined ? { destinationId: opts.destinationId } : {}) });
  }

  // ---- the admin router, authenticated as the Owner ----
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = (await crypto.subtle.exportKey("jwk", kp.publicKey)) as { n: string; e: string };
  const jwks = { keys: [{ kid: KID, kty: "RSA", n: pubJwk.n, e: pubJwk.e }] };
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url === `${ISS}/cdn-cgi/access/certs`) return new Response(JSON.stringify(jwks), { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected network fetch in test: ${url}`);
  }) as typeof fetch;
  const futureExp = Math.floor(Date.now() / 1000) + 3600;
  async function token(): Promise<string> {
    const header = jwtPart({ alg: "RS256", kid: KID, typ: "JWT" });
    const body = jwtPart({ iss: ISS, aud: AUD, exp: futureExp, iat: futureExp - 3600, email: OWNER, sub: `sub-of-${OWNER}` });
    const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", kp.privateKey, new TextEncoder().encode(`${header}.${body}`)));
    return `${header}.${body}.${b64urlEncode(sig)}`;
  }
  function envFor(rig: Rig, dest: MemoryDestination): Env {
    return {
      SCHEDULER: rig.namespace,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      DEST_KIND: "r2",
      DEST_R2: r2For(dest),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
      [`KV_${NS}`]: { put: async () => {}, get: async () => null, delete: async () => {}, list: async () => ({ keys: [], list_complete: true }) } as unknown as KVNamespace,
    } as unknown as Env;
  }
  async function admin<T>(env: Env, path: string, body: unknown): Promise<T> {
    const r = await handleAdmin(new Request(`https://engine.example/admin${path}`, { method: "POST", headers: { "cf-access-jwt-assertion": await token(), "content-type": "application/json" }, body: JSON.stringify(body) }), env);
    return (await r.json()) as T;
  }
  // The four in-account opens of one run, through the router exactly as the console calls them.
  async function openAll(env: Env, n: number): Promise<{ plan: RestorePlan; drill: DrillResult; verify: BlindRestoreTest; attest: KeylessAttestationResult }> {
    return {
      plan: await admin<RestorePlan>(env, "/restore", { runId: RUN(n) }),
      drill: await admin<DrillResult>(env, "/drill", { runId: RUN(n) }),
      verify: await admin<BlindRestoreTest>(env, "/restore/verify", { runId: RUN(n) }),
      attest: await admin<KeylessAttestationResult>(env, "/restore/attest", { runId: RUN(n) }),
    };
  }

  try {
    // =====================================================================================================
    console.log("A/B -- one destination, runs 1-3, then in-flight, failed and other-destination indices");
    const rig = makeRig();
    const d = new MemoryDestination();
    const env = envFor(rig, d);
    await handleAdmin(new Request("https://engine.example/admin/whoami", { headers: { "cf-access-jwt-assertion": await token() } }), env);
    await addDownpipe(rig, DP);
    let afterRun1: [Uint8Array, Uint8Array] | undefined;
    for (const n of [1, 2, 3]) {
      await inFlight(rig, DP, n);
      await seal(d, DP, n, n === 1 ? null : RUN(n - 1));
      await complete(rig, DP, n);
      if (n === 1) afterRun1 = await snapshotRunlog(d);
    }
    ok("the env-backed destination's floor is 3 after three ok completions", (await floorOf(rig)) === 3);

    // B: the three states the raw counter confused with a rollback.
    await inFlight(rig, DP, 4); // allocated, sealing, nothing appended yet
    await inFlight(rig, DP, 5);
    await complete(rig, DP, 5, { ok: false }); // consumed index 5, appended nothing
    const put = await doCall(rig, "POST", "/destinations", { label: "second", config: { endpoint: "https://d2.example.com", bucket: "second-bucket", region: "auto", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "secret" }, envDestConfigured: true }, OWNER_CALLER);
    const d2 = ((await put.json()) as { destinations?: Array<{ id: string; bucket: string }> }).destinations?.find((x) => x.bucket === "second-bucket")?.id ?? "";
    await rig.storage.put("runlogCounter", 6);
    await addDownpipe(rig, DP_B);
    await doCall(rig, "POST", "/replication/record", { id: DP_B, destinationId: d2, ok: true, runId: RUN(6), index: 6 });
    ok("FLOOR: the account-global counter is 6", ((await rig.storage.get("runlogCounter")) as number) === 6);
    ok("the in-flight run 4 and the failed run 5 did not raise the floor (still 3)", (await floorOf(rig)) === 3);
    ok(`the second destination holds its own floor of 6 (${await floorOf(rig, d2)})`, (await floorOf(rig, d2)) === 6);

    const healthy = await openAll(env, 3);
    ok(`B: the dry run of run 3 succeeds (${healthy.plan.reason ?? "ok"})`, healthy.plan.ok === true);
    ok(`B: the manual drill of run 3 succeeds (${healthy.drill.reason ?? "ok"})`, healthy.drill.ok === true);
    // THE ASSERTIONS THE RAW-COUNTER PIN FAILED: counter 6 > this destination's maximum of 3.
    ok(`B: /restore/verify of run 3 succeeds (${healthy.verify.reason ?? "ok"})`, healthy.verify.ok === true);
    ok(`B: /restore/attest of run 3 succeeds (${healthy.attest.reason ?? "ok"})`, healthy.attest.ok === true);
    {
      const state = (await rig.storage.get(`dp:${DP}`)) as DownpipeState;
      await runScheduledRestoreTest(env, rig.stub, state);
      const after = (await rig.storage.get(`dp:${DP}`)) as DownpipeState;
      ok("B: the scheduled drill of the latest run (3) passes", after.lastRestoreTestOk === true);
    }

    // A prune marks run 1 superseded and keeps its entry, so the maximum index stays 3: still restorable.
    await supersedeRunlog(d, signer, [RUN(1)]);
    const afterPrune = await admin<RestorePlan>(env, "/restore", { runId: RUN(2) });
    ok(`D: after a prune supersedes run 1, the dry run of run 2 still succeeds (${afterPrune.reason ?? "ok"})`, afterPrune.ok === true);

    // A: the rollback. The RUNLOG and its signature are put back to the copy taken after run 1.
    await putBack(d, afterRun1!);
    const rolled = await openAll(env, 1);
    // THE ASSERTIONS THE OLD RESTORE AND DRILL FAILED: they opened with no pin and read the old copy clean.
    ok(`A: the dry run of run 1 refuses as a rollback (${rolled.plan.reason ?? "ok"})`, rolled.plan.ok === false && rolled.plan.reason === REASON_FRESHNESS);
    ok(`A: the manual drill of run 1 refuses as a rollback (${rolled.drill.reason ?? "ok"})`, rolled.drill.ok === false && rolled.drill.reason === REASON_FRESHNESS);
    ok(`A: /restore/verify of run 1 refuses as a rollback (${rolled.verify.reason ?? "ok"})`, rolled.verify.ok === false && rolled.verify.reason === REASON_FRESHNESS);
    ok("A: /restore/attest of run 1 reports the rollback", rolled.attest.ok === false && rolled.attest.notRolledBack === false);
    // CONTROL: the same rolled-back bucket with no floor recorded opens clean, so the refusals above are the
    // floor, not some other fault in the rig.
    await rig.storage.put(RUNLOG_FLOOR_KEY, {});
    const unpinned = await admin<RestorePlan>(env, "/restore", { runId: RUN(1) });
    ok(`CONTROL: with no floor recorded, the rolled-back bucket's dry run opens (${unpinned.reason ?? "ok"})`, unpinned.ok === true);

    // =====================================================================================================
    console.log("\nC -- a shared destination: another downpipe's later run, then a rollback before it");
    {
      const rigC = makeRig();
      const dc = new MemoryDestination();
      const envC = envFor(rigC, dc);
      await handleAdmin(new Request("https://engine.example/admin/whoami", { headers: { "cf-access-jwt-assertion": await token() } }), envC);
      await addDownpipe(rigC, DP);
      await addDownpipe(rigC, DP_B);
      for (const n of [1, 2, 3]) {
        await inFlight(rigC, DP, n);
        await seal(dc, DP, n, n === 1 ? null : RUN(n - 1));
        await complete(rigC, DP, n);
      }
      const beforeB = await snapshotRunlog(dc);
      await inFlight(rigC, DP_B, 4);
      await seal(dc, DP_B, 4, null);
      await complete(rigC, DP_B, 4);
      ok("the shared destination's floor is 4 (run 4 of the other downpipe)", (await floorOf(rigC)) === 4);
      const state = (await rigC.storage.get(`dp:${DP}`)) as DownpipeState;
      await runScheduledRestoreTest(envC, rigC.stub, state);
      ok("CONTROL: the scheduled drill of run 3 passes on the intact RUNLOG", ((await rigC.storage.get(`dp:${DP}`)) as DownpipeState).lastRestoreTestOk === true);
      await putBack(dc, beforeB);
      await runScheduledRestoreTest(envC, rigC.stub, (await rigC.storage.get(`dp:${DP}`)) as DownpipeState);
      // THE ASSERTION THE OLD SCHEDULED DRILL FAILED: run 3 is present and the chain is clean, so only the pin sees it.
      ok("C: the scheduled drill refuses once the RUNLOG is put back to before run 4", ((await rigC.storage.get(`dp:${DP}`)) as DownpipeState).lastRestoreTestOk === false);
    }

    // =====================================================================================================
    console.log("\nD -- the destination lifecycle keeps the floor about ONE bucket");
    {
      const r = makeRig();
      await addDownpipe(r, DP);
      const add = async (bucket: string, id?: string): Promise<string> => {
        const resp = await doCall(r, "POST", "/destinations", { ...(id !== undefined ? { id } : {}), label: bucket, config: { endpoint: "https://s3.example.com", bucket, region: "auto", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "secret" }, envDestConfigured: true }, OWNER_CALLER);
        const list = ((await resp.json()) as { destinations?: Array<{ id: string; bucket: string }> }).destinations ?? [];
        return list.find((x) => x.bucket === bucket)?.id ?? "";
      };
      const x = await add("bucket-x");
      ok("FLOOR: a console destination was added next to the seeded env destination", x !== "" && x !== "deploy");
      await inFlight(r, DP, 7);
      await complete(r, DP, 7, { destinationId: x });
      ok("an ok completion to a named destination raises ITS floor", (await floorOf(r, x)) === 7);
      ok("and leaves the env destination's floor alone", (await floorOf(r)) === null);

      await add("bucket-x", x); // an edit that keeps the location (a credential rotation or a relabel)
      ok("an edit that keeps the endpoint and bucket keeps the floor", (await floorOf(r, x)) === 7);

      const startedBeforeRepoint = new Date(Date.now() - 60_000).toISOString();
      await inFlight(r, DP, 8, startedBeforeRepoint);
      await add("bucket-x-migrated", x); // the same id, repointed at a different bucket
      ok("REPLACED: repointing the id at another bucket resets its floor (no pin on the new bucket)", (await floorOf(r, x)) === null);
      await complete(r, DP, 8, { destinationId: x });
      ok("a run that began BEFORE the repoint and completes after it does not raise the new bucket's floor", (await floorOf(r, x)) === null);
      // Started a second after the repoint: a run started in the same millisecond is skipped, which is the
      // conservative direction (no pin until the next run).
      await inFlight(r, DP, 9, new Date(Date.now() + 1000).toISOString());
      await complete(r, DP, 9, { destinationId: x });
      ok("the first run that began after the repoint raises the new bucket's floor", (await floorOf(r, x)) === 9);

      await inFlight(r, DP, 10);
      await doCall(r, "POST", "/destinations/remove", { id: x, force: true }, OWNER_CALLER);
      ok("DETACHED: removing the destination resets its floor", (await floorOf(r, x)) === null);
      await complete(r, DP, 10, { destinationId: x });
      ok("a run whose destination was removed mid-run raises nothing (not even the env floor)", (await floorOf(r)) === null && (await floorOf(r, x)) === null);
      const y = await add("bucket-x-migrated");
      ok(`REATTACHED: re-adding the same bucket gives a new id (${y}) with no inherited floor`, y !== "" && y !== x && (await floorOf(r, y)) === null);
      await doCall(r, "POST", "/replication/record", { id: DP, destinationId: y, ok: true, runId: RUN(11), index: 11 });
      ok("a replicate-pass record raises the re-added destination's floor", (await floorOf(r, y)) === 11);
      await doCall(r, "POST", "/replication/record", { id: DP, destinationId: "dest-gone", ok: true, runId: RUN(12), index: 12 });
      ok("a replicate-pass record for an unknown destination raises nothing", (await floorOf(r)) === null);

      // A default-routed run records no destination id, so a run that began before the default moved may
      // have sealed to the previous default. It must not raise the new default's floor.
      await inFlight(r, DP, 13, new Date(Date.now() - 60_000).toISOString());
      await doCall(r, "POST", "/destinations/default", { id: y }, OWNER_CALLER);
      await complete(r, DP, 13);
      // The default is now y, so the no-id read answers y's floor; the env key is checked in the map below.
      ok("a default-routed run that began before the default moved raises nothing", (await floorOf(r, y)) === 11 && (await floorOf(r)) === 11);
      await inFlight(r, DP, 14, new Date(Date.now() + 1000).toISOString());
      await complete(r, DP, 14);
      ok("a default-routed run that began after the move raises the new default's floor", (await floorOf(r)) === 14 && (await floorOf(r, y)) === 14);
      const map = ((await r.storage.get(RUNLOG_FLOOR_KEY)) as Record<string, { index: number }> | undefined) ?? {};
      ok("the env key was never raised by any of the above", map[ENV_FLOOR_KEY] === undefined);
    }
  } finally {
    globalThis.fetch = realFetch;
  }

  console.log(failures === 0 ? "\nRUNLOG FLOOR PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
