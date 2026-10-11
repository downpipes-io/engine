// A signer re-key hands every destination RUNLOG over from the old key to the new one, and never launders.
//
// Each destination's _RECOVERY/RUNLOG is signed under the OLD signer. After a re-key the engine signs under
// the new one, and it must not re-sign a RUNLOG it has not verified. So POST /admin/keys/install with a
// confirmed re-key (admin/rekey-runlog-handover.ts, seal/runlog-handover.ts, sched/rekey-handover.ts):
//   1. holds the OLD PUBLIC key and new run allocations, and verifies every destination RUNLOG under the old
//      key. Any failure stops the re-key BEFORE a secret is written, and names the destination;
//   2. installs the secrets;
//   3. signs, under the new key, the exact bytes of each RUNLOG that still verifies under the held old key.
//      With nothing pending the held key is discarded and an audit row says so.
// A destination left pending is handed over later under the held key, and a RUNLOG that verifies under
// neither key is never signed.
//
// This validator drives the real route (handleAdmin + SchedulerDO, an in-memory R2 binding and a Cloudflare
// secrets double), and the per-destination functions on in-memory buckets.
//
// Run: node test/validate-rekey-runlog-handover.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { handleAdmin } from "../src/admin/router.ts";
import { buildSupportBundle } from "../src/admin/support.ts";
import { b64urlDecode, b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { type HybridVerifier, hybridVerify } from "../src/crypto/sign.ts";
import { buildDestination } from "../src/dest/factory.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import { parseRunlog, type RunlogEntry, signRunlog } from "../src/format/writer.ts";
import { SchedulerDO } from "../src/index.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { decodeVerifier, encodeVerifier } from "../src/sched/rekey-handover.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { handOverRunlog } from "../src/seal/runlog-handover.ts";
import { memoryBucket } from "./lib/memory-r2.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const TOKEN = "cfat-rekey-handover-test-token-0123456789";
const ACCOUNT = "acct-rekey";
const SCRIPT = "downpipe-engine";
const ADMIN = "rekey-handover-route-token";
const DP = "dp_rekey";
const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FD${n}`;

const signerB64 = (): string => b64urlEncode(concat(rand(32), rand(32)));
function recipientPub(): string {
  const xk = x25519.keygen();
  return b64urlEncode(concat(xk.publicKey, mlkemKeygen(rand(64)).encapKey));
}
function configKeys(): { configRecipientPublic: string; configRecipientPrivate: string; configWrapKey: string } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { configRecipientPublic: b64urlEncode(concat(xk.publicKey, mlkemKeygen(seed).encapKey)), configRecipientPrivate: b64urlEncode(concat(xk.secretKey, seed)), configWrapKey: b64urlEncode(rand(32)) };
}
const entry = (n: number, prev: string | null): RunlogEntry => ({ index: n, runId: R(n), downpipeId: DP, time: `2026-10-01T0${n}:00:00.000Z`, recordCount: 1, prevRunId: prev, status: "active" });

// The Cloudflare secrets endpoint: PUT binds a secret, DELETE unbinds it. refusePut makes one PUT fail.
function cfSecrets(initial: Record<string, string>, refusePut?: string): { fetch: typeof fetch; bound: Map<string, string>; log: string[] } {
  const bound = new Map(Object.entries(initial));
  const log: string[] = [];
  const base = `/accounts/${ACCOUNT}/workers/scripts/${SCRIPT}/secrets`;
  const f = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "PUT" && url.endsWith(base)) {
      const body = JSON.parse(String(init?.body ?? "{}")) as { name?: string; text?: string };
      log.push(`PUT ${body.name}`);
      if (body.name === refusePut) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
      bound.set(body.name ?? "", body.text ?? "");
      return new Response(JSON.stringify({ success: true, result: { name: body.name } }), { status: 200 });
    }
    const del = new RegExp(`${base}/([A-Z_]+)$`).exec(url);
    if (method === "DELETE" && del) {
      log.push(`DELETE ${del[1]}`);
      bound.delete(del[1] as string);
      return new Response(JSON.stringify({ success: true, result: null }), { status: 200 });
    }
    log.push(`UNEXPECTED ${method} ${url}`);
    return new Response(JSON.stringify({ success: false, errors: [{ code: 0, message: "unexpected" }] }), { status: 500 });
  }) as typeof fetch;
  return { fetch: f, bound, log };
}

interface Estate {
  env: Env;
  dobj: SchedulerDO;
  store: Map<string, Uint8Array>;
  dest: Destination;
}
async function estate(oldSigner: string): Promise<Estate> {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
  const { bucket, store } = memoryBucket();
  const env = { SCHEDULER: { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace, ADMIN_TOKEN: ADMIN, WORKER_NAME: SCRIPT, CF_ACCOUNT_ID: ACCOUNT, DEST_KIND: "r2", DEST_R2: bucket, SIGNER_PRIVATE: oldSigner, BREAK_GLASS_PUBLIC: recipientPub() } as unknown as Env;
  const dest = await buildDestination(env);
  const s = await loadSigner(oldSigner);
  await appendRunlog(dest, s, entry(1, null));
  await appendRunlog(dest, s, entry(2, R(1)));
  return { env, dobj, store, dest };
}

async function sigVerifies(store: Map<string, Uint8Array>, v: HybridVerifier): Promise<boolean> {
  const body = store.get(RUNLOG);
  const sig = store.get(RUNLOG_SIG);
  if (!body || !sig) return false;
  try {
    return await hybridVerify(v, body, b64urlDecode(new TextDecoder().decode(sig).trim()));
  } catch {
    return false;
  }
}

interface Drive {
  status: number;
  body: Record<string, unknown>;
  audit: Array<{ action?: string; outcome?: string; target?: Record<string, unknown> }>;
}
async function install(e: Estate, cf: ReturnType<typeof cfSecrets>, newSigner: string): Promise<Drive> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = cf.fetch;
  try {
    const body = { token: TOKEN, signerPrivate: newSigner, breakGlassPublic: recipientPub(), ...configKeys(), confirmRekey: true };
    const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", { method: "POST", headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" }, body: JSON.stringify(body) }), e.env);
    const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { headers: { authorization: `Bearer ${ADMIN}` } }), e.env);
    const audit = ((await auditResp.json()) as { events?: Drive["audit"] }).events ?? [];
    return { status: resp.status, body: (await resp.json().catch(() => ({}))) as Record<string, unknown>, audit };
  } finally {
    globalThis.fetch = realFetch;
  }
}
// packOf builds the real support bundle for the estate, with every outbound fetch refused (the pack reads the DO).
async function packOf(e: Estate): Promise<Record<string, unknown>> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => new Response("offline", { status: 503 })) as typeof fetch;
  try {
    return await buildSupportBundle(e.env, e.env.SCHEDULER.get(e.env.SCHEDULER.idFromName("scheduler")));
  } finally {
    globalThis.fetch = realFetch;
  }
}
function runlogAnomaliesIn(pack: Record<string, unknown>, downpipeId: string): Array<{ kind?: string; indexA?: number; indexB?: number; digest?: string; entryCount?: number }> {
  const f = (pack.integrityFaults ?? {}) as Record<string, { runlogAnomalies?: Array<{ kind?: string }> }>;
  return f[downpipeId]?.runlogAnomalies ?? [];
}
async function handoverRecord(e: Estate): Promise<{ open?: boolean; pending?: string[]; oldVerifier?: unknown }> {
  return (await (await e.dobj.fetch(new Request("https://scheduler.internal/rekey-handover"))).json()) as { open?: boolean; pending?: string[]; oldVerifier?: unknown };
}

async function main(): Promise<void> {
  console.log("-- 1. a re-key over a clean RUNLOG hands it over, then discards the held key --");
  {
    const oldSigner = signerB64();
    const newSigner = signerB64();
    const oldV = verifierFrom(await loadSigner(oldSigner));
    const newV = verifierFrom(await loadSigner(newSigner));
    const e = await estate(oldSigner);
    const before = e.store.get(RUNLOG)!.slice();
    ok("CONTROL: before the re-key the RUNLOG verifies under the old key only", (await sigVerifies(e.store, oldV)) && !(await sigVerifies(e.store, newV)));
    const cf = cfSecrets({ SIGNER_PRIVATE: oldSigner });
    const r = await install(e, cf, newSigner);
    ok(`the confirmed re-key returns 200 (got ${r.status})`, r.status === 200, r.body);
    ok("the new signer is installed", cf.bound.get("SIGNER_PRIVATE") === newSigner);
    const h = r.body.runlogHandover as { outcomes?: Array<{ id: string; outcome: string }>; pending?: string[]; heldKeyDiscarded?: boolean } | undefined;
    ok("the response reports the RUNLOG re-signed, none pending, and the held key discarded", h?.outcomes?.length === 1 && h.outcomes[0]?.outcome === "re-signed" && h.pending?.length === 0 && h.heldKeyDiscarded === true, h);
    ok("the RUNLOG now verifies under the NEW key", await sigVerifies(e.store, newV));
    const after = e.store.get(RUNLOG)!;
    ok("the RUNLOG bytes are unchanged (only the signature moved)", before.length === after.length && before.every((b, i) => b === after[i]));
    ok("the audit has a runlog-handover row with one re-signed", r.audit.some((a) => a.action === "runlog-handover" && a.target?.op === "handover" && a.target.resigned === 1 && a.target.pending === 0));
    ok("the audit records that the held old key was discarded", r.audit.some((a) => a.action === "runlog-handover" && a.target?.op === "held-key-discarded"));
    ok("the DO holds no old key after the hand-over", (await handoverRecord(e)).open === false);
  }

  console.log("\n-- 2. a RUNLOG changed in the bucket stops the re-key before any secret is written --");
  {
    const oldSigner = signerB64();
    const newSigner = signerB64();
    const oldV = verifierFrom(await loadSigner(oldSigner));
    const newV = verifierFrom(await loadSigner(newSigner));
    const e = await estate(oldSigner);
    const changed = parseRunlog(e.store.get(RUNLOG)!).map((x) => (x.runId === R(1) ? { ...x, recordCount: 999 } : x));
    const s = await loadSigner(oldSigner);
    await e.dest.put(RUNLOG, (await signRunlog(changed, s.edPrivate, s.mldsaSecret)).runlog); // the serialiser only; the old .sig stays
    const tampered = e.store.get(RUNLOG)!.slice();
    const cf = cfSecrets({ SIGNER_PRIVATE: oldSigner });
    const r = await install(e, cf, newSigner);
    ok(`the re-key is refused with 409 (got ${r.status})`, r.status === 409, r.body);
    ok("no secret was written (no PUT reached Cloudflare)", cf.log.length === 0 && cf.bound.get("SIGNER_PRIVATE") === oldSigner, cf.log);
    ok("the refusal names the destination and the reason", /deploy-time destination: sig-invalid/.test(String(r.body.error ?? "")), r.body);
    ok("the changed RUNLOG was NOT re-signed under either key", !(await sigVerifies(e.store, oldV)) && !(await sigVerifies(e.store, newV)));
    ok("the changed bytes are left as they were", e.store.get(RUNLOG)!.every((b, i) => b === tampered[i]));
    ok("the audit records the refused hand-over with the destination and reason", r.audit.some((a) => a.action === "runlog-handover" && a.outcome === "failed" && a.target?.op === "handover-refused" && JSON.stringify(a.target.reasons) === '["sig-invalid"]'));
    ok("the DO holds no old key and holds no allocation", (await handoverRecord(e)).open === false);
    ok("CONTROL: a signature refusal posts no chain-anomaly row, so the pack has none for this downpipe", runlogAnomaliesIn(await packOf(e), DP).length === 0);
  }

  console.log("\n-- 2b. a validly signed RUNLOG with a chain anomaly stops the re-key, and the pack names the anomaly --");
  {
    const oldSigner = signerB64();
    const newSigner = signerB64();
    const oldV = verifierFrom(await loadSigner(oldSigner));
    const e = await estate(oldSigner);
    // The plant: entry 2's predecessor is a run that is not in the RUNLOG, signed under
    // the old key, so the signature and the parse pass and only the chain check refuses.
    const s = await loadSigner(oldSigner);
    const planted = await signRunlog([entry(1, null), entry(2, R(9))], s.edPrivate, s.mldsaSecret);
    await e.dest.put(RUNLOG, planted.runlog);
    await e.dest.put(RUNLOG_SIG, new TextEncoder().encode(b64urlEncode(planted.sig)));
    await e.dest.delete("_RECOVERY/RUNLOG.sig.pending");
    ok("CONTROL: the planted RUNLOG verifies under the old key", await sigVerifies(e.store, oldV));
    ok("CONTROL: before the re-key the pack has no RUNLOG anomaly for the downpipe", runlogAnomaliesIn(await packOf(e), DP).length === 0);
    const cf = cfSecrets({ SIGNER_PRIVATE: oldSigner });
    const r = await install(e, cf, newSigner);
    ok(`the re-key is refused with 409 (got ${r.status})`, r.status === 409, r.body);
    ok("the refusal names the chain anomaly", /deploy-time destination: chain-anomaly/.test(String(r.body.error ?? "")), r.body);
    ok("no secret was written", cf.log.length === 0 && cf.bound.get("SIGNER_PRIVATE") === oldSigner, cf.log);
    const pack = await packOf(e);
    const rows = runlogAnomaliesIn(pack, DP);
    // Entry 2 does not chain to entry 1, so the linearity check (run before the dangling check) names a chain-break.
    ok("the pack names the refused re-key's anomaly: integrityFaults carries a chain-break row for the downpipe", rows.some((a) => a.kind === "chain-break" && a.indexA === 1 && a.indexB === 2), pack.integrityFaults);
    ok("the row carries the entry count and a 12-hex RUNLOG digest", rows.some((a) => a.kind === "chain-break" && a.entryCount === 2 && /^[0-9a-f]{12}$/.test(a.digest ?? "")), rows);
    const text = JSON.stringify(pack);
    ok("the pack carries no run id from the anomaly's reason text", !text.includes(R(9)) && !text.includes(R(2)));
  }

  console.log("\n-- 3. an install that fails AFTER the signer PUT still hands over under the new key --");
  {
    const oldSigner = signerB64();
    const newSigner = signerB64();
    const newV = verifierFrom(await loadSigner(newSigner));
    const e = await estate(oldSigner);
    const cf = cfSecrets({ SIGNER_PRIVATE: oldSigner }, "BREAK_GLASS_PUBLIC");
    const r = await install(e, cf, newSigner);
    ok(`the install fails with 400 (got ${r.status})`, r.status === 400);
    ok("the signer PUT landed before the failure", cf.bound.get("SIGNER_PRIVATE") === newSigner);
    ok("the RUNLOG was handed over to the signer now installed", await sigVerifies(e.store, newV));
    ok("the held key was discarded", (await handoverRecord(e)).open === false && r.audit.some((a) => a.target?.op === "held-key-discarded"));
  }

  console.log("\n-- 4. an install that fails AT the signer PUT changes nothing --");
  {
    const oldSigner = signerB64();
    const newSigner = signerB64();
    const oldV = verifierFrom(await loadSigner(oldSigner));
    const e = await estate(oldSigner);
    const cf = cfSecrets({ SIGNER_PRIVATE: oldSigner }, "SIGNER_PRIVATE");
    const r = await install(e, cf, newSigner);
    ok(`the install fails with 400 (got ${r.status})`, r.status === 400);
    ok("the RUNLOG is still signed under the old (still installed) key", (await sigVerifies(e.store, oldV)) && cf.bound.get("SIGNER_PRIVATE") === oldSigner);
    ok("the hand-over record was dropped", (await handoverRecord(e)).open === false);
  }

  console.log("\n-- 5. the hold on new runs, and a destination left pending under the held key --");
  {
    const oldSigner = signerB64();
    const newSigner = signerB64();
    const oldS = await loadSigner(oldSigner);
    const newS = await loadSigner(newSigner);
    const oldV = verifierFrom(oldS);
    const newV = verifierFrom(newS);
    const e = await estate(oldSigner);
    const call = async (method: string, path: string, body?: unknown): Promise<Response> => e.dobj.fetch(new Request(`https://scheduler.internal${path}`, { method, headers: { "content-type": "application/json" }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
    const add = await call("POST", "/downpipes", { id: DP, name: DP, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_ns", namespaceId: "ns", include: [], exclude: [] } });
    ok("CONTROL: a downpipe is registered", add.ok);
    await call("POST", "/rekey-handover/begin", { oldVerifier: encodeVerifier(oldV) });
    const held = (await (await call("POST", "/trigger", { id: DP })).json()) as { skipped?: string; index?: number };
    ok("while the re-key is open, a new run is held with a named reason", typeof held.skipped === "string" && /re-key/.test(held.skipped), held);
    ok("a second re-key over an open one is refused", (await call("POST", "/rekey-handover/begin", { oldVerifier: encodeVerifier(oldV) })).status === 409);
    const settle = (await (await call("POST", "/rekey-handover/settle", { pending: ["dest_late"] })).json()) as { discarded?: boolean };
    ok("with a destination pending, the old public key stays held", settle.discarded === false && (await handoverRecord(e)).pending?.[0] === "dest_late");
    const t2 = (await (await call("POST", "/trigger", { id: DP })).json()) as { skipped?: string; index?: number };
    ok("once the pass has run, new runs are no longer held", typeof t2.index === "number", t2);

    // The pending destination: a seal on the OLD Worker version wrote to it after the pass.
    // An old-version Worker has no verify-before-write, so it re-signs under the old key whatever it finds;
    // this writes that outcome directly.
    const late = new MemoryDestination();
    await appendRunlog(late, newS, entry(1, null));
    const lateSigned = await signRunlog([entry(1, null), entry(2, R(1))], oldS.edPrivate, oldS.mldsaSecret);
    await late.put(RUNLOG, lateSigned.runlog);
    await late.put(RUNLOG_SIG, new TextEncoder().encode(b64urlEncode(lateSigned.sig)));
    await late.delete("_RECOVERY/RUNLOG.sig.pending");
    ok("CONTROL: the late RUNLOG verifies under the old key, not the new", (await sigVerifies(late.entries(), oldV)) && !(await sigVerifies(late.entries(), newV)));
    const heldV = decodeVerifier((await handoverRecord(e)).oldVerifier);
    ok("the held record carries the old PUBLIC key, which decodes to the outgoing verifier", heldV !== null && b64urlEncode(heldV.ed) === b64urlEncode(oldV.ed));
    ok("later, the held key hands the late destination over", heldV !== null && (await handOverRunlog(late, heldV, newS)) === "re-signed" && (await sigVerifies(late.entries(), newV)));

    // A RUNLOG changed in the bucket while pending: neither key verifies it, so it is never signed.
    const bad = new MemoryDestination();
    await appendRunlog(bad, oldS, entry(1, null));
    const changed = parseRunlog((await bad.get(RUNLOG))!.body).map((x) => ({ ...x, recordCount: 999 }));
    await bad.put(RUNLOG, (await signRunlog(changed, oldS.edPrivate, oldS.mldsaSecret)).runlog);
    ok("a changed RUNLOG stays pending under the held key (for the attended re-sign), never signed", heldV !== null && (await handOverRunlog(bad, heldV, newS)) === "pending" && !(await sigVerifies(bad.entries(), newV)) && !(await sigVerifies(bad.entries(), oldV)));
    // A settle body that does not parse, or that is not a list of destination ids, is refused and closes
    // nothing: read as "nothing pending" it would drop the held key while destinations still wait.
    const raw = await e.dobj.fetch(new Request("https://scheduler.internal/rekey-handover/settle", { method: "POST", headers: { "content-type": "application/json" }, body: "not json" }));
    ok(`a settle body that does not parse is refused 400 (got ${raw.status})`, raw.status === 400);
    const noList = await call("POST", "/rekey-handover/settle", {});
    ok(`a settle with no pending list is refused 400 (got ${noList.status})`, noList.status === 400);
    const mixed = await call("POST", "/rekey-handover/settle", { pending: ["dest_late", 7] });
    ok(`a pending list that is not all destination ids is refused 400 (got ${mixed.status})`, mixed.status === 400);
    ok("...and none of them closed the hand-over or dropped the held key", (await handoverRecord(e)).open === true);
    const done = (await (await call("POST", "/rekey-handover/settle", { pending: [] })).json()) as { discarded?: boolean };
    ok("when nothing is pending the held key is discarded", done.discarded === true && (await handoverRecord(e)).open === false);
  }

  console.log("\n-- 6. a re-key over a signer that does not load skips the hand-over and signs nothing --");
  {
    const oldSigner = signerB64();
    const newSigner = signerB64();
    const oldV = verifierFrom(await loadSigner(oldSigner));
    const newV = verifierFrom(await loadSigner(newSigner));
    const e = await estate(oldSigner);
    (e.env as unknown as Record<string, string>).SIGNER_PRIVATE = "a-corrupt-signer-that-does-not-load";
    const cf = cfSecrets({ SIGNER_PRIVATE: "a-corrupt-signer-that-does-not-load" });
    const r = await install(e, cf, newSigner);
    const h = r.body.runlogHandover as { skipped?: string } | undefined;
    ok(`the repair re-key proceeds (got ${r.status}) and reports the hand-over skipped`, r.status === 200 && h?.skipped === "outgoing-signer-unreadable", r.body);
    ok("the RUNLOG was not signed under the new key (it waits for the attended re-sign)", (await sigVerifies(e.store, oldV)) && !(await sigVerifies(e.store, newV)));
    ok("no old key is held", (await handoverRecord(e)).open === false);
  }

  console.log("\n-- 7. CONTROL: an install with no re-key does not run a hand-over --");
  {
    const newSigner = signerB64();
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
    const { bucket } = memoryBucket();
    const env = { SCHEDULER: { idFromName: () => ({}), get: () => stub } as unknown as DurableObjectNamespace, ADMIN_TOKEN: ADMIN, WORKER_NAME: SCRIPT, CF_ACCOUNT_ID: ACCOUNT, DEST_KIND: "r2", DEST_R2: bucket } as unknown as Env;
    const cf = cfSecrets({});
    const r = await install({ env, dobj, store: new Map(), dest: await buildDestination(env) }, cf, newSigner);
    ok(`a first install returns 200 with no hand-over (got ${r.status})`, r.status === 200 && r.body.runlogHandover === undefined, r.body);
  }

  console.log("\n-- 8. the support pack's configEvents names a re-key's hand-over and a refused re-key --");
  {
    // packEvents builds the real support bundle (outbound fetches refused) and returns its runlog-handover rows.
    const packEvents = async (e: Estate): Promise<Array<Record<string, unknown>>> => {
      const realFetch = globalThis.fetch;
      globalThis.fetch = (async () => new Response("offline", { status: 503 })) as typeof fetch;
      try {
        const pack = await buildSupportBundle(e.env, e.env.SCHEDULER.get(e.env.SCHEDULER.idFromName("scheduler")));
        return ((pack.configEvents ?? []) as Array<Record<string, unknown>>).filter((c) => c.action === "runlog-handover");
      } finally {
        globalThis.fetch = realFetch;
      }
    };
    const ok1 = await estate(signerB64());
    ok("CONTROL: before any re-key the pack has no runlog-handover row", (await packEvents(ok1)).length === 0);
    const oldSigner = signerB64();
    const done = await estate(oldSigner);
    await install(done, cfSecrets({ SIGNER_PRIVATE: oldSigner }), signerB64());
    const ev = await packEvents(done);
    ok("a completed hand-over: the pack has runlogOp handover with 1 re-signed and 0 pending", ev.some((c) => c.runlogOp === "handover" && c.resigned === 1 && c.pending === 0), ev);
    ok("...and runlogOp held-key-discarded", ev.some((c) => c.runlogOp === "held-key-discarded"), ev);
    const refusedSigner = signerB64();
    const refused = await estate(refusedSigner);
    const s = await loadSigner(refusedSigner);
    const changed = parseRunlog(refused.store.get(RUNLOG)!).map((x) => (x.runId === R(1) ? { ...x, recordCount: 999 } : x));
    await refused.dest.put(RUNLOG, (await signRunlog(changed, s.edPrivate, s.mldsaSecret)).runlog);
    await install(refused, cfSecrets({ SIGNER_PRIVATE: refusedSigner }), signerB64());
    const rv = await packEvents(refused);
    ok("a refused re-key: the pack has runlogOp handover-refused with reasons sig-invalid", rv.some((c) => c.runlogOp === "handover-refused" && JSON.stringify(c.reasons) === '["sig-invalid"]'), rv);
    ok("the pack rows carry no destination id or digest", [...ev, ...rv].every((c) => !("destinationIds" in c) && !("digest" in c)), [...ev, ...rv]);
  }

  console.log(failures === 0 ? "\nREKEY RUNLOG HANDOVER PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
