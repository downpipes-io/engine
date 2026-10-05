// Validates that a strict break-glass-only choice leaves the engine holding nothing that can decrypt a run.
//
// THE DEFECT THIS PINS. A key re-key that deliberately omits the operational pair (the strict choice on the
// Keys screen) went through installEngineSecrets, which set the OPERATIONAL_RETIRED marker and left an
// existing OPERATIONAL_PUBLIC and OPERATIONAL_PRIVATE bound. The seal paths read OPERATIONAL_PUBLIC with no
// marker check, so every run sealed after the strict re-key still carried the old operational recipient, and
// the engine still held the private that opens it. POST /admin/keys/break-glass-only (removeOperationalSecrets)
// always set the marker AND deleted both secrets; the strict install now runs that same function.
//
// An estate the old install already left in that state (marker bound, pair bound) cannot be repaired by the
// engine alone: it holds no Cloudflare token that can delete its own secrets. So the engine now honours the
// marker over a bound pair: it seals to break-glass alone, opens no run with the operational private, and
// reports the stale pair (status, posture, support pack) until the break-glass-only switch deletes it.
//
// HOW IT WAS MISSED. validate-keys-install.ts counted the strict install's PUTs over a stub that refused every
// DELETE and started from an estate with no operational pair, so it could not see what the install left bound.
// No test sealed a run after a strict re-key.
//
// WHAT THIS DRIVES, all on the real code:
//   1. installEngineSecrets over a STATEFUL Cloudflare secrets double (PUT binds, DELETE unbinds, a DELETE of an
//      unbound secret is a 404), from an estate that holds an operational pair, from a fresh estate, and with the
//      pair supplied (the control). addOperationalSecrets over the same double.
//   2. A run sealed with the env those secrets leave: the sliced seal (seal/runstate-helpers.ts sliceDepsFromEnv),
//      the buffered seal (seal/runstate.ts, SLICED_RUNS_DISABLED) and the canary flight (canary/cycle.ts). Each
//      root manifest's masterCapsule is read back through the signature-verifying reader and its recipient
//      fingerprints compared with the break-glass and operational publics.
//   3. The same seals on the stale estate the old install left (marker and pair both bound), and on an estate
//      with the pair and no marker (the control: both recipients, and the operational identity opens the run).
//   4. What the engine reports on each estate: buildStatus, the posture computed from the router's slice as the
//      scheduler DO parses it, and the support pack's keys section.
//   5. POST /admin/keys/install through the real handleAdmin and SchedulerDO: the audit rows a strict re-key
//      leaves, on success and when Cloudflare refuses a delete.
//
// Run: node test/validate-strict-rekey-removes-operational.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { addOperationalSecrets, installEngineSecrets, keyCeremonyFaultOf } from "../src/admin/attach.ts";
import { computePosture } from "../src/admin/posture.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { statusSliceForPosture } from "../src/admin/router-posture.ts";
import { buildStatus } from "../src/admin/status.ts";
import { buildKeysHealth } from "../src/admin/support-sections-config.ts";
import { runCanaryCycle } from "../src/canary/cycle.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { recipientFingerprint } from "../src/crypto/capsule.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { type ObjectStore, openRun, readRunCapsule } from "../src/format/reader.ts";
import { SchedulerDO } from "../src/index.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { sealRunSliced } from "../src/seal/runstate.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MockStorage } from "./mock-storage.ts";
import { healthyInput, NOW } from "./validate-posture-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---- key material: every pair is real, so fingerprints and opens are checked against the actual keys ----

interface RecipientPair {
  pub: string; // base64url x25519(32) || ML-KEM-1024 ek(1568)
  priv: string; // base64url x25519 scalar(32) || ML-KEM seed(64)
  fingerprint: string;
}
async function recipientPair(): Promise<RecipientPair> {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return { pub: b64urlEncode(concat(xk.publicKey, ek)), priv: b64urlEncode(concat(xk.secretKey, seed)), fingerprint: await recipientFingerprint(xk.publicKey, ek) };
}
const signerB64 = (): string => b64urlEncode(concat(rand(32), rand(32)));

const TOKEN = "cfat-strict-rekey-test-token-0123456789";
const ACCOUNT = "acct-strict";
const SCRIPT = "downpipe-engine";

// ---- a STATEFUL Cloudflare worker-secrets double -----------------------------------------------------------
//
// PUT .../secrets binds {name: text}; DELETE .../secrets/<name> unbinds it, and answers 404 when it is not
// bound (cf-api.ts deleteSecret reads a 404 as success). refuseDelete makes Cloudflare refuse one DELETE. The
// log records "PUT <name>" and "DELETE <name>" in call order.
interface CfDouble {
  fetch: typeof fetch;
  bound: Map<string, string>;
  log: string[];
}
function cfSecrets(initial: Record<string, string>, refuseDelete?: string): CfDouble {
  const bound = new Map(Object.entries(initial));
  const log: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const base = `/accounts/${ACCOUNT}/workers/scripts/${SCRIPT}/secrets`;
    if (method === "PUT" && url.endsWith(base)) {
      const body = JSON.parse(String(init?.body ?? "{}")) as { name?: string; text?: string };
      log.push(`PUT ${body.name}`);
      bound.set(body.name ?? "", body.text ?? "");
      return new Response(JSON.stringify({ success: true, result: { name: body.name } }), { status: 200 });
    }
    const del = new RegExp(`${base}/([A-Z_]+)$`).exec(url);
    if (method === "DELETE" && del) {
      const name = del[1] as string;
      log.push(`DELETE ${name}`);
      if (name === refuseDelete) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
      if (!bound.has(name)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10007, message: "not found" }] }), { status: 404 });
      bound.delete(name);
      return new Response(JSON.stringify({ success: true, result: null }), { status: 200 });
    }
    log.push(`UNEXPECTED ${method} ${url}`);
    return new Response(JSON.stringify({ success: false, errors: [{ code: 0, message: "unexpected" }] }), { status: 500 });
  }) as typeof fetch;
  return { fetch: fetchImpl, bound, log };
}

// configKeys is the configuration key set every install carries (a matched recovery pair and a wrap key).
function configKeys(): { configRecipientPublic: string; configRecipientPrivate: string; configWrapKey: string } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return {
    configRecipientPublic: b64urlEncode(concat(xk.publicKey, mlkemKeygen(seed).encapKey)),
    configRecipientPrivate: b64urlEncode(concat(xk.secretKey, seed)),
    configWrapKey: b64urlEncode(rand(32)),
  };
}

// ---- an in-memory R2 binding: the surface the R2 destination adapter uses, conditional puts included ----------
function memoryBucket(): { bucket: Record<string, unknown>; store: Map<string, Uint8Array> } {
  const store = new Map<string, Uint8Array>();
  const tags = new Map<string, string>();
  let seq = 0;
  const drain = async (body: unknown): Promise<Uint8Array> => {
    if (body instanceof Uint8Array) return body;
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (typeof body === "string") return new TextEncoder().encode(body);
    const reader = (body as ReadableStream<Uint8Array>).getReader();
    const parts: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    return concat(...parts);
  };
  const objectFor = (key: string, bytes: Uint8Array): Record<string, unknown> => ({
    key,
    size: bytes.length,
    etag: tags.get(key) ?? "e0",
    httpEtag: `"${tags.get(key) ?? "e0"}"`,
    uploaded: new Date(0),
    arrayBuffer: async () => bytes.slice().buffer,
    body: new ReadableStream<Uint8Array>({
      start(c): void {
        c.enqueue(bytes);
        c.close();
      },
    }),
  });
  const bucket = {
    put: async (key: string, body: unknown, opts?: { onlyIf?: { etagMatches?: string; etagDoesNotMatch?: string } }): Promise<Record<string, unknown> | null> => {
      const bytes = await drain(body);
      const cur = tags.get(key);
      if (opts?.onlyIf?.etagDoesNotMatch !== undefined && (opts.onlyIf.etagDoesNotMatch === "*" ? cur !== undefined : cur === opts.onlyIf.etagDoesNotMatch)) return null;
      if (opts?.onlyIf?.etagMatches !== undefined && cur !== opts.onlyIf.etagMatches) return null;
      store.set(key, bytes);
      tags.set(key, `e${++seq}`);
      return objectFor(key, bytes);
    },
    get: async (key: string): Promise<Record<string, unknown> | null> => {
      const v = store.get(key);
      return v ? objectFor(key, v) : null;
    },
    head: async (key: string): Promise<Record<string, unknown> | null> => {
      const v = store.get(key);
      return v ? objectFor(key, v) : null;
    },
    delete: async (keys: string | string[]): Promise<void> => {
      for (const k of Array.isArray(keys) ? keys : [keys]) {
        store.delete(k);
        tags.delete(k);
      }
    },
    list: async (opts?: { prefix?: string }): Promise<{ objects: Array<Record<string, unknown>>; truncated: false; delimitedPrefixes: string[] }> => {
      const prefix = opts?.prefix ?? "";
      return { objects: [...store.entries()].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => objectFor(k, v)), truncated: false, delimitedPrefixes: [] };
    },
  };
  return { bucket, store };
}

// A KV namespace double holding a few records, enough for a run to seal real content.
function memoryKV(): Record<string, unknown> {
  const seeds = Array.from({ length: 6 }, (_, i) => ({ name: `k${i}`, value: rand(64) }));
  return {
    list: async () => ({ keys: seeds.map((s) => ({ name: s.name })), list_complete: true, cacheStatus: null }),
    getWithMetadata: async (key: string) => {
      const s = seeds.find((x) => x.name === key);
      if (!s) return { value: null, metadata: null, cacheStatus: null };
      return { value: s.value.slice().buffer, metadata: null, cacheStatus: null };
    },
  };
}

// The scheduler DO double the seal path talks to: it records /complete and grants the heartbeat.
function schedulerDouble(): { stub: DurableObjectStub; completions: Array<Record<string, unknown>> } {
  const completions: Array<Record<string, unknown>> = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : undefined;
      if (url.pathname === "/complete" && body !== undefined) completions.push(body);
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: true }));
      if (url.pathname === "/runlog-lock/acquire") return new Response(JSON.stringify({ acquired: false }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, completions };
}
const nsFor = (stub: DurableObjectStub): DurableObjectNamespace => ({ idFromName: () => ({}) as DurableObjectId, get: () => stub }) as unknown as DurableObjectNamespace;

class MapStore implements ObjectStore {
  private readonly map: Map<string, Uint8Array>;
  private readonly prefix: string;
  constructor(map: Map<string, Uint8Array>, prefix = "") {
    this.map = map;
    this.prefix = prefix;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(this.prefix + key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
}

// KEY_NAMES are the worker secrets a seal reads. envFromBound copies exactly those the Cloudflare double holds,
// so the seal sees the env the install actually left.
const KEY_NAMES = ["SIGNER_PRIVATE", "BREAK_GLASS_PUBLIC", "OPERATIONAL_PUBLIC", "OPERATIONAL_PRIVATE", "OPERATIONAL_RETIRED"] as const;
function envFromBound(bound: Map<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const n of KEY_NAMES) {
    const v = bound.get(n);
    if (v !== undefined) out[n] = v;
  }
  return out;
}

const dpState = (id: string): DownpipeState =>
  ({
    config: { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_TEST", namespaceId: "ns1", include: [], exclude: [] } },
    nextRunAt: 0,
    lastRunId: null,
    inFlight: true,
    inFlightSince: Date.now(),
  }) as DownpipeState;

interface SealOutcome {
  status: string | undefined;
  fingerprints: string[];
  verifiedVia: string | undefined;
  opened: (identityB64: string) => Promise<boolean>;
}

// sealWith seals one run through sealRunSliced with the given key env. buffered selects the v1 buffered seal
// (runstate.ts) instead of the sliced one (runstate-helpers.ts).
async function sealWith(keys: Record<string, string>, runId: string, buffered: boolean): Promise<SealOutcome> {
  const { bucket, store } = memoryBucket();
  const sched = schedulerDouble();
  const runseal = schedulerDouble();
  const env = {
    SCHEDULER: nsFor(sched.stub),
    RUNSEAL: nsFor(runseal.stub),
    DEST_KIND: "r2",
    DEST_R2: bucket,
    KV_TEST: memoryKV(),
    ...(buffered ? { SLICED_RUNS_DISABLED: "1" } : {}),
    ...keys,
  } as unknown as Env;
  await sealRunSliced(env, dpState(buffered ? "dp-buffered" : "dp-sliced"), { runId, index: 1, prevRunId: null }, { budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }) });
  const complete = sched.completions[0] as { status?: string; sealVerification?: { status?: string; via?: string } } | undefined;
  const verifier = verifierFrom(await loadSigner(keys.SIGNER_PRIVATE as string));
  let fingerprints: string[] = [];
  try {
    fingerprints = (await readRunCapsule(new MapStore(store), runId, verifier)).masterCapsule.map((w) => w.fingerprint);
  } catch {
    fingerprints = [];
  }
  return {
    status: complete?.status,
    fingerprints,
    verifiedVia: complete?.sealVerification?.status === "verified" ? complete.sealVerification.via ?? "tier-0" : undefined,
    opened: async (identityB64: string) => {
      try {
        const run = await openRun(new MapStore(store), runId, parseIdentity(Buffer.from(identityB64, "base64url")), verifier, {});
        return run.records.length > 0;
      } catch {
        return false;
      }
    },
  };
}

// canaryWith flies one canary with the given key env and reads its cell's capsule back.
async function canaryWith(keys: Record<string, string>, runId: string): Promise<{ status: string; fingerprints: string[] }> {
  const { bucket, store } = memoryBucket();
  const env = { DEST_KIND: "r2", DEST_R2: bucket, ...keys } as unknown as Env;
  const sched = { async fetch(): Promise<Response> { return new Response("{}", { status: 200, headers: { "content-type": "application/json" } }); } } as unknown as DurableObjectStub;
  const result = await runCanaryCycle(env, sched, { runId, runSeq: 1, destinationId: null, cleanupRunId: null });
  const verifier = verifierFrom(await loadSigner(keys.SIGNER_PRIVATE as string));
  let fingerprints: string[] = [];
  try {
    fingerprints = (await readRunCapsule(new MapStore(store, `_CANARY/runs/${runId}/`), runId, verifier)).masterCapsule.map((w) => w.fingerprint);
  } catch {
    fingerprints = [];
  }
  return { status: result.status, fingerprints };
}

const sameSet = (a: string[], b: string[]): boolean => a.length === b.length && [...a].sort().join(",") === [...b].sort().join(",");

// postureFor computes the posture from the router's env slice, parsed by the scheduler DO exactly as the
// POST /posture route parses it, over the shared healthy fixture.
function postureFor(env: Env): Map<string, { status: string; remediation?: string }> {
  const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState) as unknown as { parsePostureStatusSlice(raw: unknown): ReturnType<typeof healthyInput>["status"] };
  const parsed = dobj.parsePostureStatusSlice(JSON.parse(JSON.stringify(statusSliceForPosture(env, {}))));
  const base = healthyInput();
  const report = computePosture({ ...base, status: { ...base.status, ...parsed }, operationalPrivatePresent: parsed.operationalConfigured.private }, NOW);
  return new Map(report.checks.map((c) => [c.id, { status: c.status, ...(c.remediation !== undefined ? { remediation: c.remediation } : {}) }]));
}

// routeEnv is a real SchedulerDO-backed Env for the route cases (the audit append and the owner token path).
function routeEnv(adminToken: string, extra: Record<string, unknown>): Env {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
  return { SCHEDULER: nsFor(stub), ADMIN_TOKEN: adminToken, WORKER_NAME: SCRIPT, CF_ACCOUNT_ID: ACCOUNT, ...extra } as unknown as Env;
}

async function main(): Promise<void> {
  const oldBreakGlass = await recipientPair();
  const newBreakGlass = await recipientPair();
  const operational = await recipientPair();
  const freshOperational = await recipientPair();
  const oldSigner = signerB64();
  const newSigner = signerB64();

  // The estate before the re-key: two-recipient, as a console or terminal install leaves it.
  const twoRecipientEstate = (): Record<string, string> => ({ SIGNER_PRIVATE: oldSigner, BREAK_GLASS_PUBLIC: oldBreakGlass.pub, OPERATIONAL_PUBLIC: operational.pub, OPERATIONAL_PRIVATE: operational.priv });

  console.log("-- 1. a strict re-key over an estate that holds an operational pair --");
  const strict = cfSecrets(twoRecipientEstate());
  {
    const result = await installEngineSecrets(ACCOUNT, SCRIPT, { token: TOKEN, signerPrivate: newSigner, breakGlassPublic: newBreakGlass.pub, ...configKeys() }, strict.fetch);
    ok("the strict install returns operational: false", result.configured.operational === false);
    ok("OPERATIONAL_PRIVATE is no longer bound", !strict.bound.has("OPERATIONAL_PRIVATE"));
    ok("OPERATIONAL_PUBLIC is no longer bound", !strict.bound.has("OPERATIONAL_PUBLIC"));
    ok('the OPERATIONAL_RETIRED marker is bound, with the flag value "true"', strict.bound.get("OPERATIONAL_RETIRED") === "true");
    const at = (e: string): number => strict.log.indexOf(e);
    ok("the order is the break-glass-only switch's: marker PUT, then DELETE OPERATIONAL_PRIVATE, then DELETE OPERATIONAL_PUBLIC", at("PUT OPERATIONAL_RETIRED") >= 0 && at("PUT OPERATIONAL_RETIRED") < at("DELETE OPERATIONAL_PRIVATE") && at("DELETE OPERATIONAL_PRIVATE") < at("DELETE OPERATIONAL_PUBLIC"));
    ok("the removal runs after the new break-glass public is bound", at("PUT BREAK_GLASS_PUBLIC") < at("PUT OPERATIONAL_RETIRED"));
    ok("the new signer and break-glass public are bound", strict.bound.get("SIGNER_PRIVATE") === newSigner && strict.bound.get("BREAK_GLASS_PUBLIC") === newBreakGlass.pub);
    ok("no call went anywhere unexpected", !strict.log.some((l) => l.startsWith("UNEXPECTED")));
  }

  console.log("\n-- 2. a strict install on a fresh estate: deleting what is not bound is harmless --");
  {
    const fresh = cfSecrets({});
    let threw = "";
    try {
      await installEngineSecrets(ACCOUNT, SCRIPT, { token: TOKEN, signerPrivate: newSigner, breakGlassPublic: newBreakGlass.pub, ...configKeys() }, fresh.fetch);
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("the install succeeds although neither operational secret existed (both DELETEs were 404s)", threw === "" && fresh.log.includes("DELETE OPERATIONAL_PRIVATE") && fresh.log.includes("DELETE OPERATIONAL_PUBLIC"));
    ok("the marker is bound and no operational secret is", fresh.bound.get("OPERATIONAL_RETIRED") === "true" && !fresh.bound.has("OPERATIONAL_PUBLIC") && !fresh.bound.has("OPERATIONAL_PRIVATE"));
  }

  console.log("\n-- 3. CONTROL: a re-key that includes an operational pair keeps it and clears the marker --");
  const withPair = cfSecrets({ ...twoRecipientEstate(), OPERATIONAL_RETIRED: "true" });
  {
    const result = await installEngineSecrets(ACCOUNT, SCRIPT, { token: TOKEN, signerPrivate: newSigner, breakGlassPublic: newBreakGlass.pub, operationalPublic: freshOperational.pub, operationalPrivate: freshOperational.priv, ...configKeys() }, withPair.fetch);
    ok("the install returns operational: true", result.configured.operational === true);
    ok("the supplied operational pair is bound", withPair.bound.get("OPERATIONAL_PUBLIC") === freshOperational.pub && withPair.bound.get("OPERATIONAL_PRIVATE") === freshOperational.priv);
    ok("the OPERATIONAL_RETIRED marker is cleared", !withPair.bound.has("OPERATIONAL_RETIRED"));
    ok("neither operational secret was deleted", !withPair.log.includes("DELETE OPERATIONAL_PRIVATE") && !withPair.log.includes("DELETE OPERATIONAL_PUBLIC"));
    const at = (e: string): number => withPair.log.indexOf(e);
    ok("the marker is cleared BEFORE the pair is PUT, so a failed clear never leaves a pair beside it", at("DELETE OPERATIONAL_RETIRED") >= 0 && at("DELETE OPERATIONAL_RETIRED") < at("PUT OPERATIONAL_PUBLIC"));
  }

  console.log("\n-- 4. addOperationalSecrets: the marker is cleared first, and a refused clear sets no pair --");
  {
    const add = cfSecrets({ SIGNER_PRIVATE: oldSigner, BREAK_GLASS_PUBLIC: oldBreakGlass.pub, OPERATIONAL_RETIRED: "true" });
    await addOperationalSecrets(ACCOUNT, SCRIPT, TOKEN, freshOperational.pub, freshOperational.priv, add.fetch);
    ok("the add binds the pair and unbinds the marker", add.bound.get("OPERATIONAL_PRIVATE") === freshOperational.priv && !add.bound.has("OPERATIONAL_RETIRED"));
    ok("the marker DELETE is the first call", add.log[0] === "DELETE OPERATIONAL_RETIRED");
    const refused = cfSecrets({ SIGNER_PRIVATE: oldSigner, BREAK_GLASS_PUBLIC: oldBreakGlass.pub, OPERATIONAL_RETIRED: "true" }, "OPERATIONAL_RETIRED");
    let tag: ReturnType<typeof keyCeremonyFaultOf> = null;
    try {
      await addOperationalSecrets(ACCOUNT, SCRIPT, TOKEN, freshOperational.pub, freshOperational.priv, refused.fetch);
    } catch (e) {
      tag = keyCeremonyFaultOf(e);
    }
    ok("a refused marker clear fails the add, tagged operational-retired-marker / cf-delete", tag?.step === "operational-retired-marker" && tag.cause === "cf-delete");
    ok("...and no operational secret was PUT", !refused.log.some((l) => l.startsWith("PUT OPERATIONAL_P")));
  }

  console.log("\n-- 5. runs sealed after the strict re-key carry only the break-glass recipient --");
  const afterStrict = envFromBound(strict.bound);
  {
    const sliced = await sealWith(afterStrict, "01BX5ZZKBKACTAV9WEVGEMMVR1", false);
    ok("the sliced seal completes ok", sliced.status === "ok");
    ok("its masterCapsule names the new break-glass recipient only", sameSet(sliced.fingerprints, [newBreakGlass.fingerprint]));
    const buffered = await sealWith(afterStrict, "01BX5ZZKBKACTAV9WEVGEMMVR2", true);
    ok("the buffered seal completes ok", buffered.status === "ok");
    ok("its masterCapsule names the new break-glass recipient only", sameSet(buffered.fingerprints, [newBreakGlass.fingerprint]));
    ok("the old operational private opens neither run", !(await sliced.opened(operational.priv)) && !(await buffered.opened(operational.priv)));
    const canary = await canaryWith(afterStrict, "01BX5ZZKBKACTAV9WEVGEMMVR3");
    ok(`the canary flight is alive (got ${canary.status})`, canary.status === "alive");
    ok("the canary cell's masterCapsule names the new break-glass recipient only", sameSet(canary.fingerprints, [newBreakGlass.fingerprint]));
  }

  console.log("\n-- 6. the stale estate (marker AND pair bound, as the strict re-key used to leave it) --");
  const stale = { SIGNER_PRIVATE: newSigner, BREAK_GLASS_PUBLIC: newBreakGlass.pub, OPERATIONAL_PUBLIC: operational.pub, OPERATIONAL_PRIVATE: operational.priv, OPERATIONAL_RETIRED: "true" };
  {
    const sliced = await sealWith(stale, "01BX5ZZKBKACTAV9WEVGEMMVR4", false);
    ok("the sliced seal completes ok", sliced.status === "ok");
    ok("its masterCapsule names the break-glass recipient only, not the operational key still bound", sameSet(sliced.fingerprints, [newBreakGlass.fingerprint]));
    ok("verify-at-seal verified it through the run's own master, not the retired operational wrap", sliced.verifiedVia === "master");
    ok("the operational private still bound does not open it", !(await sliced.opened(operational.priv)));
    const buffered = await sealWith(stale, "01BX5ZZKBKACTAV9WEVGEMMVR5", true);
    ok("the buffered seal names the break-glass recipient only", buffered.status === "ok" && sameSet(buffered.fingerprints, [newBreakGlass.fingerprint]));
    const canary = await canaryWith(stale, "01BX5ZZKBKACTAV9WEVGEMMVR6");
    ok(`the canary flight is alive and its cell names break-glass only (got ${canary.status})`, canary.status === "alive" && sameSet(canary.fingerprints, [newBreakGlass.fingerprint]));
  }

  console.log("\n-- 7. CONTROL: a pair with no marker still seals to both, and the operational identity opens it --");
  const twoRecipient = { SIGNER_PRIVATE: newSigner, BREAK_GLASS_PUBLIC: newBreakGlass.pub, OPERATIONAL_PUBLIC: operational.pub, OPERATIONAL_PRIVATE: operational.priv };
  {
    const sliced = await sealWith(twoRecipient, "01BX5ZZKBKACTAV9WEVGEMMVR7", false);
    ok("its masterCapsule names break-glass AND operational", sliced.status === "ok" && sameSet(sliced.fingerprints, [newBreakGlass.fingerprint, operational.fingerprint]));
    ok("verify-at-seal opened it through the operational recipient wrap", sliced.verifiedVia === "recipient");
    ok("the operational private opens it", await sliced.opened(operational.priv));
    const canary = await canaryWith(twoRecipient, "01BX5ZZKBKACTAV9WEVGEMMVR8");
    ok("the canary cell names both recipients", canary.status === "alive" && sameSet(canary.fingerprints, [newBreakGlass.fingerprint, operational.fingerprint]));
  }

  console.log("\n-- 8. what the engine reports on each estate --");
  {
    const staleEnv = stale as unknown as Env;
    const status = buildStatus(staleEnv, 0) as unknown as { operationalRetired?: boolean; operationalConfigured: { public: boolean; private: boolean } };
    ok("status reports the break-glass-only choice beside the bound pair", status.operationalRetired === true && status.operationalConfigured.private === true);
    const posture = postureFor(staleEnv);
    const held = posture.get("operational-retired-key-held");
    ok(`the posture check operational-retired-key-held FAILS on the stale estate (got ${held?.status ?? "absent"})`, held?.status === "fail");
    ok("its remediation names the break-glass-only switch and its route", /break-glass only/.test(held?.remediation ?? "") && /POST \/admin\/keys\/break-glass-only/.test(held?.remediation ?? ""));
    const keys = (await buildKeysHealth(staleEnv)) as { operationalRetired?: { markerSet?: boolean; staleKeyHeld?: boolean } };
    ok("the support pack's keys section flags the stale key", keys.operationalRetired?.markerSet === true && keys.operationalRetired?.staleKeyHeld === true);

    const cleanEnv = afterStrict as unknown as Env;
    ok("after the strict re-key the check passes (the choice is fully applied)", postureFor(cleanEnv).get("operational-retired-key-held")?.status === "pass");
    const cleanKeys = (await buildKeysHealth(cleanEnv)) as { operationalRetired?: { markerSet?: boolean; staleKeyHeld?: boolean } };
    ok("...and the pack reports the marker with no stale key", cleanKeys.operationalRetired?.markerSet === true && cleanKeys.operationalRetired?.staleKeyHeld === false);
    ok("CONTROL: with no marker the check is not graded at all", !postureFor(twoRecipient as unknown as Env).has("operational-retired-key-held"));
  }

  console.log("\n-- 9. POST /admin/keys/install: the audit rows a strict re-key leaves --");
  {
    const ADMIN = "strict-rekey-route-token";
    const body = { token: TOKEN, signerPrivate: newSigner, breakGlassPublic: newBreakGlass.pub, ...configKeys(), confirmRekey: true };
    const drive = async (cf: CfDouble): Promise<{ status: number; audit: Array<{ action?: string; outcome?: string; target?: { step?: string } }> }> => {
      const env = routeEnv(ADMIN, twoRecipientEstate());
      const realFetch = globalThis.fetch;
      globalThis.fetch = cf.fetch;
      try {
        const resp = await handleAdmin(new Request("https://engine.example/admin/keys/install", { method: "POST", headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" }, body: JSON.stringify(body) }), env);
        const auditResp = await handleAdmin(new Request("https://engine.example/admin/audit?limit=50", { headers: { authorization: `Bearer ${ADMIN}` } }), env);
        const events = ((await auditResp.json()) as { events?: Array<{ action?: string; outcome?: string; target?: { step?: string } }> }).events ?? [];
        return { status: resp.status, audit: events };
      } finally {
        globalThis.fetch = realFetch;
      }
    };
    const good = cfSecrets(twoRecipientEstate());
    const r1 = await drive(good);
    ok(`the confirmed strict re-key returns 200 (got ${r1.status})`, r1.status === 200);
    ok("the pair is gone from the account", !good.bound.has("OPERATIONAL_PRIVATE") && !good.bound.has("OPERATIONAL_PUBLIC"));
    ok("the audit has keys-installed AND operational-removed success rows", r1.audit.some((e) => e.action === "keys-installed" && e.outcome === "success") && r1.audit.some((e) => e.action === "operational-removed" && e.outcome === "success"));

    const refused = cfSecrets(twoRecipientEstate(), "OPERATIONAL_PRIVATE");
    const r2 = await drive(refused);
    ok(`a refused DELETE fails the install with 400 (got ${r2.status})`, r2.status === 400);
    ok("the marker was set before the refused delete, so the engine already stops using the pair", refused.bound.get("OPERATIONAL_RETIRED") === "true");
    const fault = r2.audit.find((e) => e.action === "key-removal-failed");
    ok("the failure is audited as key-removal-failed with step operational-private", fault?.outcome === "failed" && fault.target?.step === "operational-private");
  }

  console.log("");
  verdictReached(failures);
  if (failures > 0) {
    console.log(`STRICT RE-KEY FAIL (${failures} assertion(s) failed)`);
    process.exit(1);
  }
  console.log("STRICT RE-KEY PASS (a strict choice leaves no operational key bound, and no run is sealed to one while the marker is set)");
}

await main();
