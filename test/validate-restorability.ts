// Restorability-assurance tiers: prove the BLIND restore test, the KEYLESS Tier 0 attestation, the
// restore.verify capability and the per-downpipe "offline restorability last proven" record against real
// in-memory archives and a real scheduler DO. No network, no deploy, no cost. Run:
//   node test/validate-restorability.ts
//
// The load-bearing security properties this validator pins:
//   1. The BLIND restore test decrypts EVERY in-scope record to a discard sink, verifies each plaintext
//      hash, and returns counts + a restoreDigest WITHOUT ever putting a byte of plaintext (or a key) in
//      the response OR the logs. We seal records whose plaintext is a unique sentinel and assert the
//      sentinel never appears in JSON.stringify(result) NOR in any captured console line. The test also
//      asserts the blind test wrote NOTHING (the discard sink: spy.putLog stays empty), so restore.verify
//      can never apply or read content out.
//   2. A TAMPERED archive fails: a flipped segment byte surfaces a per-record failure (the archive is
//      partially unrecoverable), and a flipped manifest field fails the signature gate (ok:false), both
//      WITHOUT leaking plaintext.
//   3. The KEYLESS attestation passes with NO identity (no OPERATIONAL_PRIVATE at all): it verifies the
//      signature, completeness and anti-rollback using only the PUBLIC verifier and no decryption key. A
//      tampered manifest drops signatureValid; tampered shard bytes drop complete (signature still valid).
//   4. restore.verify CANNOT apply or read content: the capability is held from the viewer floor up but
//      does NOT imply restore.apply or downpipe.read, and the verify route writes nothing.
//   5. The "last proven" record is stamped on a PASS (who+when+method) and re-checked server-side: the DO
//      refuses a /restore-proven write from a caller without restore.verify, is a no-op for an unknown
//      downpipe, and a config re-upsert preserves the record.
//
// In-memory doubles only; the archive idiom mirrors validate-drill.ts and the DO harness mirrors
// validate-reports.ts.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { runBlindRestoreTest, runKeylessAttest } from "../src/admin/restore.ts";
import type { RestoreRequest } from "../src/admin/restore-types.ts";
import { can } from "../src/admin/identity.ts";
import { SchedulerDO, type DownpipeState, type RestoreProven, type IntegrityVerified } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { HEADER_SIZE } from "../src/format/container.ts";
import { STREAM_NONCE_SIZE } from "../src/format/version.ts";
import { flipBit } from "./memdest.ts";
// The in-memory DO storage double is shared across the DO validators.
import { MockStorage } from "./mock-storage.ts";

// ---- harness ----------------------------------------------------------------

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const DOWNPIPE_ID = "dp_restorability";
const NS = "ns_assure";

// A UNIQUE, easily-greppable sentinel embedded in every record's plaintext. If ANY of these strings ever
// surfaces in a blind-test response or a log line, the discard-only property is broken. They are chosen so
// they cannot occur incidentally in a hash, a count or a coarse reason.
const SENTINELS: Record<string, string> = {
  "key:alpha": "PLAINTEXT-SENTINEL-ALPHA-must-never-leak-7f3a",
  "key:beta": "PLAINTEXT-SENTINEL-BETA-must-never-leak-9c21-longer-value",
  "key:gamma": "PLAINTEXT-SENTINEL-GAMMA-must-never-leak-1b88",
};

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return {
    entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } },
    identity: concat(xk.secretKey, seed),
  };
}

// SpyDestination is a MemoryDestination that records every WRITE so a test can assert the blind test wrote
// nothing back (the discard sink), and offers tamper helpers for the negative controls.
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
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) parts.push(value);
    }
    this.putLog.push(`putStream:${key}`);
  }
  async putConditional(key: string, body: Uint8Array): Promise<PutConditionalResult> {
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
  // tamperManifest flips the last hex digit of the signed merkleRoot value, invalidating the manifest
  // signature (the signature covers the whole manifest blob).
  tamperManifest(): void {
    const key = `run/${RUN_ID}/root.manifest.json`;
    const bytes = this.store.get(key);
    if (!bytes) throw new Error("manifest not in store");
    const text = new TextDecoder().decode(bytes);
    const tampered = text.replace(/"merkleRoot":"([0-9a-f]{95})([0-9a-f])"/, (_m, prefix, last) => {
      const flipped = last === "a" ? "b" : "a";
      return `"merkleRoot":"${prefix}${flipped}"`;
    });
    if (tampered === text) throw new Error("manifest tamper regex did not match; update the pattern");
    this.store.set(key, new TextEncoder().encode(tampered));
  }
  // tamperSegment flips a ciphertext byte in the first .seg file. The AEAD tag fails on decrypt; the
  // manifest signature stays valid (segment bytes are not covered by the signature or the shard SHA-384).
  tamperSegment(): void {
    let segKey: string | undefined;
    for (const k of this.store.keys()) {
      if (k.startsWith("seg/") && k.endsWith(".seg")) { segKey = k; break; }
    }
    if (!segKey) throw new Error("no segment file found in the store");
    const copy = new Uint8Array(this.store.get(segKey)!);
    const PAYLOAD_START = HEADER_SIZE + STREAM_NONCE_SIZE; // container header + payload nonce
    if (copy.length <= PAYLOAD_START) throw new Error("segment file too short to tamper");
    flipBit(copy, PAYLOAD_START);
    this.store.set(segKey, copy);
  }
  // tamperShardBytes flips a byte in the FIRST shard manifest object. The shard SHA-384 is in the signed
  // root, so the keyless completeness check catches the mismatch while the root signature stays valid.
  tamperShardBytes(): void {
    let shardKey: string | undefined;
    for (const k of this.store.keys()) {
      if (k.startsWith("shard/") || /\/shard/.test(k) || k.endsWith(".shard")) { shardKey = k; break; }
    }
    // The shard object key convention is recovered from the manifest; fall back to any non-seg, non-run
    // object that is referenced as a shard. We locate it by reading the root manifest's shards[].object.
    if (!shardKey) {
      const rootBytes = this.store.get(`run/${RUN_ID}/root.manifest.json`)!;
      const root = JSON.parse(new TextDecoder().decode(rootBytes)) as { shards: Array<{ object: string }> };
      shardKey = root.shards[0]?.object;
    }
    if (!shardKey || !this.store.has(shardKey)) throw new Error("no shard object found in the store");
    const copy = new Uint8Array(this.store.get(shardKey)!);
    flipBit(copy, copy.length - 1);
    this.store.set(shardKey, copy);
  }
  // dropShard removes the first shard object entirely (a dropped shard = incomplete archive).
  dropShard(): string {
    const rootBytes = this.store.get(`run/${RUN_ID}/root.manifest.json`)!;
    const root = JSON.parse(new TextDecoder().decode(rootBytes)) as { shards: Array<{ object: string }> };
    const shardKey = root.shards[0]!.object;
    this.store.delete(shardKey);
    return shardKey;
  }
}

// makeR2Adapter wraps a SpyDestination as an R2Bucket so buildDestination(env) (DEST_KIND:"r2") resolves to
// the spy. Mirrors validate-drill.ts.
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
      else {
        const bytes = body instanceof Uint8Array ? body : new Uint8Array(body as ArrayBuffer);
        await spy.put(key, bytes);
      }
      return null;
    },
    async head(key: string): Promise<R2Object | null> {
      return (await spy.exists(key)) ? ({ etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2Object) : null;
    },
    list: async () => ({ objects: [], truncated: false, delimitedPrefixes: [] } as unknown as R2Objects),
    delete: async () => { return; },
    createMultipartUpload: async () => { throw new Error("not implemented"); },
    resumeMultipartUpload: () => { throw new Error("not implemented"); },
  } as unknown as R2Bucket;
}

// captureConsole records every console.log / console.error line so the blind-test no-leak assertion can
// scan the WHOLE log stream, not just the returned value. It returns the joined output and a restore fn.
function captureConsole(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  const sink = (...args: unknown[]) => { lines.push(args.map((a) => (typeof a === "string" ? a : JSON.stringify(a))).join(" ")); };
  console.log = sink as typeof console.log;
  console.error = sink as typeof console.error;
  return { lines, restore: () => { console.log = origLog; console.error = origErr; } };
}

function envWith(spy: SpyDestination, signerPrivateB64: string, operationalPrivateB64?: string): Env {
  return {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: makeR2Adapter(spy),
    SIGNER_PRIVATE: signerPrivateB64,
    ...(operationalPrivateB64 ? { OPERATIONAL_PRIVATE: operationalPrivateB64 } : {}),
  } as unknown as Env;
}

// ---- DO harness (mirrors validate-reports.ts) -------------------------------

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  return { storage, stub: new SchedulerDO({ storage } as unknown as DurableObjectState) };
}

function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, header?: string): Promise<Response> {
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(header !== undefined ? { "x-downpipe-caller": header } : {}),
  };
  return dobj.fetch(new Request(`https://scheduler.internal${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }));
}

function callerHeader(role: Caller["role"], email: string | null): string {
  // subject mirrors the method: an access caller (has an email) carries a stable subject; the bare-token
  // break-glass (no email) has a null subject, exactly as resolveCaller produces.
  return encodeCaller({ method: email ? "access" : "token", email, subject: email !== null ? `subject-${email}` : null, role, groups: [] });
}

// wrapSchedulerStub adapts the raw SchedulerDO instance (which .fetch()es a single Request, as fetchDO
// above drives it) to the two-argument DurableObjectStub.fetch(url, init) shape runKeylessAttest /
// runBlindRestoreTest's fetchMinRunlogIndex calls (via doURL), mirroring
// validate-cov-admin-router-restore.ts's identical makeScheduler wrapper.
function wrapSchedulerStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
}

// ---- test body --------------------------------------------------------------

// Ctx is the shared fixture every scenario reads: the sealed archive plus the keys and records it was
// built from. setup() builds it once; main() threads it into each scenario function.
interface Ctx {
  signerPrivateB64: string;
  operationalPrivateB64: string;
  signer: Signer;
  breakGlass: ReturnType<typeof makeRecipient>;
  op: ReturnType<typeof makeRecipient>;
  records: { sourceType: string; name: string; value: Uint8Array; namespace: string }[];
  archive: Awaited<ReturnType<typeof buildArchive>>;
}

// noLeak is the load-bearing assertion shared by every scenario: none of the sentinel plaintexts may
// appear in a response body or a captured log line.
function noLeak(label: string, serialised: string, logLines: string[]): void {
  const allSentinels = Object.values(SENTINELS);
  const inResponse = allSentinels.filter((s) => serialised.includes(s));
  const inLogs = allSentinels.filter((s) => logLines.some((l) => l.includes(s)));
  ok(`${label}: NO plaintext sentinel in the response`, inResponse.length === 0);
  ok(`${label}: NO plaintext sentinel in the logs`, inLogs.length === 0);
}

async function setup(): Promise<Ctx> {
  const signerSeed = rand(64);
  const signerPrivateB64 = b64urlEncode(signerSeed);
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer); // the PUBLIC verifier; keyless needs only this
  void verifier;

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  const records = Object.entries(SENTINELS).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: NS }));
  const archive = await buildArchive({
    downpipeId: DOWNPIPE_ID,
    downpipeName: "restorability-test",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records,
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  return { signerPrivateB64, operationalPrivateB64, signer, breakGlass, op, records, archive };
}

// ---- SCENARIO 1: BLIND restore test on a sealed (healthy) archive -----------------------------
async function scenarioBlind(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, operationalPrivateB64, records, archive } = ctx;
  console.log("restorability-1: blind restore test on a sealed archive (zero plaintext)");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    const cap = captureConsole();
    const result = await runBlindRestoreTest(envWith(spy, signerPrivateB64, operationalPrivateB64), { runId: RUN_ID });
    cap.restore();
    const serialised = JSON.stringify(result);

    ok("blind: ok is true", result.ok === true);
    ok("blind: runId echoed", result.runId === RUN_ID);
    ok("blind: downpipeId is the run's downpipe", result.downpipeId === DOWNPIPE_ID);
    ok("blind: recordsVerified equals the record count", result.recordsVerified === records.length);
    ok("blind: no failures", result.failures.length === 0);
    // bytesVerified is the REAL decrypted byte total (the sum of the sentinel value byte lengths).
    const expectedBytes = Object.values(SENTINELS).reduce((n, v) => n + utf8(v).length, 0);
    ok("blind: bytesVerified equals the summed plaintext size", result.bytesVerified === expectedBytes);
    ok("blind: restoreDigest is a sha384 hash", typeof result.restoreDigest === "string" && result.restoreDigest!.startsWith("sha384:"));
    // THE load-bearing property: zero plaintext anywhere.
    noLeak("blind", serialised, cap.lines);
    // The discard sink wrote NOTHING (restore.verify can never apply or read content out).
    ok("blind: wrote NOTHING back (discard sink)", spy.putLog.length === 0);
  }
}

// ---- SCENARIO 1a2: an EMPTY verify window is not a pass --------------------------------------
// The selector on a verify request is caller-supplied, and an empty scope is reachable in ordinary
// use: `exclude: [""]` puts everything out of scope (src/selector.ts names that shape in as many
// words), and so does an `include` prefix that matches nothing, which is one typo away from a
// prefix that matches everything.
//
// This is worth its own scenario because of what consumes `ok`. router-restore.ts writes the
// "restorability last proven" compliance stamp on `result.ok && result.downpipeId`, so an empty
// window that reported ok would stamp an archive as proven restorable having decrypted zero
// records and zero bytes: a compliance claim over nothing, indistinguishable from a real one.
//
// The `recordsVerified > 0` term in restore-verify.ts is the only thing standing between those two
// outcomes, and this scenario is what asserts it.
async function scenarioEmptyScope(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, operationalPrivateB64, archive } = ctx;
  console.log("restorability-1a2: an empty verify window is an ABSTAIN, never a pass");
  const cases: { label: string; body: RestoreRequest }[] = [
    { label: "exclude-everything", body: { runId: RUN_ID, exclude: [""] } },
    { label: "include-matches-nothing", body: { runId: RUN_ID, include: ["no-such-prefix-in-this-archive/"] } },
    { label: "recordName-matches-nothing", body: { runId: RUN_ID, recordName: "no-such-record-in-this-archive" } },
  ];
  for (const { label, body } of cases) {
    const spy = new SpyDestination();
    spy.seed(archive);
    const cap = captureConsole();
    const result = await runBlindRestoreTest(envWith(spy, signerPrivateB64, operationalPrivateB64), body);
    cap.restore();
    ok(`empty-scope ${label}: recordsVerified is 0 (the window really is empty)`, result.recordsVerified === 0);
    ok(`empty-scope ${label}: bytesVerified is 0`, result.bytesVerified === 0);
    ok(`empty-scope ${label}: ok is FALSE, so nothing stamps this archive as proven restorable`, result.ok === false);
    // nothingToVerify names a run that itself holds zero records (a genuinely empty source), never
    // a selector that emptied a non-empty one. This archive HAS records; the caller's own selector is what
    // matched nothing, so the coarse {ok:false} stays coarse and unqualified here -- it is a distinguishable-
    // response addition for the empty-RUN case (validate-restore-honesty.ts section E), not a
    // reclassification of every empty-window verify as a deferral.
    ok(`empty-scope ${label}: NOT marked nothingToVerify (the run has records; the selector matched none)`, result.nothingToVerify === undefined);
    ok(`empty-scope ${label}: wrote NOTHING back`, spy.putLog.length === 0);
    noLeak(`empty-scope ${label}`, JSON.stringify(result), cap.lines);
  }
}

// ---- SCENARIO 1b: restoreDigest determinism + data-binding -----------------------------------
async function scenarioDigest(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, operationalPrivateB64, signer, breakGlass, op, archive } = ctx;
  console.log("restorability-1b: restoreDigest is deterministic and data-bound");
  {
    const spyA = new SpyDestination(); spyA.seed(archive);
    const a = await runBlindRestoreTest(envWith(spyA, signerPrivateB64, operationalPrivateB64), { runId: RUN_ID });
    const spyB = new SpyDestination(); spyB.seed(archive);
    const b = await runBlindRestoreTest(envWith(spyB, signerPrivateB64, operationalPrivateB64), { runId: RUN_ID });
    ok("digest: a repeat blind test yields the SAME restoreDigest (same data restores)", a.restoreDigest !== null && a.restoreDigest === b.restoreDigest);

    // A DIFFERENT data set must yield a DIFFERENT digest. Build a second archive (new run id) whose
    // plaintext differs, and confirm the digest differs. It is built standalone (its own isolated
    // _RECOVERY/RUNLOG containing only its own entry, not a shared continuation of `archive`'s log),
    // so prevRunId is null here (a genuine first run of its own chain) rather than RUN_ID: pointing it
    // at RUN_ID would make this synthetic single-entry RUNLOG carry a prevRunId no entry in THAT
    // document resolves, which the unconditional chain-anomaly check correctly rejects (in real
    // production the account-wide RUNLOG always retains a pruned predecessor, so this dangling shape
    // never legitimately occurs there -- it is purely an artifact of this fixture building two
    // independent single-run archives for comparison).
    const RUN_ID2 = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
    const recs2 = [{ sourceType: "kv", name: "key:alpha", value: utf8("DIFFERENT-DATA"), namespace: NS }];
    const archive2 = await buildArchive({
      downpipeId: DOWNPIPE_ID, downpipeName: "restorability-test", cadence: "3600s", runId: RUN_ID2,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer, records: recs2,
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:02.000Z",
      runlogIndex: 2, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const spyC = new SpyDestination(); spyC.seed(archive2);
    const c = await runBlindRestoreTest(envWith(spyC, signerPrivateB64, operationalPrivateB64), { runId: RUN_ID2 });
    ok("digest: a different data set yields a DIFFERENT restoreDigest", c.restoreDigest !== null && c.restoreDigest !== a.restoreDigest);
  }
}

// ---- SCENARIO 2: TAMPERED archive fails (segment) --------------------------------------------
async function scenarioTamperedSegment(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, operationalPrivateB64, archive } = ctx;
  console.log("restorability-2: tampered segment -> per-record failure, no plaintext");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.tamperSegment();
    const cap = captureConsole();
    const result = await runBlindRestoreTest(envWith(spy, signerPrivateB64, operationalPrivateB64), { runId: RUN_ID });
    cap.restore();
    ok("tampered-segment: ok is false", result.ok === false);
    ok("tampered-segment: at least one record failed", result.failures.length >= 1);
    // A tampered archive must STILL not leak plaintext (the bytes that did decrypt are discarded; the
    // failing record never decrypts at all).
    noLeak("tampered-segment", JSON.stringify(result), cap.lines);
    ok("tampered-segment: wrote NOTHING back", spy.putLog.length === 0);
  }
}

// ---- SCENARIO 2b: TAMPERED archive fails (manifest signature) --------------------------------
async function scenarioTamperedManifest(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, operationalPrivateB64, archive } = ctx;
  console.log("restorability-2b: tampered manifest -> signature gate fails, no plaintext");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.tamperManifest();
    const cap = captureConsole();
    const result = await runBlindRestoreTest(envWith(spy, signerPrivateB64, operationalPrivateB64), { runId: RUN_ID });
    cap.restore();
    ok("tampered-manifest: ok is false", result.ok === false);
    ok("tampered-manifest: reason is integrity check failed (signature fired)", result.reason === "integrity check failed");
    ok("tampered-manifest: recordsVerified is 0 (aborted before any record)", result.recordsVerified === 0);
    ok("tampered-manifest: restoreDigest is null (nothing verified)", result.restoreDigest === null);
    noLeak("tampered-manifest", JSON.stringify(result), cap.lines);
    ok("tampered-manifest: wrote NOTHING back", spy.putLog.length === 0);
  }
}

// ---- SCENARIO 2c: break-glass-only posture (blind test cannot run without a read-back key) ----
async function scenarioBreakGlass(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, archive } = ctx;
  console.log("restorability-2c: break-glass-only posture (no read-back key)");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    const cap = captureConsole();
    // No OPERATIONAL_PRIVATE -> the keyed blind test cannot decrypt; it reports the break-glass posture.
    const result = await runBlindRestoreTest(envWith(spy, signerPrivateB64), { runId: RUN_ID });
    cap.restore();
    ok("break-glass: ok is false", result.ok === false);
    ok("break-glass: reason mentions break-glass-only posture", /break-glass-only posture/.test(result.reason ?? ""));
    ok("break-glass: wrote NOTHING back", spy.putLog.length === 0);
    noLeak("break-glass", JSON.stringify(result), cap.lines);
  }
}

// ---- SCENARIO 3: KEYLESS attestation passes with NO identity ---------------------------------
async function scenarioKeyless(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, archive } = ctx;
  console.log("restorability-3: keyless attestation passes with NO decryption key");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    // env carries NO OPERATIONAL_PRIVATE at all: the keyless attest uses only the public verifier.
    const env = envWith(spy, signerPrivateB64);
    ok("keyless: env has NO operational private (no decryption key)", (env as unknown as { OPERATIONAL_PRIVATE?: string }).OPERATIONAL_PRIVATE === undefined);
    const cap = captureConsole();
    const result = await runKeylessAttest(env, { runId: RUN_ID });
    cap.restore();
    ok("keyless: ok is true (no key, no data needed)", result.ok === true);
    ok("keyless: signatureValid is true", result.signatureValid === true);
    ok("keyless: complete is true", result.complete === true);
    ok("keyless: notRolledBack is true", result.notRolledBack === true);
    ok("keyless: downpipeId recovered from the signed manifest", result.downpipeId === DOWNPIPE_ID);
    ok("keyless: no reason on a clean attestation", result.reason === undefined);
    ok("keyless: wrote NOTHING back", spy.putLog.length === 0);
    noLeak("keyless", JSON.stringify(result), cap.lines);
  }
}

// ---- SCENARIO 3b: keyless on a tampered manifest -> signatureValid false ---------------------
async function scenarioKeylessTamperedManifest(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, archive } = ctx;
  console.log("restorability-3b: keyless attestation on a tampered manifest");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.tamperManifest();
    const result = await runKeylessAttest(envWith(spy, signerPrivateB64), { runId: RUN_ID });
    ok("keyless-tampered: ok is false", result.ok === false);
    ok("keyless-tampered: signatureValid is false", result.signatureValid === false);
    ok("keyless-tampered: complete is false (not evaluated past the bad signature)", result.complete === false);
    ok("keyless-tampered: notRolledBack is false", result.notRolledBack === false);
    ok("keyless-tampered: reason names the signature", /signature/.test(result.reason ?? ""));
  }
}

// ---- SCENARIO 3c: keyless on tampered shard bytes -> complete false, signature still valid -----
async function scenarioKeylessTamperedShard(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, archive } = ctx;
  console.log("restorability-3c: keyless attestation on tampered shard bytes");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.tamperShardBytes();
    const result = await runKeylessAttest(envWith(spy, signerPrivateB64), { runId: RUN_ID });
    ok("keyless-shard: signatureValid stays true (manifest untouched)", result.signatureValid === true);
    ok("keyless-shard: complete is false (a shard no longer hashes to the signed root)", result.complete === false);
    ok("keyless-shard: ok is false", result.ok === false);
  }
}

// ---- SCENARIO 3d: keyless on a dropped shard -> complete false (incomplete archive) -----------
async function scenarioKeylessDroppedShard(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, archive } = ctx;
  console.log("restorability-3d: keyless attestation on a dropped shard");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.dropShard();
    const result = await runKeylessAttest(envWith(spy, signerPrivateB64), { runId: RUN_ID });
    ok("keyless-drop: signatureValid stays true", result.signatureValid === true);
    ok("keyless-drop: complete is false (a listed shard is missing)", result.complete === false);
    ok("keyless-drop: ok is false", result.ok === false);
  }
}

// ---- SCENARIO 4: restore.verify CANNOT apply or read content ---------------------------------
async function scenarioVerifyCapability(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, operationalPrivateB64, records, archive } = ctx;
  console.log("restorability-4: restore.verify cannot apply or read content");
  {
    // The capability model: restore.verify is held by viewer (the floor) but is NOT restore.apply and is
    // NOT downpipe.read, so a verify-capable caller can neither apply a restore nor read downpipe content.
    ok("verify: viewer holds restore.verify", can("viewer", "restore.verify"));
    ok("verify: viewer does NOT hold restore.apply", !can("viewer", "restore.apply"));
    // restore.verify and restore.apply are DISTINCT grants, proven behaviourally through the role table:
    // access-admin holds restore.verify but NOT restore.apply, while restore-operator holds BOTH, so a
    // route gated on restore.apply is never satisfied by a verify-only caller.
    ok("verify: access-admin holds restore.verify but NOT restore.apply", can("access-admin", "restore.verify") && !can("access-admin", "restore.apply"));
    ok("verify: restore-operator holds restore.apply on top of restore.verify", can("restore-operator", "restore.verify") && can("restore-operator", "restore.apply"));
    // BEHAVIOURAL proof the verify path is side-effect-free: the blind test (the heaviest verify action)
    // wrote nothing in every scenario above. Re-assert on a fresh run for clarity.
    const spy = new SpyDestination();
    spy.seed(archive);
    const result = await runBlindRestoreTest(envWith(spy, signerPrivateB64, operationalPrivateB64), { runId: RUN_ID });
    ok("verify: the blind test verified records", result.recordsVerified === records.length);
    ok("verify: yet wrote NOTHING (no apply, no content out)", spy.putLog.length === 0);
  }
}

// ---- SCENARIO 4b: the live scheduler minRunlogIndex pin closes the SAME clean whole-document
// RUNLOG replay on BOTH restorability tiers, including the sibling runBlindRestoreTest path (POST
// /restore/verify) alongside runKeylessAttest (POST /restore/attest). The fixture archive's own
// _RECOVERY/RUNLOG is already a genuinely-signed
// single-entry snapshot for RUN_ID (index 1, prevRunId null) -- exactly the bytes a bucket-write (or
// leaked destination-credential) adversary would capture and replay unmodified after the SAME downpipe
// produces a later run elsewhere: no forging, no signing key, a pure whole-document replay, so it trips
// no chain anomaly. Simulating "elsewhere" needs nothing more than the scheduler DO's OWN account-global
// runlogCounter having moved on (set directly here), completely independent of the destination bucket the
// replayed document lives in -- which is the entire point of the out-of-band pin.
async function scenarioRollbackPin(ctx: Ctx): Promise<void> {
  const { signerPrivateB64, operationalPrivateB64, archive } = ctx;
  console.log("restorability-4b: the live scheduler pin catches a clean whole-document RUNLOG replay on both tiers");

  const { storage, stub } = makeScheduler();
  // Simulate the scheduler having already allocated index 2 (for a later run of this same downpipe,
  // sealed to a destination the replay does not reflect): schedulerSignals reads this back verbatim
  // (scheduler-do-scheduling.ts:575), with no downpipe registration required.
  storage.rawPut("runlogCounter", 2);
  const schedulerStub = wrapSchedulerStub(stub);

  const spy = new SpyDestination();
  spy.seed(archive); // The archive's natural RUNLOG is the t0-only snapshot: the attacker's replay, untouched.
  const env = envWith(spy, signerPrivateB64, operationalPrivateB64);

  // CONTROL / THE EXPLOIT: no scheduler passed (the call shape every caller used before this fix, and
  // still what a caller with no scheduler in scope gets). The replayed document is internally consistent
  // (no chain anomaly), so both tiers read it clean -- notRolledBack/isLatest both true.
  const keylessNoPin = await runKeylessAttest(env, { runId: RUN_ID });
  ok("rollback-pin: keyless attest with NO scheduler still reads the replay clean (unprotected call shape)", keylessNoPin.ok === true && keylessNoPin.notRolledBack === true);
  const blindNoPin = await runBlindRestoreTest(env, { runId: RUN_ID });
  ok("rollback-pin: blind restore test with NO scheduler still reads the replay clean (the sibling exploit)", blindNoPin.ok === true && blindNoPin.isLatest === true);

  // Passing the live scheduler stub, as router-restore.ts does for BOTH /restore/attest
  // AND /restore/verify, means the replayed document's own global max (1) falls below the live pin (2), so both
  // tiers correctly reject it -- rollbackDetected fires unconditionally, regardless of allowStale.
  const keylessPinned = await runKeylessAttest(env, { runId: RUN_ID }, undefined, schedulerStub);
  ok("rollback-pin: keyless attest WITH the live scheduler pin rejects the replay", keylessPinned.ok === false && keylessPinned.notRolledBack === false);
  const blindPinned = await runBlindRestoreTest(env, { runId: RUN_ID }, undefined, schedulerStub);
  ok("rollback-pin: blind restore test WITH the live scheduler pin rejects the replay (the fix)", blindPinned.ok === false && blindPinned.isLatest === false);
  ok("rollback-pin: blind restore test's reason names the freshness/rollback check", /freshness|latest|stale/.test(blindPinned.reason ?? ""));
  ok("rollback-pin: blind restore test wrote NOTHING back even on the rejected replay", spy.putLog.length === 0);
}

// ---- SCENARIO 5: the per-downpipe "offline restorability last proven" record -----------------
async function scenarioLastProven(): Promise<void> {
  console.log("restorability-5: 'last proven' record (who+when+method), server re-checked");
  {
    const { stub, storage } = makeScheduler();
    // Seed a downpipe so the DO has state to stamp.
    await fetchDO(stub, "POST", "/downpipes", {
      id: DOWNPIPE_ID, name: "restorability-test", cadenceSeconds: 3600, enabled: true,
      source: { type: "kv", binding: "KV_uploads", namespaceId: NS, include: [], exclude: [] },
    }, callerHeader("owner", null));

    // A caller WITH restore.verify (viewer is the floor) stamps the record (blind-test method).
    const proverEmail = "prover@example.com";
    const provenResp = await fetchDO(stub, "POST", "/restore-proven",
      { downpipeId: DOWNPIPE_ID, method: "blind-test", runId: RUN_ID }, callerHeader("viewer", proverEmail));
    const provenBody = (await provenResp.json()) as { ok?: boolean };
    ok("proven: a viewer (holds restore.verify) may stamp the record", provenBody.ok === true);

    const ds1 = storage.rawGet<DownpipeState>(`dp:${DOWNPIPE_ID}`);
    const rp1 = ds1?.restoreProven as RestoreProven | undefined;
    ok("proven: the record is persisted on the downpipe state", rp1 !== undefined);
    ok("proven: WHO is the verified prover email", rp1?.by === proverEmail);
    ok("proven: WHEN is a finite epoch ms", typeof rp1?.at === "number" && Number.isFinite(rp1?.at));
    ok("proven: METHOD is blind-test", rp1?.method === "blind-test");
    ok("proven: the proven runId is recorded", rp1?.runId === RUN_ID);
    // A passed proof (blind test / keyless attest) is also a fresh integrity verification, so the same
    // write stamps the "archive integrity last verified" recency with how:"attest" and a finite `at` that
    // agrees with the proof. This is what lets the protection statement read "integrity-checked" off an
    // attestation as well as off a run, instead of "never integrity-checked".
    const iv1 = ds1?.integrityVerified as IntegrityVerified | undefined;
    ok("proven: integrity-verified stamp set by a passed proof", iv1 !== undefined);
    ok("proven: integrity-verified how is 'attest'", iv1?.how === "attest");
    ok("proven: integrity-verified at is a finite epoch ms", typeof iv1?.at === "number" && Number.isFinite(iv1?.at));
    ok("proven: integrity-verified at agrees with the proof timestamp", iv1?.at === rp1?.at);

    // GET /downpipes surfaces it (so the console can show "last proven on <date> by <who>") AND surfaces the
    // integrity stamp in the SAME wire shape the console mapper consumes (nested integrityVerified { at, how }).
    const listResp = await fetchDO(stub, "GET", "/downpipes");
    const list = (await listResp.json()) as DownpipeState[];
    const surfaced = list.find((d) => d.config.id === DOWNPIPE_ID)?.restoreProven;
    ok("proven: GET /downpipes surfaces restoreProven", surfaced !== undefined && surfaced.by === proverEmail);
    const surfacedIv = list.find((d) => d.config.id === DOWNPIPE_ID)?.integrityVerified;
    ok("proven: GET /downpipes surfaces integrityVerified { at, how }", surfacedIv !== undefined && surfacedIv.how === "attest" && Number.isFinite(surfacedIv.at));

    // A config re-upsert (editing the cadence) PRESERVES the record (a config edit must not erase proof).
    await fetchDO(stub, "POST", "/downpipes", {
      id: DOWNPIPE_ID, name: "restorability-test", cadenceSeconds: 7200, enabled: true,
      source: { type: "kv", binding: "KV_uploads", namespaceId: NS, include: [], exclude: [] },
    }, callerHeader("owner", null));
    const ds2 = storage.rawGet<DownpipeState>(`dp:${DOWNPIPE_ID}`);
    ok("proven: a config re-upsert PRESERVES the last-proven record", (ds2?.restoreProven as RestoreProven | undefined)?.runId === RUN_ID);

    // A keyless attestation stamps method keyless-attest and overwrites the prior record.
    const keylessEmail = "keyless@example.com";
    await fetchDO(stub, "POST", "/restore-proven",
      { downpipeId: DOWNPIPE_ID, method: "keyless-attest", runId: RUN_ID }, callerHeader("operator", keylessEmail));
    const ds3 = storage.rawGet<DownpipeState>(`dp:${DOWNPIPE_ID}`);
    const rp3 = ds3?.restoreProven as RestoreProven | undefined;
    ok("proven: a keyless attest updates method to keyless-attest", rp3?.method === "keyless-attest");
    ok("proven: a keyless attest updates WHO to the new prover", rp3?.by === keylessEmail);
  }
}

// ---- SCENARIO 5b: the DO re-checks restore.verify (defence in depth) -------------------------
async function scenarioDoRecheck(): Promise<void> {
  console.log("restorability-5b: the DO refuses a /restore-proven write without restore.verify");
  {
    const { stub } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", {
      id: DOWNPIPE_ID, name: "restorability-test", cadenceSeconds: 3600, enabled: true,
      source: { type: "kv", binding: "KV_uploads", namespaceId: NS, include: [], exclude: [] },
    }, callerHeader("owner", null));

    // EVERY role holds restore.verify in the current model, so to exercise the DO's fail-closed re-check we
    // forward NO caller header at all (decodeCaller -> null -> requireCapability throws AuthError -> 403).
    // This proves the DO does not honour an absent/malformed caller as if it held restore.verify.
    const resp = await fetchDO(stub, "POST", "/restore-proven", { downpipeId: DOWNPIPE_ID, method: "blind-test", runId: RUN_ID });
    ok("re-check: an absent caller is refused (DO fails closed, 403)", resp.status === 403);

    // A malformed method is rejected even for an authorised caller.
    const badMethod = await fetchDO(stub, "POST", "/restore-proven",
      { downpipeId: DOWNPIPE_ID, method: "not-a-method", runId: RUN_ID }, callerHeader("owner", "owner@example.com"));
    ok("re-check: a malformed method is refused (400)", badMethod.status === 400);

    // An unknown downpipe is a no-op (ok:false), never a throw, for an authorised caller.
    const unknown = await fetchDO(stub, "POST", "/restore-proven",
      { downpipeId: "dp_does_not_exist", method: "blind-test", runId: RUN_ID }, callerHeader("owner", "owner@example.com"));
    const unknownBody = (await unknown.json()) as { ok?: boolean };
    ok("re-check: an unknown downpipe is a no-op (ok:false)", unknown.status === 200 && unknownBody.ok === false);
  }
}

async function main(): Promise<void> {
  const ctx = await setup();
  await scenarioBlind(ctx);
  await scenarioEmptyScope(ctx);
  await scenarioDigest(ctx);
  await scenarioTamperedSegment(ctx);
  await scenarioTamperedManifest(ctx);
  await scenarioBreakGlass(ctx);
  await scenarioKeyless(ctx);
  await scenarioKeylessTamperedManifest(ctx);
  await scenarioKeylessTamperedShard(ctx);
  await scenarioKeylessDroppedShard(ctx);
  await scenarioVerifyCapability(ctx);
  await scenarioRollbackPin(ctx);
  await scenarioLastProven();
  await scenarioDoRecheck();

  // ---- summary ----------------------------------------------------------------
  console.log(failures === 0 ? "\nRESTORABILITY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
