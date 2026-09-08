// Prove that console.error in drill.ts and restore.ts does NOT log raw exception messages.
//
// restore.ts and drill.ts previously interpolated (e as Error).message directly into
// console.error, leaking internal details (object paths, cryptographic error text) into the
// operational log. The fix replaces each raw interpolation with a stable, opaque FNV-1a
// error id plus a coarse category label. These tests drive the REAL production code and
// assert:
//
//  1. console.error output matches [err:XXXXXXXX category] -- never the raw exception text.
//  2. The coarse client-facing reason returned to the caller is UNCHANGED by the fix.
//  3. Each test is written so it would FAIL if the fix were reverted (i.e. if (e as Error).message
//     were interpolated directly, the canary assertion catches it).
//
// The tests use a "canary" pattern: they capture the raw exception message that the underlying
// engine code produces (e.g. "root signature did not verify"), then assert that string does NOT
// appear anywhere in the console.error output. If someone reintroduces .message interpolation the
// canary fires and the test fails.
//
// Run:  node test/validate-errlog.ts
// In-memory doubles only; no network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, } from "../src/keys-env.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { runDrill } from "../src/admin/drill.ts";
import { runRestore } from "../src/admin/restore.ts";
import type { Env } from "../src/env.d.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import { flipBit } from "./memdest.ts";

// ---- helpers ----------------------------------------------------------------

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_errlog";
const KVSET: Record<string, string> = { "key:x": "value-x", "key:y": "value-y" };

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

// captureConsole swaps console.error for a collector and returns captured lines plus a restore fn.
// It does NOT suppress the real console.error so the test runner still sees output.
function captureErrors(): { errors: string[]; restore: () => void } {
  const errors: string[] = [];
  const real = console.error;
  console.error = (...args: unknown[]) => {
    errors.push(args.map((a) => String(a)).join(" "));
    real(...args);
  };
  return { errors, restore: () => { console.error = real; } };
}

// SpyDestination: same shape used in validate-drill.ts.
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

  tamperManifest(): void {
    const key = `run/${RUN_ID}/root.manifest.json`;
    const bytes = this.store.get(key);
    if (!bytes) throw new Error("manifest not in store");
    const text = new TextDecoder().decode(bytes);
    const tampered = text.replace(/"merkleRoot":"([0-9a-f]{95})([0-9a-f])"/, (_m, prefix, last) => {
      const flipped = last === "a" ? "b" : "a";
      return `"merkleRoot":"${prefix}${flipped}"`;
    });
    if (tampered === text) throw new Error("tampering regex did not match; update the pattern");
    this.store.set(key, new TextEncoder().encode(tampered));
  }

  tamperSegment(): void {
    let segKey: string | undefined;
    for (const k of this.store.keys()) {
      if (k.startsWith("seg/") && k.endsWith(".seg")) { segKey = k; break; }
    }
    if (!segKey) throw new Error("no segment file found in the store");
    const bytes = this.store.get(segKey)!;
    const copy = new Uint8Array(bytes);
    const HEADER = 5;
    const NONCE = 16;
    const PAYLOAD_START = HEADER + NONCE;
    if (copy.length <= PAYLOAD_START) throw new Error("segment file too short to tamper");
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
      if (body instanceof ReadableStream) {
        await spy.putStream(key, body);
      } else {
        const bytes = body instanceof Uint8Array ? body : new Uint8Array(body as ArrayBuffer);
        await spy.put(key, bytes);
      }
      return null;
    },
    async head(key: string): Promise<R2Object | null> {
      const exists = await spy.exists(key);
      return exists ? ({ etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2Object) : null;
    },
    list: async () => ({ objects: [], truncated: false, delimitedPrefixes: [] } as unknown as R2Objects),
    delete: async () => { return; },
    createMultipartUpload: async () => { throw new Error("not implemented"); },
    resumeMultipartUpload: () => { throw new Error("not implemented"); },
  } as unknown as R2Bucket;
}

// errLogPattern is the regex the fixed code emits. Any console.error line from the engine
// under an error path MUST match this pattern: [err:XXXXXXXX coarse-category].
const ERR_LOG_RE = /\[err:[0-9a-f]{8} [a-z][a-z0-9-]+\]/;

// ---- test body --------------------------------------------------------------

async function main(): Promise<void> {
  const signerSeed = rand(64);
  const signerPrivateB64 = b64urlEncode(signerSeed);
  const signer: Signer = await loadSigner(signerPrivateB64);

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  const records = Object.entries(KVSET).map(([name, v]) => ({
    sourceType: "kv", name, value: utf8(v), namespace: NS,
  }));

  const archive = await buildArchive({
    downpipeId: "dp_errlog",
    downpipeName: "errlog-test",
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

  // ---- SCENARIO EL-1: drill tampered manifest -- signature error must NOT leak ----------
  // The tampered manifest causes "root signature did not verify under the operator-pinned
  // signer" to be thrown inside openRun. Before the fix, that text appeared verbatim in
  // console.error. After the fix it must appear ONLY as [err:XXXXXXXX integrity-check-failed].
  //
  // CANARY: if someone reintroduces (e as Error).message in the log, "did not verify" will
  // appear in the captured output and the canary assertion will fail.
  console.log("errlog-scenario-1: drill tampered manifest -- no raw message in log");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.tamperManifest();

    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: makeR2Adapter(spy),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
    } as unknown as Env;

    const cap = captureErrors();
    let result;
    try {
      result = await runDrill(env, RUN_ID);
    } finally {
      cap.restore();
    }

    // The coarse result is unchanged from what the caller sees.
    ok("EL-1: drill result ok is false", result.ok === false);
    ok("EL-1: drill coarse reason is integrity-check-failed", result.reason === "integrity check failed");

    // The log line must be present and must match the [err:...] pattern.
    const drillErrors = cap.errors.filter((l) => l.includes("drill"));
    ok("EL-1: at least one drill console.error line was emitted", drillErrors.length >= 1);
    ok("EL-1: every drill error line matches [err:XXXXXXXX category]", drillErrors.every((l) => ERR_LOG_RE.test(l)));

    // CANARY: the raw message MUST NOT appear in any logged line.
    // "did not verify" is a substring of the real exception text from the signing layer.
    // If (e as Error).message is reintroduced, this assertion fails.
    const rawLeaked = cap.errors.some((l) => l.includes("did not verify") || l.includes("signature"));
    ok("EL-1 CANARY: raw signature error text does not appear in log", !rawLeaked);
  }

  // ---- SCENARIO EL-2: drill tampered segment -- AEAD error must NOT leak -----------------
  // The AEAD authentication failure produces "The operation failed for an operation-specific
  // reason" (or equivalent). Before the fix that text appeared in the log.
  //
  // CANARY: if (e as Error).message is reintroduced, "operation-specific" or "OperationError"
  // will appear in the output and the canary assertion will fail. (The reader now re-labels a
  // present-but-corrupt segment's decrypt failure as a structured integrity failure, so the
  // coarse reason is "integrity check failed"; the log still carries only [err:ID category],
  // never the raw AEAD message, so the no-leak guarantee is unchanged.)
  console.log("errlog-scenario-2: drill tampered segment -- no raw AEAD message in log");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.tamperSegment();

    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: makeR2Adapter(spy),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
    } as unknown as Env;

    const cap = captureErrors();
    let result;
    try {
      result = await runDrill(env, RUN_ID);
    } finally {
      cap.restore();
    }

    ok("EL-2: drill result ok is false", result.ok === false);
    ok("EL-2: drill coarse reason is the integrity class (present-but-corrupt segment)", result.reason === "integrity check failed");

    const drillErrors = cap.errors.filter((l) => l.includes("drill"));
    ok("EL-2: at least one drill console.error line was emitted", drillErrors.length >= 1);
    ok("EL-2: every drill error line matches [err:XXXXXXXX category]", drillErrors.every((l) => ERR_LOG_RE.test(l)));

    // CANARY: the AEAD raw message must not appear.
    const rawLeaked = cap.errors.some((l) => l.includes("operation-specific") || l.includes("OperationError"));
    ok("EL-2 CANARY: raw AEAD error text does not appear in log", !rawLeaked);
  }

  // ---- SCENARIO EL-3: restore missing run -- object path must NOT leak -------------------
  // A missing run causes "object run/RUNID/root.manifest.json is missing" to be thrown.
  // That string contains the internal object-key path. Before the fix it appeared verbatim.
  //
  // CANARY: if (e as Error).message is reintroduced, "root.manifest.json" will appear in
  // the captured output and the canary assertion will fail.
  console.log("errlog-scenario-3: restore missing run -- no raw object path in log");
  {
    const spy = new SpyDestination();
    // Do NOT seed the archive; every object is absent.

    const mockKV = {
      store: new Map<string, Uint8Array>(),
      putCount: 0,
      async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
        this.putCount++;
        this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
      },
      async get(k: string, _type?: string): Promise<ArrayBuffer | null> {
        const val = this.store.get(k);
        if (!val) return null;
        const out = new ArrayBuffer(val.byteLength);
        new Uint8Array(out).set(val);
        return out;
      },
    };

    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: makeR2Adapter(spy),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
      [`KV_${NS}`]: mockKV as unknown as KVNamespace,
    } as unknown as Env;

    const cap = captureErrors();
    let result;
    try {
      result = await runRestore(env, { runId: RUN_ID });
    } finally {
      cap.restore();
    }

    ok("EL-3: restore result ok is false", result.ok === false);
    ok("EL-3: restore coarse reason is object-missing", result.reason === "object missing");

    const restoreErrors = cap.errors.filter((l) => l.includes("restore"));
    ok("EL-3: at least one restore console.error line was emitted", restoreErrors.length >= 1);
    ok("EL-3: every restore error line matches [err:XXXXXXXX category]", restoreErrors.every((l) => ERR_LOG_RE.test(l)));

    // CANARY: the internal object path must not appear in any logged line.
    // "root.manifest.json" is the key path the ObjectStore.get error carries.
    const rawLeaked = cap.errors.some((l) => l.includes("root.manifest.json") || l.includes("is missing"));
    ok("EL-3 CANARY: raw object-key path does not appear in log", !rawLeaked);
  }

  // ---- SCENARIO EL-4: errId stability -- same exception class+message always same code ----
  // errId is not exported from the production source, so we exercise the OBSERVABLE property:
  // two successive calls to runDrill on the same tampered archive MUST produce the same
  // [err:...] code in their log lines. This proves the hash is deterministic (not random).
  //
  // A random nonce would cause two runs to produce different codes; the FNV-1a hash is
  // deterministic so codes are stable and an operator can correlate them across restarts.
  console.log("errlog-scenario-4: errId stability -- same error produces same code across two runs");
  {
    const spy = new SpyDestination();
    spy.seed(archive);
    spy.tamperManifest();
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: makeR2Adapter(spy),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
    } as unknown as Env;

    const cap1 = captureErrors();
    try {
      await runDrill(env, RUN_ID);
    } finally {
      cap1.restore();
    }

    const spy2 = new SpyDestination();
    spy2.seed(archive);
    spy2.tamperManifest();
    const env2 = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: makeR2Adapter(spy2),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
    } as unknown as Env;

    const cap2 = captureErrors();
    try {
      await runDrill(env2, RUN_ID);
    } finally {
      cap2.restore();
    }

    const code1 = (cap1.errors.filter((l) => l.includes("drill"))[0] ?? "").match(/\[err:([0-9a-f]{8})/)?.[1];
    const code2 = (cap2.errors.filter((l) => l.includes("drill"))[0] ?? "").match(/\[err:([0-9a-f]{8})/)?.[1];

    ok("EL-4: errId is non-empty for both runs", !!code1 && !!code2);
    ok("EL-4: errId is identical across two runs with the same error (deterministic)", code1 === code2);
  }

  // ---- summary ----------------------------------------------------------------
  console.log(failures === 0 ? "\nALL ERRLOG VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
