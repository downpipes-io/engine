// Drive the REAL runCanaryCycle on a BREAK-GLASS-ONLY engine, end to end, against a working in-memory
// R2 binding. This is the production arm of the operational-key reduction that the existing canary
// validators cannot see: validate-canary.ts exercises finalise() and the helpers with hand-built
// results, and validate-cov-sched-scheduler-do-canary.ts hand-posts a CanaryCheckResult into the DO.
// Neither ever enters cycle.ts, so before this file the branch that decides how the flight reads its
// own cell back had no test at all.
//
// What it pins:
//
//  1. A flight with NO OPERATIONAL_PRIVATE finishes ALIVE. It used to finish ailing on every flight,
//     forever, with four aspects reported skip, because the read-back needed an in-account recipient
//     private. It now opens the cell with that flight's own per-run master.
//  2. Every aspect passes, and specifically NONE is skipped for a posture reason. A skip here would
//     mean the read-back silently did not happen while the flight still read healthy.
//  3. The decrypt and restore aspects genuinely ran, so the corpus was decrypted and byte-compared
//     rather than assumed.
//
// Run: node test/validate-canary-bgonly.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { concat, b64urlEncode } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { runCanaryCycle } from "../src/canary/cycle.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"}   ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// A minimal working R2Bucket double: enough of the binding surface for the R2 destination adapter
// (put with a body or a stream, get, head, delete, list). Deliberately NOT a fault injector; the point
// here is the healthy path, which is the one that could not previously be reached in this posture.
function memoryBucket(): Record<string, unknown> {
  const store = new Map<string, Uint8Array>();
  const drain = async (body: unknown): Promise<Uint8Array> => {
    if (body instanceof Uint8Array) return body;
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
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
    etag: `e${bytes.length}`,
    httpEtag: `"e${bytes.length}"`,
    uploaded: new Date(0),
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
    body: new ReadableStream<Uint8Array>({
      start(c): void {
        c.enqueue(bytes);
        c.close();
      },
    }),
  });
  return {
    put: async (key: string, body: unknown): Promise<Record<string, unknown>> => {
      const bytes = await drain(body);
      store.set(key, bytes);
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
    delete: async (key: string): Promise<void> => {
      store.delete(key);
    },
    list: async (opts?: { prefix?: string }): Promise<{ objects: Array<Record<string, unknown>>; truncated: false }> => {
      const prefix = opts?.prefix ?? "";
      return { objects: [...store.entries()].filter(([k]) => k.startsWith(prefix)).map(([k, v]) => objectFor(k, v)), truncated: false };
    },
  };
}

// schedulerDouble answers only what the canary asks of the DO. fetchDestConfig reads the destination
// config; returning an empty object makes the cycle fall through to the env-bound default destination,
// which is the DEST_R2 binding above.
function schedulerDouble(): DurableObjectStub {
  return {
    async fetch(): Promise<Response> {
      return new Response(JSON.stringify({}), { status: 200, headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  const xk = x25519.keygen();
  const breakGlassPublic = b64urlEncode(concat(xk.publicKey, mlkemKeygen(rand(64)).encapKey));

  // The break-glass-only posture, exactly: a signer (which the engine must always hold, it signs every
  // run) and a break-glass PUBLIC to seal to. No OPERATIONAL_PUBLIC and no OPERATIONAL_PRIVATE, so the
  // engine holds nothing that can decrypt an archive at rest.
  const env = {
    DEST_KIND: "r2",
    DEST_R2: memoryBucket(),
    SIGNER_PRIVATE: b64urlEncode(concat(rand(32), rand(32))),
    BREAK_GLASS_PUBLIC: breakGlassPublic,
  } as unknown as Env;

  ok("the test env really is break-glass-only", (env as unknown as Record<string, unknown>).OPERATIONAL_PRIVATE === undefined && (env as unknown as Record<string, unknown>).OPERATIONAL_PUBLIC === undefined);

  console.log("a break-glass-only flight completes ALIVE (it used to be ailing by posture, every hour, forever):");
  const result = await runCanaryCycle(env, schedulerDouble(), {
    runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    runSeq: 1,
    destinationId: null,
    cleanupRunId: null,
  });

  ok(`the flight is alive (got ${result.status})`, result.status === "alive");
  ok("no ailing cause is carried on a healthy flight", result.ailingCause === undefined);
  ok("no dead reason", result.deadReason === null);
  ok("no bytes strayed from the known corpus", result.byteDelta === 0);

  const byKey = new Map(result.aspects.map((a) => [a.key, a]));
  const skipped = result.aspects.filter((a) => a.outcome === "skip");
  ok(`nothing was skipped for want of a read-back key (skipped: ${skipped.map((a) => a.key).join(", ") || "none"})`, skipped.length === 0);

  // The four aspects that used to be skipped in this posture are the whole point: they are the read,
  // decrypt and restore half of the flight, and they must genuinely have run.
  for (const key of ["read-signature", "runlog-freshness", "decrypt-integrity", "restore", "restore-verify"]) {
    const a = byKey.get(key as never);
    ok(`aspect ${key} ran and passed`, a?.outcome === "pass");
  }

  // The read-signature detail names WHICH opener ran, so a master-sourced read-back is never presented
  // as though a recipient wrap had been proven to open. That distinction is the honest half of this
  // change: nothing in either posture exercises the break-glass wrap.
  ok("the read-signature detail says the flight's own run key opened the cell", (byKey.get("read-signature" as never)?.detail ?? "").includes("own run key"));

  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`CANARY BREAK-GLASS-ONLY FAIL (${failures} assertion(s) failed)`);
    process.exit(1);
  }
  console.log("CANARY BREAK-GLASS-ONLY PASS (a flight with no in-account decryption key reads its own cell back, decrypts, restores and verifies)");
}

await main();
