// Streaming-reader authenticated-emit invariant (recovery-redundancy, net-zero). restoreRecordStream's
// documented integrity model promises "a chunk is EMITTED ONLY AFTER its tag verifies ... a GCM failure errors
// the stream rather than yielding unauthenticated bytes." The existing refuters only assert the stream THROWS
// on a tamper -- they do NOT assert it never emits corrupt bytes FIRST. A regression to emit-then-verify would
// leak corrupt data into a customer's restore before the error. This cell tampers the FIRST chunk and the LAST
// chunk of a 3-chunk record and asserts, default-FAIL, that in every case: (a) the stream THROWS, and (b) every
// byte it emitted before throwing is a CORRECT PREFIX of the seed (never a corrupt/unauthenticated byte) -- a
// first-chunk tamper emits ~0 bytes, a last-chunk tamper emits the authentic head then aborts. A clean control
// proves the stream emits the whole value without throwing (not vacuous). Net-zero: in-memory. Run: node the file.
import { x25519 } from "@noble/curves/ed25519.js";
import { concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { buildArchive, type RecipientEntry, type Signer, } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";

const CHUNK = 65536;
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const rand = (n: number): Uint8Array => {
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
  return out;
};

let assertions = 0;
let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  assertions++;
  console.log(cond ? `  ok   ${label}${detail ? ` (${detail})` : ""}` : `  FAIL ${label}${detail ? ` (${detail})` : ""}`);
  if (!cond) failures++;
}
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } }, identity: concat(xk.secretKey, seed) };
}
async function makeSigner(): Promise<{ signer: Signer; signerPub: Uint8Array }> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { signer: { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey }, signerPub: concat(edPublic, mldsa.publicKey) };
}
class MapStore implements ObjectStore {
  private readonly map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) { this.map = map; }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (!v) throw new Error(`object not found: ${key}`);
    return v;
  }
  list(prefix: string): Promise<string[]> {
    return Promise.resolve([...this.map.keys()].filter((k) => k.startsWith(prefix)));
  }
}
async function sealOne(name: string, value: Uint8Array): Promise<{ map: Map<string, Uint8Array>; bgIdentity: Uint8Array; signer: Signer }> {
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const { signer } = await makeSigner();
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    { downpipeId: "dp_streamabort", downpipeName: "stream-abort", cadence: "0 * * * *", runId: RUN_ID, master: rand(32), recipients: [bg.entry, op.entry], signer, records: [{ sourceType: "kv", name, value }], windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  return { map: new Map(mem.entries()), bgIdentity: bg.identity, signer };
}

// emittedBeforeThrow drains a stream, collecting every emitted byte, and records whether it threw.
async function emittedBeforeThrow(stream: ReadableStream<Uint8Array>): Promise<{ emitted: Uint8Array; threw: boolean }> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  let threw = false;
  try {
    for (;;) { const { done, value } = await reader.read(); if (done) break; if (value) parts.push(value); }
  } catch { threw = true; }
  let total = 0;
  for (const p of parts) total += p.length;
  const emitted = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { emitted.set(p, off); off += p.length; }
  return { emitted, threw };
}

// isCleanPrefix: every emitted byte equals the seed at that position (no corrupt/unauthenticated byte emitted).
function isCleanPrefix(emitted: Uint8Array, seed: Uint8Array): boolean {
  return emitted.length <= seed.length && bytesEqual(emitted, seed.subarray(0, emitted.length));
}

async function main(): Promise<void> {
  const size = 3 * CHUNK + 137; // 4 chunks: a first, middles, and a last to abort at different points
  const value = rand(size);
  const NAME = "stream-abort-probe";

  // The largest object is the record's data segment; tamper positions target its FIRST vs LAST chunk region.
  const largestKey = (map: Map<string, Uint8Array>): { key: string; len: number } => {
    let key = "";
    let len = 0;
    for (const [k, v] of map) if (v.length > len) { len = v.length; key = k; }
    return { key, len };
  };

  // CONTROL: a clean stream emits the whole value and never throws (proves the tamper cells are not vacuous).
  {
    const { map, bgIdentity, signer } = await sealOne(NAME, value);
    const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
    const rec = run.records.find((r) => r.name === NAME)!;
    const { emitted, threw } = await emittedBeforeThrow(run.restoreRecordStream(rec));
    ok("CONTROL: a clean stream emits the whole value byte-identical and does NOT throw", !threw && bytesEqual(emitted, value), `threw=${threw} bytes=${emitted.length}/${value.length}`);
  }

  // FIRST-chunk tamper: the stream must throw having emitted a clean (near-empty) prefix, never a corrupt byte.
  {
    const { map, bgIdentity, signer } = await sealOne(NAME, value);
    const { key, len } = largestKey(map);
    const tv = new Uint8Array(map.get(key)!);
    const pos = Math.floor(len * 0.02); // early => the first chunk
    tv[pos] = tv[pos]! ^ 1;
    map.set(key, tv);
    const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
    const rec = run.records.find((r) => r.name === NAME)!;
    const { emitted, threw } = await emittedBeforeThrow(run.restoreRecordStream(rec));
    ok("FIRST-chunk tamper: the stream THROWS and every emitted byte is a clean prefix (no corrupt byte leaked)", threw && isCleanPrefix(emitted, value), `threw=${threw} emitted=${emitted.length}B cleanPrefix=${isCleanPrefix(emitted, value)}`);
  }

  // LAST-chunk tamper: the stream emits the AUTHENTIC head (a clean prefix), then throws at the tampered chunk.
  {
    const { map, bgIdentity, signer } = await sealOne(NAME, value);
    const { key, len } = largestKey(map);
    const tv = new Uint8Array(map.get(key)!);
    const pos = Math.floor(len * 0.92); // late => the last chunk region
    tv[pos] = tv[pos]! ^ 1;
    map.set(key, tv);
    const run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifierFrom(signer), {});
    const rec = run.records.find((r) => r.name === NAME)!;
    const { emitted, threw } = await emittedBeforeThrow(run.restoreRecordStream(rec));
    ok("LAST-chunk tamper: the stream THROWS, the emitted head is a clean prefix, and the tampered tail is NEVER emitted", threw && isCleanPrefix(emitted, value) && emitted.length < value.length, `threw=${threw} emitted=${emitted.length}/${value.length} cleanPrefix=${isCleanPrefix(emitted, value)}`);
  }

  console.log(failures === 0
    ? `\nSTREAM-ABORT INVARIANT OK: restoreRecordStream emits ONLY authenticated bytes -- a first/last-chunk tamper throws with a clean prefix, never a corrupt byte; a clean stream emits the whole value. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("STREAM-ABORT FUZZER FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
