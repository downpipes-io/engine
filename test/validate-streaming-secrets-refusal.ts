// Streaming reader SECRETS refusal (recovery-redundancy / defence-in-depth, net-zero). Secrets records are sealed
// under a DIFFERENT file key (deriveSecretsFileKey, a fresh per-record salt so a secret is never deduped) than
// non-secret records, and the constant-memory streaming reader restoreRecordStream (reader.ts) deliberately does
// NOT handle the secrets path -- it must REFUSE a secrets record and route the caller to the buffered
// restoreRecord instead (reader.ts:180). If it silently streamed a secrets record it would apply the wrong key
// schedule. validate-streaming-restore exercises restoreRecordStream only on NON-secret records (0 secrets), so
// this specific safety guard was untested. Default-FAIL: the streaming reader must THROW (naming secrets) on a
// secrets record, the BUFFERED reader must restore that same secret byte-identical, and -- as the control that
// proves the refusal is specific to secrets, not a broken stream -- the streaming reader must restore a NON-secret
// (multi-chunk) record byte-identical. Net-zero: in-memory, harness-minted keys, no IO. Run: node the file.
import { x25519 } from "@noble/curves/ed25519.js";
import { concat } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
function rand(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let off = 0; off < n; off += 65536) crypto.getRandomValues(out.subarray(off, Math.min(off + 65536, n)));
  return out;
}
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
async function streamToBytes(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { out.set(c, off); off += c.length; }
  return out;
}

let assertions = 0;
let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  assertions++;
  console.log(cond ? `  ok   ${label}${detail ? ` (${detail})` : ""}` : `  FAIL ${label}${detail ? ` (${detail})` : ""}`);
  if (!cond) failures++;
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } }, identity: concat(xk.secretKey, seed) };
}
async function makeSigner(): Promise<Signer> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
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

async function main(): Promise<void> {
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const signer = await makeSigner();
  const secretVal = rand(128);
  const kvVal = rand(70000); // > CHUNK_SIZE (65536): a genuine multi-chunk non-secret, so the streaming control is real
  const records: WriteRecord[] = [
    { sourceType: "secrets", name: "api-token", value: secretVal },
    { sourceType: "kv", name: "config", value: kvVal },
  ];
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    { downpipeId: "dp_secref", downpipeName: "secrets-refusal", cadence: "0 * * * *", runId: RUN_ID, master: rand(32), recipients: [bg.entry, op.entry], signer, records, windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const run = await openRun(new MapStore(new Map(mem.entries())), RUN_ID, parseIdentity(bg.identity), verifierFrom(signer), {});

  const secretsRec = run.records.find((r) => r.name === "api-token");
  const kvRec = run.records.find((r) => r.name === "config");
  ok("SETUP: the archive opens with both a secrets record and a non-secret record", secretsRec !== undefined && kvRec !== undefined && secretsRec.sourceType === "secrets");
  if (!secretsRec || !kvRec) { process.exit(1); }

  // 1. The streaming reader REFUSES a secrets record (naming secrets), routing the caller to the buffered path.
  let streamErr = "";
  try { await streamToBytes(run.restoreRecordStream(secretsRec)); } catch (e) { streamErr = e instanceof Error ? e.message : String(e); }
  ok("REFUSAL: restoreRecordStream REFUSES a secrets record (routes to the buffered path), never streaming it under the wrong key schedule", streamErr.toLowerCase().includes("secret"), streamErr.slice(0, 70));

  // 2. The BUFFERED path is the correct route for a secret: it restores it byte-identical.
  const bufSecret = await run.restoreRecord(secretsRec);
  ok("BUFFERED: the buffered restoreRecord path restores the secret byte-identical (the route the stream reader points at)", bytesEqual(bufSecret, secretVal));

  // 3. CONTROL: the streaming reader restores a NON-secret multi-chunk record byte-identical -- proving the refusal
  // above is SPECIFIC to secrets, not a broken stream reader.
  const streamedKv = await streamToBytes(run.restoreRecordStream(kvRec));
  ok("CONTROL: the streaming reader restores a NON-secret multi-chunk record byte-identical (streaming works; only secrets are refused)", bytesEqual(streamedKv, kvVal) && kvVal.length > 65536);

  // 4. Both paths agree on the non-secret record.
  const bufKv = await run.restoreRecord(kvRec);
  ok("AGREEMENT: buffered and streaming restore of the non-secret record are byte-identical", bytesEqual(bufKv, kvVal));

  console.log(failures === 0
    ? `\nSTREAMING SECRETS REFUSAL OK: the constant-memory reader refuses secrets records (routing to buffered, which restores them correctly) while streaming non-secret records byte-identical -- no secret is ever streamed under the wrong key schedule. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("STREAMING-SECRETS-REFUSAL FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
