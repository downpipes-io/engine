// Hybrid post-quantum CAPSULE (confidentiality) AND-composition (recovery-redundancy, net-zero). The master
// capsule that gates every segment key is wrapped to each recipient under BOTH x25519 AND ML-KEM-1024, so the
// unwrap needs BOTH the classical AND the post-quantum private components -- confidentiality holds if EITHER
// primitive holds. The recipient identity is concat(x25519_secret(32), mlkem_seed(64)). validate-integrity-faults
// proves a WHOLLY-wrong identity (matches no capsule) is refused, but that would pass even if the unwrap
// only needed ONE component. This cell proves BOTH are required: the true identity opens, but a HALF-wrong
// identity {x25519:A, mlkem:B} (classical right, PQ wrong) AND {x25519:B, mlkem:A} (PQ right, classical wrong)
// each FAIL to unwrap -> refused. Default-FAIL: an open with either half means a one-primitive break exposes the
// key. Companion to validate-hybrid-signature-and (integrity). Net-zero: in-memory. Run: node the file.
import { x25519 } from "@noble/curves/ed25519.js";
import { concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const X25519_SECRET_LEN = 32; // the identity is x25519_secret(32) || mlkem_seed(64)
const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

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
// Split an identity into its x25519-secret and ML-KEM-seed halves, and recombine across recipients.
function x25519Half(id: Uint8Array): Uint8Array { return id.subarray(0, X25519_SECRET_LEN); }
function mlkemHalf(id: Uint8Array): Uint8Array { return id.subarray(X25519_SECRET_LEN); }
function frankenId(x25519From: Uint8Array, mlkemFrom: Uint8Array): Uint8Array { return concat(x25519Half(x25519From), mlkemHalf(mlkemFrom)); }

async function opensWith(map: Map<string, Uint8Array>, identityBytes: Uint8Array, signer: Signer): Promise<boolean> {
  try {
    await openRun(new MapStore(map), RUN_ID, parseIdentity(identityBytes), verifierFrom(signer), {});
    return true;
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  const bg = makeRecipient("break-glass"); // recipient A -- the archive is sealed to this identity
  const op = makeRecipient("operational");
  const other = makeRecipient("stranger"); // recipient B -- source of the WRONG half
  const signer = await makeSigner();
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    { downpipeId: "dp_capand", downpipeName: "capsule-and", cadence: "0 * * * *", runId: RUN_ID, master: rand(32), recipients: [bg.entry, op.entry], signer, records: [{ sourceType: "kv", name: "probe", value: rand(256) }], windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const map = new Map(mem.entries());

  // Sanity: the franken-identities have the SAME length as a real identity (so a parse-length gate cannot be
  // what refuses them -- the refusal must come from the hybrid unwrap failing).
  ok("franken-identities parse to the same length as a real identity (refusal is the unwrap, not a length gate)", frankenId(bg.identity, other.identity).length === bg.identity.length && frankenId(other.identity, bg.identity).length === bg.identity.length);

  const control = await opensWith(map, bg.identity, signer);
  const pqWrongRefused = !(await opensWith(map, frankenId(bg.identity, other.identity), signer)); // x25519:A, mlkem:B
  const classicalWrongRefused = !(await opensWith(map, frankenId(other.identity, bg.identity), signer)); // x25519:B, mlkem:A

  ok("CONTROL: the true recipient identity (x25519:A, mlkem:A) unwraps the capsule and opens the run", control);
  ok("REFUTER (default-FAIL): a PQ-half-wrong identity {x25519:A, mlkem:B} is REFUSED (ML-KEM required) -- if x25519 were broken, ML-KEM still guards confidentiality", pqWrongRefused);
  ok("REFUTER (default-FAIL): a classical-half-wrong identity {x25519:B, mlkem:A} is REFUSED (x25519 required) -- if ML-KEM were broken, x25519 still guards confidentiality", classicalWrongRefused);

  console.log(failures === 0
    ? `\nHYBRID CAPSULE AND-COMPOSITION OK: the master capsule needs BOTH x25519 AND ML-KEM to unwrap -- a one-primitive break (classical-only or PQ-only) cannot recover the key, so confidentiality holds if either holds. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("HYBRID-CAPSULE-AND FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
