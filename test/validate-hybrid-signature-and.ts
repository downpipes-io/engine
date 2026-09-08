// Hybrid post-quantum signature AND-composition at the ARCHIVE boundary (recovery-redundancy, net-zero). The
// archive root is signed with a HYBRID detached signature edSig(64) || mldsaSig(4627); SPEC 8.1 requires BOTH
// halves to verify, so a forgery that breaks only the classical half (Ed25519) OR only the PQ half (ML-DSA)
// must still be refused -- that is the whole point of hybrid: security holds if EITHER primitive holds. The
// existing wrong-signer refuters swap a WHOLLY different signer (both halves wrong), which would pass even if
// openRun only checked ONE half. This cell proves openRun enforces the AND: a correctly-signed archive is
// opened with the true verifier {ed:A, mldsa:A}, but REFUSED with a half-mismatched verifier {ed:A, mldsa:B}
// (Ed valid, ML-DSA wrong) and {ed:B, mldsa:A} (ML-DSA valid, Ed wrong). Default-FAIL: an ACCEPT of either
// half-mismatch means the hybrid resilience is broken. Net-zero: in-memory. Run: node the file.
import { x25519 } from "@noble/curves/ed25519.js";
import { concat } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
// HybridVerifier is declared in crypto/sign.ts (keys-env.ts only imports it for verifierFrom, it does
// not re-export it), so the type is taken from its canonical home.
import type { HybridVerifier } from "../src/crypto/sign.ts";
import { MemoryDestination } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
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
async function opensWith(map: Map<string, Uint8Array>, bgIdentity: Uint8Array, verifier: HybridVerifier): Promise<boolean> {
  try {
    await openRun(new MapStore(map), RUN_ID, parseIdentity(bgIdentity), verifier, {});
    return true;
  } catch {
    return false;
  }
}

async function main(): Promise<void> {
  const signerA = await makeSigner();
  const signerB = await makeSigner(); // a DIFFERENT hybrid key: source of the wrong half
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    { downpipeId: "dp_hybridand", downpipeName: "hybrid-and", cadence: "0 * * * *", runId: RUN_ID, master: rand(32), recipients: [bg.entry, op.entry], signer: signerA, records: [{ sourceType: "kv", name: "probe", value: rand(256) }], windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const map = new Map(mem.entries());

  const trueVerifier: HybridVerifier = { ed: signerA.edPublic, mldsa: signerA.mldsaPublic };
  const pqHalfWrong: HybridVerifier = { ed: signerA.edPublic, mldsa: signerB.mldsaPublic }; // Ed valid, ML-DSA wrong
  const classicalHalfWrong: HybridVerifier = { ed: signerB.edPublic, mldsa: signerA.mldsaPublic }; // ML-DSA valid, Ed wrong

  const control = await opensWith(map, bg.identity, trueVerifier);
  const pqRefused = !(await opensWith(map, bg.identity, pqHalfWrong));
  const classicalRefused = !(await opensWith(map, bg.identity, classicalHalfWrong));

  ok("CONTROL: the correctly hybrid-signed archive opens with the true verifier {ed:A, mldsa:A}", control);
  ok("REFUTER (default-FAIL): a PQ-half mismatch {ed:A, mldsa:B} is REFUSED (Ed25519 valid, ML-DSA wrong) -- if Ed25519 were forged, ML-DSA still guards", pqRefused);
  ok("REFUTER (default-FAIL): a classical-half mismatch {ed:B, mldsa:A} is REFUSED (ML-DSA valid, Ed25519 wrong) -- if ML-DSA were forged, Ed25519 still guards", classicalRefused);

  console.log(failures === 0
    ? `\nHYBRID SIGNATURE AND-COMPOSITION OK: openRun enforces BOTH halves at the archive boundary -- a one-algorithm forgery (classical-only or PQ-only) is refused, so hybrid resilience holds if either primitive holds. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("HYBRID-AND FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
