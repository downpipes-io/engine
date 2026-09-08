// Adversarial-archive fuzz: NO SILENT CORRUPTION (recovery-redundancy / robustness, net-zero). The load-bearing
// guarantee of a recovery tool is that it NEVER hands back wrong data as if it were right: any corrupted archive
// must be either REFUSED (a controlled error) or -- if the corrupted byte was genuinely unused for this restore --
// still restore to the EXACT original. The one outcome that must never occur is ACCEPTED-WITH-WRONG-PLAINTEXT
// (silent corruption). validate-fuzzing-tier1 fuzzes the WRITE domain and uses a single fixed tamper as a refuter
// to prove its differential has teeth; validate-integrity-faults pins SPECIFIC named faults. Neither sweeps
// ARBITRARY single-byte corruption across every object of a real archive and asserts the no-silent-corruption
// invariant. This does: seal a real multi-record, multi-chunk archive, then for a seeded, reproducible sweep pick
// an object and apply one length-safe mutation (bit-flip / byte-randomise / truncate -- none can drive an
// unbounded allocation), attempt a FULL restore, and classify REFUSED / CORRECT / WRONG. Default-FAIL: the sweep
// must yield ZERO WRONG. Two teeth checks stop a vacuous pass: the clean control restores CORRECT (the compare is
// real) and a targeted ciphertext-byte flip is REFUSED (the REFUSED bucket is not catching everything blindly);
// object coverage is asserted (every object is corrupted at least once). Net-zero: in-memory, harness-minted keys,
// no IO. Run: node test/validate-adversarial-archive-fuzz.ts
import { x25519 } from "@noble/curves/ed25519.js";
import { concat } from "../src/crypto/bytes.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { verifierFrom } from "../src/keys-env.ts";
import { MemoryDestination } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const N = 256; // sweep size (>= object count, so every object is corrupted at least once)
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
// Seeded PRNG (mulberry32) so a failing sweep is reproducible byte-for-byte.
function mulberry32(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
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
function deepCopy(map: Map<string, Uint8Array>): Map<string, Uint8Array> {
  const out = new Map<string, Uint8Array>();
  for (const [k, v] of map) out.set(k, new Uint8Array(v));
  return out;
}
// Apply one length-safe mutation to map[key], guaranteed to change >= 1 byte (or the length). None can drive an
// unbounded allocation: bit-flip and byte-set are length-preserving; truncate only shortens.
function corrupt(map: Map<string, Uint8Array>, key: string, rng: () => number): void {
  const orig = map.get(key)!;
  const kind = Math.floor(rng() * 3);
  if (kind === 2 && orig.length > 6) {
    const keep = 1 + Math.floor(rng() * (orig.length - 1)); // 1..len-1
    map.set(key, orig.slice(0, keep));
    return;
  }
  const b = new Uint8Array(orig);
  const off = Math.floor(rng() * b.length);
  if (kind === 0) {
    // off is in 0..b.length-1 (rng() < 1 and every archive object is non-empty), so the read is in range; the
    // rng() call order is unchanged from the compound-assignment form, keeping the seeded sweep reproducible.
    b[off] = b[off]! ^ (1 << Math.floor(rng() * 8)); // flip one bit
  } else {
    let v = Math.floor(rng() * 256);
    if (v === b[off]) v = (v + 1) & 0xff; // guarantee a change
    b[off] = v;
  }
  map.set(key, b);
}

async function main(): Promise<void> {
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const signer = await makeSigner();
  // A real archive: one 2-chunk record (substantial ciphertext) plus two small records, mixed source types.
  // Every fixture here is a buffered record, so `value` is always present; the narrowed type says so and keeps the
  // byte-for-byte compare below honest (WriteRecord.value is optional because a streamed record omits it).
  const originals: (WriteRecord & { value: Uint8Array })[] = [
    { sourceType: "kv", name: "big", value: rand(130000) },
    { sourceType: "r2", name: "small-a", value: rand(1024) },
    { sourceType: "d1", name: "small-b", value: rand(777) },
  ];
  const mem = new MemoryDestination();
  const archive = await buildArchive(
    { downpipeId: "dp_advfuzz", downpipeName: "adv-fuzz", cadence: "0 * * * *", runId: RUN_ID, master: rand(32), recipients: [bg.entry, op.entry], signer, records: originals, windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z", runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16) },
    { dest: mem },
  );
  for (const [k, b] of archive) await mem.put(k, b);
  const clean = new Map(mem.entries());

  // Classify one archive: REFUSED (open or restore threw), CORRECT (opened + every record restored to the exact
  // original), or WRONG (opened but a record is missing/miscounted/restored to different bytes -- silent corruption).
  async function classify(map: Map<string, Uint8Array>): Promise<"REFUSED" | "CORRECT" | "WRONG"> {
    let run: Awaited<ReturnType<typeof openRun>>;
    try {
      run = await openRun(new MapStore(map), RUN_ID, parseIdentity(bg.identity), verifierFrom(signer), {});
    } catch {
      return "REFUSED";
    }
    try {
      if (run.records.length !== originals.length) return "WRONG"; // accepted a wrong record count
      for (const o of originals) {
        const rec = run.records.find((r) => r.name === o.name);
        if (!rec) return "WRONG"; // a record vanished yet the run opened
        const restored = await run.restoreRecord(rec);
        if (!bytesEqual(restored, o.value)) return "WRONG"; // THE catastrophic case: accepted, wrong bytes
      }
    } catch {
      return "REFUSED"; // integrity caught at restore
    }
    return "CORRECT";
  }

  // Teeth 1: the clean archive opens and restores every record to the exact original (the compare is not vacuous).
  ok("CONTROL: the un-corrupted archive opens and every record restores to the EXACT original", (await classify(clean)) === "CORRECT");

  // Teeth 2: a targeted ciphertext-byte flip in the largest object is REFUSED (the REFUSED bucket is real).
  const keys = [...clean.keys()];
  const bigKey = keys.reduce((a, b) => (clean.get(b)!.length > clean.get(a)!.length ? b : a), keys[0]!);
  const targeted = deepCopy(clean);
  const tb = targeted.get(bigKey)!;
  const mid = Math.floor(tb.length / 2); // bigKey is the LARGEST object, so mid is in range
  tb[mid] = tb[mid]! ^ 0x40;
  ok("TEETH: a targeted byte flip in the largest object (segment ciphertext) is REFUSED", (await classify(targeted)) === "REFUSED");

  // The sweep: one length-safe corruption per iteration, cycling objects for guaranteed coverage. Tally per object
  // so a load-bearing object that is silently benign (an under-verified field) would stand out.
  const rng = mulberry32(0x51ee_d5ea);
  let refused = 0, correct = 0, wrong = 0;
  const wrongDetail: string[] = [];
  const per = new Map<string, { refused: number; correct: number; wrong: number }>();
  for (const k of keys) per.set(k, { refused: 0, correct: 0, wrong: 0 });
  for (let i = 0; i < N; i++) {
    const map = deepCopy(clean);
    const key = keys[i % keys.length]!;
    corrupt(map, key, rng);
    const r = await classify(map);
    const p = per.get(key)!;
    if (r === "REFUSED") { refused++; p.refused++; }
    else if (r === "CORRECT") { correct++; p.correct++; }
    else { wrong++; p.wrong++; if (wrongDetail.length < 5) wrongDetail.push(key); }
  }

  // Per-object breakdown (diagnostic): shows exactly which objects are integrity-gated on the bg restore path
  // (100% refused) vs benign-when-corrupted (unread by this recipient, e.g. the OTHER recipient's capsule, or
  // canonicalisation-stripped manifest formatting). None may be WRONG.
  console.log("  per-object [refused/correct/wrong] over the sweep:");
  for (const k of keys) {
    const p = per.get(k)!;
    const label = k === bigKey ? `${k} (largest = record ciphertext)` : `${k} (${clean.get(k)!.length}B)`;
    console.log(`    ${p.refused}/${p.correct}/${p.wrong}  ${label}`);
  }

  ok(`NO SILENT CORRUPTION: across ${N} single-corruption archives, ZERO were accepted with WRONG plaintext`, wrong === 0, `wrong=${wrong}, refused=${refused}, benign=${correct}${wrongDetail.length ? `, first-wrong-objects=${wrongDetail.join(",")}` : ""}`);
  // Strong, non-fragile teeth: EVERY corruption to the record-ciphertext object is caught (the data itself is
  // fully tamper-evident); a single benign there would be a genuine integrity hole.
  const bigStats = per.get(bigKey)!;
  ok("TAMPER-EVIDENT DATA: every single corruption to the record-ciphertext object was REFUSED (0 benign, 0 wrong)", bigStats.correct === 0 && bigStats.wrong === 0 && bigStats.refused > 0, `[${bigStats.refused}/${bigStats.correct}/${bigStats.wrong}]`);
  ok("TEETH (sweep): a substantial fraction of arbitrary corruptions are actively refused, not vacuously benign", refused > N / 4, `refused=${refused}/${N}`);
  ok("COVERAGE: every archive object was corrupted at least once during the sweep", [...per.values()].every((p) => p.refused + p.correct + p.wrong > 0), `objects=${keys.length}`);

  console.log(failures === 0
    ? `\nNO-SILENT-CORRUPTION OK: over ${N} arbitrary single-byte/truncation corruptions across ${keys.length} objects, every archive was either REFUSED (${refused}) or benign-and-EXACT (${correct}) -- zero silent-wrong-plaintext. ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("ADVERSARIAL-ARCHIVE-FUZZ FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
