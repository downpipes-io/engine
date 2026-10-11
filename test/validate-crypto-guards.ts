// Guard tests for the crypto envelope: the length guards in the hybrid KEM, the 32-byte master check in
// the capsule opener, and the raw-byte sort in the recipient-set hash. Each assertion fails if its guard is
// removed or weakened, or the sort is dropped, reversed or made unstable. The KEM guards are asserted by
// their own message, so a library error further down the call does not stand in for the guard.
// Net-zero: in-memory. Run: node the file.
import { x25519 } from "@noble/curves/ed25519.js";
import { concat, utf8 } from "../src/crypto/bytes.ts";
import { openCapsule, recipientSetHash, sealToRecipients } from "../src/crypto/capsule.ts";
import { decapsulateHybrid, encapsulateHybrid, type HybridRecipientPrivate, type HybridRecipientPublic } from "../src/crypto/kem.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { INFO_RECIPIENT_SET } from "../src/format/version.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const ML_KEM_EK_LEN = 1568;
const HYBRID_CT_LEN = 1600;
const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}${detail ? ` (${detail})` : ""}`);
  if (!cond) failures++;
}
async function thrown(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}
function identity(): { pub: HybridRecipientPublic; priv: HybridRecipientPrivate } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey }, priv: { x25519Scalar: xk.secretKey, mlkemSeed: seed } };
}
const sized = (n: number): Uint8Array => new Uint8Array(n).fill(7);

async function kemGuards(): Promise<void> {
  console.log("KEM length guards");
  const id = identity();
  for (const n of [0, ML_KEM_EK_LEN - 1, ML_KEM_EK_LEN + 1]) {
    const m = await thrown(() => encapsulateHybrid({ x25519: id.pub.x25519, mlkemEk: sized(n) }));
    ok(`encapsulate refuses a ${n}-byte ML-KEM key by its own guard`, m?.startsWith(`ML-KEM encapsulation key is ${n} bytes, want ${ML_KEM_EK_LEN}`) === true, String(m));
  }
  for (const n of [0, 31, 33]) {
    const m = await thrown(() => encapsulateHybrid({ x25519: sized(n), mlkemEk: id.pub.mlkemEk }));
    ok(`encapsulate refuses a ${n}-byte X25519 key by its own guard`, m?.startsWith(`X25519 public key is ${n} bytes, want 32`) === true, String(m));
  }
  const good = await encapsulateHybrid(id.pub);
  ok("encapsulate gives a 1600-byte ciphertext for a well-formed key", good.cipherText.length === HYBRID_CT_LEN);
  const back = await decapsulateHybrid(id.priv, good.cipherText);
  ok("decapsulate recovers the encapsulated secret", back.length === 32 && back.every((b, i) => b === good.sharedSecret[i]));
  for (const n of [0, HYBRID_CT_LEN - 1, HYBRID_CT_LEN + 1]) {
    const m = await thrown(() => decapsulateHybrid(id.priv, sized(n)));
    ok(`decapsulate refuses a ${n}-byte ciphertext by its own guard`, m?.startsWith(`hybrid ciphertext is ${n} bytes, want ${HYBRID_CT_LEN}`) === true, String(m));
  }
}

async function masterLength(): Promise<void> {
  console.log("Capsule master length");
  const id = identity();
  const aad = rand(48);
  const nonceFor = (): Uint8Array => rand(16);
  const good = await sealToRecipients(rand(32), [id.pub], aad, nonceFor);
  const m32 = await thrown(() => openCapsule(good, id.priv, aad));
  ok("a 32-byte master opens", m32 === null, String(m32));
  for (const n of [0, 16, 31, 33, 64]) {
    const wraps = await sealToRecipients(rand(n), [id.pub], aad, nonceFor);
    const m = await thrown(() => openCapsule(wraps, id.priv, aad));
    ok(`a ${n}-byte master is refused on open`, m === `recovered master is ${n} bytes, want 32`, String(m));
  }
}

async function recipientHashOrder(): Promise<void> {
  console.log("Recipient-set hash order");
  // Three encodings. A and B share their first byte and differ at byte 100 (in the ML-KEM half). C sorts first by its first byte. D differs from B
  // only in the last byte, so a comparison that stops early cannot order them.
  const mk = (first: number, at: number, val: number): HybridRecipientPublic => {
    const x = new Uint8Array(32).fill(0x40);
    const e = new Uint8Array(ML_KEM_EK_LEN).fill(0x40);
    x[0] = first;
    if (at < 32) x[at] = val;
    else e[at - 32] = val;
    return { x25519: x, mlkemEk: e };
  };
  const A = mk(0x50, 100, 0x90);
  const B = mk(0x50, 100, 0x10);
  const C = mk(0x20, 100, 0xf0);
  const D = mk(0x50, 100, 0x10);
  D.mlkemEk[ML_KEM_EK_LEN - 1] = 0x41;
  const enc = (r: HybridRecipientPublic): Uint8Array => concat(r.x25519, r.mlkemEk);
  const all = [A, B, C, D];
  const sortedRaw = [...all].map(enc).sort((a, b) => Buffer.compare(a, b));
  ok("fixture: A and B share a first byte", enc(A)[0] === enc(B)[0] && enc(A).some((v, i) => v !== enc(B)[i]));
  ok("fixture: raw order is C, B, D, A", Buffer.compare(sortedRaw[0]!, enc(C)) === 0 && Buffer.compare(sortedRaw[1]!, enc(B)) === 0 && Buffer.compare(sortedRaw[2]!, enc(D)) === 0 && Buffer.compare(sortedRaw[3]!, enc(A)) === 0);
  const expected = await sha384(concat(utf8(INFO_RECIPIENT_SET), new Uint8Array([0x00]), ...sortedRaw));
  const perms: HybridRecipientPublic[][] = [];
  const permute = (rest: HybridRecipientPublic[], acc: HybridRecipientPublic[]): void => {
    if (rest.length === 0) {
      perms.push(acc);
      return;
    }
    for (let i = 0; i < rest.length; i++) permute([...rest.slice(0, i), ...rest.slice(i + 1)], [...acc, rest[i]!]);
  };
  permute(all, []);
  let bad = 0;
  for (const p of perms) {
    const h = await recipientSetHash(p);
    if (Buffer.compare(h, expected) !== 0) bad++;
  }
  ok(`all ${perms.length} input orders hash to the raw-byte-sorted digest`, bad === 0, `${bad} orders differ`);
  const h2 = await recipientSetHash([A, B]);
  const h2r = await recipientSetHash([B, A]);
  const want2 = await sha384(concat(utf8(INFO_RECIPIENT_SET), new Uint8Array([0x00]), enc(B), enc(A)));
  ok("two recipients with a shared first byte order by the first differing byte", Buffer.compare(h2, want2) === 0 && Buffer.compare(h2r, want2) === 0);
  const before = all.map(enc).map((e) => Buffer.from(e).toString("hex"));
  await recipientSetHash(all);
  ok("the caller's recipients are not reordered or changed", all.map(enc).every((e, i) => Buffer.from(e).toString("hex") === before[i]));
}

async function main(): Promise<void> {
  await kemGuards();
  await masterLength();
  await recipientHashOrder();
  console.log(failures === 0 ? "\nCRYPTO GUARDS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
void main();
