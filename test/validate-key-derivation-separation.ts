// Key-schedule no-reuse property (recovery-redundancy / crypto, net-zero). The seal derives every segment
// encryption key from the run master via HKDF-SHA-384 with the segment id, codec and a purpose label mixed in.
// If two DISTINCT segments ever derived the SAME key, their AES-GCM chunks would reuse a (key, nonce) pair --
// the most catastrophic symmetric failure (XOR-recoverable plaintext). validate-crypto-kat-multichunk pins the
// derive OUTPUTS against reference vectors (correctness), but a single vector cannot catch a regression that
// DROPS the segment id from the HKDF info: every segment in a run would then share a key, yet the KAT's one
// vector would still match. This cell asserts the PROPERTY over varied inputs, default-FAIL on any collision:
//   - cross-PURPOSE domain separation: the content-address key != a segment file key (same master);
//   - per-SEGMENT uniqueness: 256 random segment ids -> 256 DISTINCT file keys (no reuse across segments);
//   - per-RUN isolation: the same segment under two masters -> different keys;
//   - per-CODEC separation: the same master+segment under two codecs -> different keys;
//   - determinism: the same inputs -> the same key (so the uniqueness is real binding, not randomness).
// Net-zero: pure key derivation, no seal, no IO. Run: node test/validate-key-derivation-separation.ts
import { deriveCAK, deriveNonSecretFileKey } from "../src/crypto/derive.ts";

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

let assertions = 0;
let failures = 0;
function ok(label: string, cond: boolean, detail = ""): void {
  assertions++;
  console.log(cond ? `  ok   ${label}${detail ? ` (${detail})` : ""}` : `  FAIL ${label}${detail ? ` (${detail})` : ""}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const master = rand(32);
  const masterB = rand(32);
  const CODEC_A = 0;
  const CODEC_B = 1;
  const seg = rand(16);

  // Cross-PURPOSE: the content-address key and a segment file key derived from the SAME master must differ.
  const cak = await deriveCAK(master, "dp_derive_sep");
  const fk = await deriveNonSecretFileKey(master, seg, CODEC_A);
  ok("cross-PURPOSE: the content-address key != a segment file key (same master) -- no cross-purpose key reuse", !bytesEqual(cak, fk) && fk.length === 32);

  // Per-SEGMENT uniqueness: N random segment ids under one master must yield N DISTINCT keys (the anti-reuse guard).
  const N = 256;
  const seen = new Set<string>();
  for (let i = 0; i < N; i++) seen.add(hex(await deriveNonSecretFileKey(master, rand(16), CODEC_A)));
  ok(`per-SEGMENT uniqueness: ${N} distinct segment ids -> ${N} DISTINCT file keys (no key reuse across segments)`, seen.size === N, `distinct=${seen.size}/${N}`);

  // Per-RUN isolation: the SAME segment under two masters (two runs) -> different keys.
  const kA = await deriveNonSecretFileKey(master, seg, CODEC_A);
  const kB = await deriveNonSecretFileKey(masterB, seg, CODEC_A);
  ok("per-RUN isolation: the same segment under a different master derives a DIFFERENT key", !bytesEqual(kA, kB));

  // Per-CODEC separation: the same master+segment under two codecs -> different keys.
  const c0 = await deriveNonSecretFileKey(master, seg, CODEC_A);
  const c1 = await deriveNonSecretFileKey(master, seg, CODEC_B);
  ok("per-CODEC separation: the same master+segment under a different codec derives a DIFFERENT key", !bytesEqual(c0, c1));

  // Determinism: the same inputs -> the same key (proving the uniqueness above is real input binding, not chance).
  const c0again = await deriveNonSecretFileKey(master, seg, CODEC_A);
  ok("determinism: the same (master, segment, codec) always derives the same key (uniqueness is binding, not randomness)", bytesEqual(c0, c0again));

  console.log(failures === 0
    ? `\nKEY-SCHEDULE NO-REUSE OK: file keys are domain-separated by purpose and unique per segment / run / codec, deterministic -- no two distinct encryptions can share a key (no AES-GCM (key,nonce) reuse). ${assertions} assertions, net-zero.`
    : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error("KEY-DERIVATION-SEPARATION FAILED:", e instanceof Error ? e.message : e); process.exit(1); });
