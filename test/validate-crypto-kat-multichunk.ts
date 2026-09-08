// Cross-implementation regression guard for the multi-chunk STREAM seal and the name-MAC
// write path. Fixed inputs produce fixed outputs; if any output changes, the cross-language
// interop promise is broken and this test fails.
//
// What this pins:
//   - multi-chunk STREAM seal: 2 full 64 KiB chunks + a 1337-byte partial third chunk,
//     proving the chunk-nonce counter increments correctly, all three GCM tags are right,
//     and the last-chunk flag is set on exactly chunk index 2. The SHA-384 of the sealed
//     output binds every byte including the 16-byte payload nonce prefix, all three
//     ciphertext+tag blocks, and the final payload length.
//   - name-MAC: three HMAC-SHA-384 vectors covering the kv, r2 and secret source types,
//     pinning the domain-separator construction (sourceType || 0x00 || name) and the full
//     derive-MK -> derive-name-MAC-key chain.
//   - round-trip: openStream recovers the original plaintext from the sealed output,
//     proving the chunk-counter and last-chunk flag are mirrored symmetrically in the
//     open path.
//
// Run: node test/validate-crypto-kat-multichunk.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { b64urlDecode, b64urlEncode, hexDecode, hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { deriveCAK, deriveMK, deriveNameMACKey, deriveNonSecretFileKey, nameMAC, segID } from "../src/crypto/derive.ts";
import { sealStream, openStream } from "../src/crypto/stream.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { ADDR_SINGLE_NON_SECRET, CODEC_NONE, CHUNK_SIZE } from "../src/format/version.ts";

const here = dirname(fileURLToPath(import.meta.url));
const kat = JSON.parse(readFileSync(join(here, "vectors", "crypto-kat-multichunk", "kat.json"), "utf8")) as {
  master: string;
  downpipeId: string;
  runId: string;
  multiChunkSeal: {
    plaintextLen: number;
    payloadNonce: string;
    cak: string;
    segIdHex: string;
    fileKey: string;
    sealedLen: number;
    sealedSha384Hex: string;
  };
  nameMAC: {
    nameMACKeyB64: string;
    vectors: Array<{ sourceType: string; name: string; macHex: string }>;
  };
};

let failures = 0;
function check(label: string, got: string, want: string): void {
  if (got === want) {
    console.log(`  ok   ${label}`);
  } else {
    failures++;
    console.log(`  FAIL ${label}\n        got  ${got}\n        want ${want}`);
  }
}
function checkNum(label: string, got: number, want: number): void {
  if (got === want) {
    console.log(`  ok   ${label}`);
  } else {
    failures++;
    console.log(`  FAIL ${label}\n        got  ${got}\n        want ${want}`);
  }
}

// Reproduce the deterministic fill pattern used to generate the vectors.
function fillPlaintext(n: number): Uint8Array {
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
  return b;
}

async function main(): Promise<void> {
  const master = b64urlDecode(kat.master);
  const runIDBytes = decodeULID(kat.runId);

  // ---- multi-chunk STREAM seal -------------------------------------------------------
  console.log("multi-chunk seal:");

  // Sanity: the plaintext length encodes 2 full chunks + 1 partial (3 chunks total).
  const expectedChunks = 3;
  const expectedLen = 2 * CHUNK_SIZE + 1337;
  checkNum("plaintextLen matches 2*CHUNK_SIZE+1337", kat.multiChunkSeal.plaintextLen, expectedLen);

  const plaintext = fillPlaintext(kat.multiChunkSeal.plaintextLen);
  const payloadNonce = b64urlDecode(kat.multiChunkSeal.payloadNonce);

  // Re-derive the key tree from scratch and compare each intermediate.
  const cak = await deriveCAK(master, kat.downpipeId);
  check("CAK", b64urlEncode(cak), kat.multiChunkSeal.cak);

  const segIDBytes = await segID(cak, ADDR_SINGLE_NON_SECRET, new Uint8Array(0), plaintext);
  check("segId", hexEncode(segIDBytes), kat.multiChunkSeal.segIdHex);

  const fileKey = await deriveNonSecretFileKey(master, segIDBytes, CODEC_NONE);
  check("fileKey", b64urlEncode(fileKey), kat.multiChunkSeal.fileKey);

  // Seal and pin the full output via its SHA-384 (binds every byte: nonce, all chunk
  // ciphertexts, all GCM tags, and the correct last-chunk flag on chunk 2).
  const sealed = await sealStream(fileKey, plaintext, payloadNonce);
  checkNum("sealedLen", sealed.length, kat.multiChunkSeal.sealedLen);
  const sealedHash = hexEncode(await sha384(sealed));
  check("SHA-384 of sealed output (pins all 3 chunks, all tags, last-chunk flag)", sealedHash, kat.multiChunkSeal.sealedSha384Hex);

  // Verify the chunk count is exactly 3 (2 full + 1 partial): the STREAM body after the
  // 16-byte nonce prefix is a sequence of (CHUNK_SIZE + 16)-byte sealed chunks, where the
  // last chunk is shorter. Counting the chunks from the sealed length proves the counter
  // incremented to 2 and then stopped.
  const bodyLen = sealed.length - 16; // subtract the payload nonce prefix
  const stride = CHUNK_SIZE + 16; // 64 KiB plaintext + 16-byte GCM tag
  const fullChunks = Math.floor(bodyLen / stride);
  const partialLen = bodyLen % stride;
  const actualChunks = fullChunks + (partialLen > 0 ? 1 : 0);
  checkNum("chunk count is 3 (2 full 64 KiB + 1 partial)", actualChunks, expectedChunks);

  // Round-trip: openStream must recover the original plaintext exactly.
  const reopened = await openStream(fileKey, sealed);
  check("round-trip: openStream recovers the original plaintext", b64urlEncode(reopened), b64urlEncode(plaintext));

  // ---- name-MAC ----------------------------------------------------------------------
  console.log("name-MAC:");

  // Re-derive the nameMACKey from scratch and verify it matches the pinned value.
  const mk = await deriveMK(master, runIDBytes);
  const nmk = await deriveNameMACKey(mk, runIDBytes);
  check("nameMACKey derivation", b64urlEncode(nmk), kat.nameMAC.nameMACKeyB64);

  for (const v of kat.nameMAC.vectors) {
    const mac = await nameMAC(nmk, v.sourceType, v.name);
    check(`nameMAC(${v.sourceType}, ${JSON.stringify(v.name)})`, hexEncode(mac), v.macHex);
  }

  // ---- domain separation: different source types must produce different MACs ----------
  console.log("domain separation:");
  const kvMac = hexDecode(kat.nameMAC.vectors.find((v) => v.sourceType === "kv")!.macHex);
  const r2Mac = hexDecode(kat.nameMAC.vectors.find((v) => v.sourceType === "r2")!.macHex);
  const secretMac = hexDecode(kat.nameMAC.vectors.find((v) => v.sourceType === "secret")!.macHex);
  // All three vectors use different source types so they MUST produce distinct MACs.
  const kv_r2 = hexEncode(kvMac) !== hexEncode(r2Mac);
  const kv_secret = hexEncode(kvMac) !== hexEncode(secretMac);
  const r2_secret = hexEncode(r2Mac) !== hexEncode(secretMac);
  if (kv_r2 && kv_secret && r2_secret) {
    console.log("  ok   all three source types produce distinct MACs (0x00 domain separator works)");
  } else {
    failures++;
    console.log("  FAIL source-type MACs collide (domain separator not working)");
  }

  console.log(failures === 0 ? "\nMULTI-CHUNK KAT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
