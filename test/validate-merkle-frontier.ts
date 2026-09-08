// Prove the incremental Merkle frontier folds to a root byte-identical to merkleRoot
// (SPEC 11.8, RFC 6962 with odd-node promotion) for every tree shape that exercises the
// promotion logic: all sizes 0..130 (every shape up to eight levels), the one-off-a-power
// sizes around 256 and 512, and a long 1031-leaf run; that a frontier serialised and
// deserialised mid-stream resumes to the identical root (the checkpoint property the
// sliced seal relies on); and that a corrupted serialised frontier is refused rather than
// silently resuming to a wrong root.
// Run: node test/validate-merkle-frontier.ts

import { merkleRoot } from "../src/format/merkle.ts";
import { MerkleFrontier } from "../src/format/frontier.ts";
import { hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// Deterministic distinct record hashes (the real ones are SHA-384 outputs; any 48 bytes do).
async function recordHash(i: number): Promise<Uint8Array> {
  return sha384(new TextEncoder().encode(`record-${i}`));
}

async function rootViaFrontier(hashes: Uint8Array[]): Promise<Uint8Array> {
  const f = new MerkleFrontier();
  for (const h of hashes) await f.append(h);
  return f.root();
}

async function main(): Promise<void> {
  console.log("merkle frontier parity:");
  const sizes: number[] = [];
  for (let n = 0; n <= 130; n++) sizes.push(n);
  sizes.push(255, 256, 257, 511, 512, 513, 1031);

  const all: Uint8Array[] = [];
  for (let i = 0; i < 1031; i++) all.push(await recordHash(i));

  let parity = true;
  for (const n of sizes) {
    const leaves = all.slice(0, n);
    const a = hexEncode(await merkleRoot(leaves));
    const b = hexEncode(await rootViaFrontier(leaves));
    if (a !== b) {
      parity = false;
      console.log(`  FAIL parity at n=${n}: merkleRoot ${a.slice(0, 16)} != frontier ${b.slice(0, 16)}`);
    }
  }
  ok(`frontier root matches merkleRoot for all ${sizes.length} sizes (0..130, around 256/512, 1031)`, parity);

  console.log("checkpoint resume:");
  {
    // Serialise mid-stream at several cut points, deserialise, finish, and compare.
    for (const cut of [1, 2, 63, 64, 65, 100]) {
      const f = new MerkleFrontier();
      for (let i = 0; i < cut; i++) await f.append(all[i]!);
      const resumed = MerkleFrontier.deserialise(JSON.parse(JSON.stringify(f.serialise())));
      ok(`count survives serialise at ${cut}`, resumed.count === cut);
      for (let i = cut; i < 130; i++) await resumed.append(all[i]!);
      const direct = hexEncode(await merkleRoot(all.slice(0, 130)));
      ok(`resume at ${cut} folds to the direct root`, hexEncode(await resumed.root()) === direct);
    }
  }

  console.log("corrupted state is refused:");
  {
    const f = new MerkleFrontier();
    for (let i = 0; i < 5; i++) await f.append(all[i]!);
    const s = f.serialise();
    const wrongCount = { ...s, count: s.count + 1 };
    let threw = false;
    try {
      MerkleFrontier.deserialise(wrongCount);
    } catch {
      threw = true;
    }
    ok("a count that does not match the covered leaves is refused", threw);

    const notDecreasing = { count: 2, nodes: [{ sizeLog: 0, hash: s.nodes[0]!.hash }, { sizeLog: 0, hash: s.nodes[0]!.hash }] };
    threw = false;
    try {
      MerkleFrontier.deserialise(notDecreasing);
    } catch {
      threw = true;
    }
    ok("a non-decreasing stack is refused", threw);

    const badHash = { count: 1, nodes: [{ sizeLog: 0, hash: "AAAA" }] };
    threw = false;
    try {
      MerkleFrontier.deserialise(badHash);
    } catch {
      threw = true;
    }
    ok("a non-SHA-384 node is refused", threw);
  }

  console.log(failures === 0 ? "\nMERKLE FRONTIER MATCHES MERKLEROOT" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
