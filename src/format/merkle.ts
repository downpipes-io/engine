import { concat } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";

// RFC 6962 Merkle tree over SHA-384 (SPEC 11.8), matching internal/format/merkle.go:
// leaf = SHA-384(0x00 || recordHash), node = SHA-384(0x01 || left || right), an odd node
// promoted unchanged, the empty tree the SHA-384 of the empty string.

/**
 * Computes the RFC 6962 Merkle root over SHA-384 (SPEC 11.8): leaf = SHA-384(0x00 || recordHash),
 * node = SHA-384(0x01 || left || right), an odd node promoted unchanged, and the empty tree the
 * SHA-384 of the empty string.
 *
 * @param recordHashes - the record hashes, in manifest order, as the tree leaves.
 * @returns the 48-byte Merkle root.
 */
export async function merkleRoot(recordHashes: Uint8Array[]): Promise<Uint8Array> {
  if (recordHashes.length === 0) return sha384(new Uint8Array(0));
  let level: Uint8Array[] = [];
  for (const rh of recordHashes) level.push(await sha384(concat(new Uint8Array([0x00]), rh)));
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(await sha384(concat(new Uint8Array([0x01]), level[i]!, level[i + 1]!)));
      } else {
        next.push(level[i]!); // odd node promoted unchanged
      }
    }
    level = next;
  }
  return level[0]!;
}
