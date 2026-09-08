import { b64urlDecode, b64urlEncode, concat } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { noteLocator } from "./integrity-fault-ledger.ts";

// MerkleFrontier is the O(log n) incremental form of merkleRoot (SPEC 11.8): it absorbs
// record hashes one at a time, in manifest order, holding only one subtree root per power
// of two of the count, and folds to a root byte-identical to merkleRoot over the same
// sequence. This is what lets a run with millions of records compute its Merkle root
// across many invocations without ever materialising the leaf list (design F11: "compute
// the Merkle root incrementally (frontier only)").
//
// Why the fold matches: merkleRoot builds levels bottom-up, hashing adjacent pairs and
// promoting an odd node unchanged. That is exactly the left-balanced tree in which every
// maximal complete subtree spans a power-of-two run of leaves, largest first. The
// frontier keeps one root per such subtree (a strictly-decreasing-size stack, merged
// binary-counter style as leaves arrive); the final fold combines them right to left,
// which reproduces the odd-node promotions of the level-by-level build. Parity with
// merkleRoot is pinned by validate-merkle-frontier across sizes including every shape
// up to several levels (powers of two, one-off-either-side, and long runs).
//
// The serialised form is deliberately tiny (one 48-byte hash per set bit of the count,
// so at most ~40 entries) and carries no record names, sizes or plaintext: it is safe to
// persist in checkpoint state where manifest lines are not.

interface FrontierNode {
  sizeLog: number; // this subtree covers 2^sizeLog leaves
  hash: Uint8Array; // its root (an interior node hash, or a leaf hash for sizeLog 0)
}

/**
 * The O(log n) incremental form of merkleRoot (SPEC 11.8): absorb record hashes one at a time in
 * manifest order via append(), then fold to the run's Merkle root via root(). It holds only one
 * subtree root per set bit of the count, so a run with millions of records computes its root
 * across many invocations without materialising the leaf list. serialise()/deserialise() persist
 * the frontier in checkpoint state, carrying only subtree hashes and the leaf count, never any
 * record content.
 */
export class MerkleFrontier {
  private stack: FrontierNode[] = []; // strictly decreasing sizeLog, leftmost first
  private leaves = 0;

  // count is the number of record hashes absorbed so far.
  get count(): number {
    return this.leaves;
  }

  // append absorbs the next record hash in manifest order: leaf-hash it (0x00 domain),
  // push it, then merge equal-sized neighbours (0x01 domain) exactly as the level-by-level
  // build would, so the stack stays one-subtree-per-set-bit of the count.
  async append(recordHash: Uint8Array): Promise<void> {
    let node: FrontierNode = { sizeLog: 0, hash: await sha384(concat(new Uint8Array([0x00]), recordHash)) };
    while (this.stack.length > 0 && this.stack[this.stack.length - 1]!.sizeLog === node.sizeLog) {
      const left = this.stack.pop()!;
      node = { sizeLog: node.sizeLog + 1, hash: await sha384(concat(new Uint8Array([0x01]), left.hash, node.hash)) };
    }
    this.stack.push(node);
    this.leaves++;
  }

  // root folds the frontier to the run's Merkle root. Folding right to left (the
  // smallest, rightmost subtree first) mirrors how the level-by-level build promotes an
  // odd node unchanged until a left neighbour exists: each fold step hashes
  // (left-subtree, accumulated-right) with the 0x01 interior domain. Zero records is the
  // pinned empty-tree root, SHA-384 of the empty string (SPEC 6.5).
  async root(): Promise<Uint8Array> {
    if (this.stack.length === 0) return sha384(new Uint8Array(0));
    let acc = this.stack[this.stack.length - 1]!.hash;
    for (let i = this.stack.length - 2; i >= 0; i--) {
      acc = await sha384(concat(new Uint8Array([0x01]), this.stack[i]!.hash, acc));
    }
    return acc;
  }

  // serialise captures the frontier for checkpoint state: the leaf count and each
  // subtree root, base64url. No names, no sizes, no plaintext.
  serialise(): { count: number; nodes: { sizeLog: number; hash: string }[] } {
    return { count: this.leaves, nodes: this.stack.map((n) => ({ sizeLog: n.sizeLog, hash: b64urlEncode(n.hash) })) };
  }

  // deserialise restores a frontier from checkpoint state, validating the shape: the
  // stack must be strictly decreasing in sizeLog and its subtree sizes must sum to the
  // count, else the state was corrupted and resuming would silently produce a wrong root.
  // These are all SEAL-CHECKPOINT CORRUPTION refusals on resume. The corrupt DO state is transient (the next
  // resume re-reads it), so support needs to see remotely that the CHECKPOINT -- not the source, not the
  // destination -- is the thing failing, and whether the drift is one leaf or wholesale. The ints below say
  // exactly that; the serialised frontier blob itself never rides.
  static deserialise(s: { count: number; nodes: { sizeLog: number; hash: string }[] }): MerkleFrontier {
    const f = new MerkleFrontier();
    let sum = 0;
    let prev = Number.POSITIVE_INFINITY;
    for (const n of s.nodes) {
      if (!Number.isInteger(n.sizeLog) || n.sizeLog < 0 || n.sizeLog >= prev) {
        noteLocator({ kind: "checkpoint-corrupt", shardOrdinal: s.nodes.length });
        throw new Error("merkle frontier state is not strictly decreasing");
      }
      const hash = b64urlDecode(n.hash);
      if (hash.length !== 48) {
        noteLocator({ kind: "checkpoint-corrupt", shardOrdinal: s.nodes.length, recoveredCount: hash.length });
        throw new Error("merkle frontier node is not a SHA-384 hash");
      }
      f.stack.push({ sizeLog: n.sizeLog, hash });
      sum += 2 ** n.sizeLog;
      prev = n.sizeLog;
    }
    if (sum !== s.count) {
      // The count drift is the diagnostic: `declaredCount` is what the checkpoint claims it absorbed,
      // `recoveredCount` is what its subtree stack actually covers.
      noteLocator({ kind: "checkpoint-corrupt", shardOrdinal: s.nodes.length, declaredCount: s.count, recoveredCount: sum });
      throw new Error(`merkle frontier count ${s.count} does not match its ${sum} covered leaves`);
    }
    f.leaves = s.count;
    return f;
  }
}
