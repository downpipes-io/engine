// The chain-verification vocabulary shared by the audit chain and the config-history chain: the verdict a
// verify returns, its closed break causes, and the genesis option. It is a pure leaf with no imports.
// audit-types.ts re-exports every symbol here, so importers keep their one path.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.

// ChainVerdict is the GET /admin/audit/verify result: intact through checkedThrough (the head
// seq), or the first seq at which the chain breaks. A break is a RESULT, not an error: the route
// still returns 200 and the console shows "break detected at entry N". earliestSeq is the lowest
// seq actually verified (the baseline), so after a retention rollover the console can show that the
// retained chain legitimately begins above seq 1 rather than at genesis; it is -1 for an empty log.
export interface ChainVerdict {
  intact: boolean;
  checkedThrough: number; // the highest seq checked (the head seq), or -1 for an empty log
  earliestSeq: number; // the lowest seq checked (the baseline), or -1 for an empty log
  brokenAt?: number; // the first seq whose stored hash or prevHash does not recompute/link
  // causeClass names WHICH of the four checks failed. "Broken at version 41" cannot distinguish an
  // EDITED snapshot (recompute-mismatch: someone changed a stored entry) from a FORGED digest
  // (prev-hash-mismatch: an entry was inserted or reordered) from a DELETED entry (seq-gap) from a chain that
  // no longer links to genesis (genesis-link). Those are four different investigations, and the verdict used
  // to give the same answer to all four. A closed enum, derived from the branch that fired; never a value.
  causeClass?: ChainBreakCause;
}

// The closed cause of ONE chain break. Shared by the audit chain and the config-history chain.
//
// "recompute-mismatch" cannot answer for TWO INDEPENDENT CHECKS on the config-history chain, because they are
// different incidents with different blast radii. The contentHash covers the SNAPSHOT BYTES. The HMAC digest
// covers the ENVELOPE around them (id/at/author/summary/contentHash/parentHash), NOT the snapshot.
//
// The split alone would assert a fact the code has never established. configContentHash takes NO KEY,
// so the only actor who can rewrite a stored version -- the only actor who can produce EITHER state -- can also
// refresh the unkeyed contentHash. That version passes the recompute and fails the digest, and the pack told
// support "the body is INTACT and verifies cleanly" about a body that was the attacker's. What actually vouches
// for a body is the SUCCESSOR's parentHash, which commits to it and rides inside the successor's KEYED digest.
// So the digest family is now three honest causes, and each says only what was proven:
//
//   recompute-mismatch        the body at version 41 no longer hashes to its own stored contentHash: it was
//                             rewritten in place by someone who did not bother to refresh the hash.
//   content-swapped           the body was rewritten AND re-hashed. The successor's VALID keyed envelope commits
//                             to a DIFFERENT contentHash for version 41, so the successor's own key-bound word is
//                             that this is not the body that was there.
//   envelope-digest-mismatch  the successor's VALID keyed envelope commits to EXACTLY this body, so the body is
//                             keyed-vouched. What was rewritten is the record's ATTRIBUTION (who changed it, and
//                             when), or the record was minted without the DO's HMAC key.
//   digest-unvouched          the digest failed on the HEAD version (no successor exists), or on a version whose
//                             successor's digest is broken too. NOTHING vouches for the body, so the code cannot
//                             separate a swapped body from a forged attribution. It says that, rather than
//                             picking one.
//   head-truncated            the retained chain's HEAD sits BELOW the head this DO itself committed to (the
//                             persisted head anchor: auditHead's seq+hash, config-history's id+contentHash), or
//                             sits AT it with a different hash. The newest entries -- the ones that record what
//                             was just done -- were REMOVED or REWRITTEN. Retention rolls the OLDEST entries off
//                             and never lowers the anchor, so a rollover cannot produce this. It needs NO key:
//                             the anchor is an unkeyed witness already in storage, and the recompute passes
//                             cannot see the deletion at all (a truncated tail leaves the survivors perfectly
//                             linked, which is why "delete the newest rows" read INTACT until R6).
//   signing-key-rotated       the in-DO HMAC key was regenerated or lost, so EVERY digest in the chain fails and
//                             the KEYED check proves nothing either way. The engine models this as recoverable
//                             context (configHistorySigningKeyRotated), and a latch that reported forgery for it
//                             was pointing support at an attacker who does not exist.
//
//                             WHAT THE KEY-FREE PASS PROVES, AND WHAT IT CANNOT. unkeyedIntact=true means
//                             exactly this: NO LAZY TAMPER. No stale content hash, no broken parent link, no id
//                             gap. It does NOT mean "not tamper". Once the key is gone, nothing unkeyed vouches
//                             for the HEAD version's body (no successor commits to it), for a rewritten body
//                             whose successor's parentHash was RE-LINKED to match, or for ANY version's
//                             attribution (the author and the timestamp live only inside the keyed envelope).
//                             Every one of those is recomputable for free by the only actor who can reach this
//                             state: they already hold DO-storage write, and they have just destroyed the one
//                             thing they could not forge. So this cause means "the rotation explains every KEYED
//                             failure, and the unkeyed checks find no careless edit" -- never "this is not
//                             tamper". A key-free pass cannot exclude a re-linked body, the head body, or a
//                             forged author, and the pack must not read as an all-clear.
//
//                             IT DOES NOT SAY "NOTHING WAS TAMPERED". verifyConfigChain
//                             returns at the FIRST break, so with the key gone it dies on version 1's digest and
//                             never examines 2..N -- and the key can be destroyed by an OWNER BUTTON (terminate
//                             all sessions deletes the passkey session key), so any actor with the DO-storage
//                             write access a tamper already requires could press it and convert every
//                             config-history tamper into the row that says nothing happened. A one-button mask.
//                             The recorder therefore runs the UNKEYED pass -- body recompute, parentHash link, id
//                             contiguity, none of which a key can fake or break -- over the WHOLE chain, and
//                             latches this cause only when that pass is CLEAN. When it is not, the unkeyed cause
//                             is latched AT ITS OWN SEQ beside this one, so a rotated key and a rewritten version
//                             are two rows, not one.
//
// The audit chain has no HMAC envelope, so its four causes are unaffected.
//
// SUPPORTING: seq-gap on config-history is reachable only if a deleter ALSO re-links the survivor's
// parentHash. A plain deletion breaks the LINK first and reports prev-hash-mismatch at the survivor, because the
// parent-hash check runs before the contiguity check.
export const CHAIN_BREAK_CAUSES = ["genesis-link", "prev-hash-mismatch", "seq-gap", "recompute-mismatch", "envelope-digest-mismatch", "content-swapped", "digest-unvouched", "signing-key-rotated", "missing-version", "head-truncated"] as const;
export type ChainBreakCause = (typeof CHAIN_BREAK_CAUSES)[number];

// VerifyChainOptions tunes the genesis-linkage check. By default verifyChain expects the first
// entry to be the TRUE genesis (seq 1 linking to GENESIS_PREV_HASH), so deleting the genesis from a
// chain that never rolled over is still detected as a break at the new first entry. After a
// documented retention rollover the chain legitimately begins above seq 1 with a first entry whose
// prevHash links to a now-pruned predecessor, so the caller (the DO, which knows a rollover
// happened) passes expectGenesis:false to take the baseline from the first RETAINED entry instead of
// failing because genesis is gone. This does NOT weaken tamper-evidence within the retained set:
// every retained entry's hash must still recompute, every link from the second retained entry
// onward must match its predecessor's stored hash, and the seqs must stay contiguous; only the "the
// first entry must be genesis" assertion is relaxed, and only when the DO has recorded a rollover.
export interface VerifyChainOptions {
  expectGenesis?: boolean; // default true; false after a documented retention rollover
}
