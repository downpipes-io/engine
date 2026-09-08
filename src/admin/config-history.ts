// Phase 4 "config as a source": downpipes versions its OWN governance configuration so an operator
// gets git-style history plus a plain-English diff over their backup setup. This module is the PURE,
// SELF-CONTAINED layer (no external dependency): it serialises the versionable config to a stable,
// key-ordered shape, builds the hash-chained, signed history record, and produces the plain-English
// (Australian English) change list between two versions. The scheduler Durable Object holds the chain
// (it is the single storage authority) and drives this logic, exactly as audit.ts is the pure chain
// logic the DO drives; keeping it here means the snapshot, the chain link, and the diff can never be
// computed two different ways across the append, the verify and the validator.
//
// This file is the CHAIN + VERIFY layer. The SNAPSHOT shapes + projection live in the leaf
// ./config-snapshot.ts (ConfigSnapshot etc., snapshotConfig, serialiseSnapshot) and the plain-English
// diff lives in ./config-diff.ts (diffConfig, summarise). Both were MOVED VERBATIM out of this module
// to keep it a readable size; this file re-exports every symbol from both so its existing callers keep
// importing them by name from config-history.ts. The behaviour is unchanged.
//
// PURELY ADDITIVE OBSERVABILITY. Nothing here changes how config is APPLIED and nothing here is an
// approval/deploy gate (that is a separate, later item). A snapshot is a read-only photograph taken
// AFTER a mutation has already committed; it can never alter or block the mutation.
//
// CRYPTO REUSE. The content hash is SHA-384 over canonical JSON, the SAME construction the audit chain
// and the archive/RUNLOG fingerprints use (dpr1:/edmldsa1: are sha384). The signed digest is
// HMAC-SHA-256 over the canonical JSON of the chain-bound fields, keyed with the engine's OWN in-DO
// session-signing key (the 32-byte CSPRNG key the DO generates once and never lets leave the DO; the
// same key signSession/verifySession use). This is the SAME primitive and key the runlog/session path
// relies on for a DO-local signature; it is a SEPARATE, lower-risk store that reuses the crypto, and it
// never touches the data-backup R2 archive or the data backup pipeline.
//
// Node 25 strip-types compatible and Workers-runtime compatible: Web Crypto only, no enums, explicit
// field declarations. TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only
// when it carries a value.

import { ab, b64urlEncode, constantTimeEqual, hexEncode, utf8 } from "../crypto/bytes.ts";
import { sha384, } from "../crypto/primitives.ts";
import { canonicalJSON } from "../format/canonjson.ts";
import type { ChainBreakCause } from "./audit-types.ts";
import { type ConfigSnapshot, serialiseSnapshot } from "./config-snapshot.ts";


// Re-export the plain-English diff layer so existing callers keep importing these by name from
// config-history.ts. They live in ./config-diff.ts.
export type { ChangeKind, ConfigChange } from "./config-diff.ts";
export { diffConfig, SUMMARY_MAX_CHANGES, summarise } from "./config-diff.ts";
// Re-export the snapshot layer (shapes + projection + serialisation) so existing callers keep importing
// these by name from config-history.ts. They live in ./config-snapshot.ts.
export type {
  ConfigCoverageInventory,
  ConfigCustomRole,
  ConfigDownpipe,
  ConfigExpiryItem,
  ConfigGroupRole,
  ConfigNotifyChannel,
  ConfigNotifyRule,
  ConfigRiskAccept,
  ConfigRoleGrant,
  ConfigSnapshot,
  SnapshotInput,
} from "./config-snapshot.ts";
export { serialiseSnapshot, snapshotConfig } from "./config-snapshot.ts";

// ---- The hash-chained, signed history record --------------------------------------------------

// CONFIG_HISTORY_PREFIX keys each version under `confighist:<paddedSeq>` in the scheduler DO, a dedicated
// keyspace entirely separate from the data-backup R2 archive and from the audit `audit:` chain. The seq
// is zero-padded so a storage prefix list returns versions in ascending (oldest-first) order, exactly as
// the audit chain keys do.
export const CONFIG_HISTORY_PREFIX = "confighist:";

// CONFIG_SEQ_PAD matches the audit chain's width so a prefix list is lexicographically == numerically
// ordered well past any realistic version count.
export const CONFIG_SEQ_PAD = 20;

// CONFIG_GENESIS_PREV_HASH is the parentHash placeholder for the first version: "sha384:" + 96 hex zeros
// (a SHA-384 digest is 48 bytes = 96 hex chars), the same genesis sentinel shape the audit chain uses.
export const CONFIG_GENESIS_PREV_HASH = `sha384:${"0".repeat(96)}`;

// CONFIG_HISTORY_CAP bounds how many versions the DO retains so the history cannot grow DO storage
// without limit, the same retention discipline as the audit chain. At the cap the DO rolls the oldest
// versions off (the seq stays monotonic; the retained chain stays internally verifiable from its first
// retained version). Config changes are far rarer than audit events, so a smaller cap is ample.
export const CONFIG_HISTORY_CAP = 2000;

// padConfigSeq renders the version sequence as a fixed-width zero-padded string for the storage key.
export function padConfigSeq(seq: number): string {
  return String(seq).padStart(CONFIG_SEQ_PAD, "0");
}

// configHistoryKey is the storage key for a version: `confighist:00000000000000000042`.
export function configHistoryKey(seq: number): string {
  return CONFIG_HISTORY_PREFIX + padConfigSeq(seq);
}

// ConfigVersion is one hash-chained, signed record of the governance posture at a point in time. It is
// the config-history analogue of an AuditEvent, with the SAME chain construction:
//   - id        the monotonic version sequence (also the storage key suffix);
//   - at        RFC-3339 UTC millis the version was captured (the DO's clock);
//   - author    the verified email that triggered the capturing mutation, or null for the bare-token
//               break-glass or an engine/internal capture (not attributable);
//   - summary   a short auto-generated, redaction-safe one-line description of what changed since the
//               parent (e.g. "downpipe kv:sessions added; alice: operator -> approver"), or the genesis
//               note for the first version;
//   - contentHash  "sha384:" + hex(SHA-384(serialiseSnapshot(snapshot))): commits to the exact posture;
//   - parentHash   the previous version's contentHash, or CONFIG_GENESIS_PREV_HASH for the first version
//                  (this is the chain link);
//   - digest    "edhmac384:" + b64url(HMAC-SHA-256(sessionKey, canonical(chain-bound fields))): the
//               DO-local signature over the record's identity + both hashes, reusing the engine's own
//               in-DO signing key, so a holder cannot forge a record that verifies without the key;
//   - snapshot  the full normalised ConfigSnapshot (so GET version/:id returns the posture, and the diff
//               can read any two versions' snapshots without recomputing them).
export interface ConfigVersion {
  id: number;
  at: string;
  author: string | null;
  summary: string;
  contentHash: string; // "sha384:..."
  parentHash: string; // "sha384:..." (prior version's contentHash, or genesis)
  digest: string; // "edhmac384:..." HMAC-SHA-256 over the chain-bound fields, keyed by the in-DO key
  snapshot: ConfigSnapshot;
}

// DIGEST_PREFIX labels the signed digest so its construction (HMAC-SHA-256, base64url) is unambiguous and
// a future change is detectable, mirroring the "sha384:" hash label and the "ed25519:"/"mldsa87:" sig
// labels the format uses. "edhmac384" reads as "engine-DO HMAC over a 384-bit-hashed body".
const DIGEST_PREFIX = "edhmac384:";

// configContentHash computes a version's content hash: "sha384:" + hex(SHA-384(canonical snapshot)). The
// SAME construction as auditHash, so the two chains hash identically and the validator can recompute it.
export async function configContentHash(snapshot: ConfigSnapshot): Promise<string> {
  return `sha384:${hexEncode(await sha384(serialiseSnapshot(snapshot)))}`;
}

// chainBoundBytes is the EXACT byte body the signed digest covers: the canonical JSON of the version's
// identity and chain fields (id, at, author, summary, contentHash, parentHash) - everything that pins
// this record to its place in the chain and to its content, but NOT the digest itself (which is the
// output) and NOT the snapshot bytes (the contentHash already commits to those, so signing the hash binds
// the snapshot transitively without re-hashing the whole posture into the MAC). Reconstructed explicitly
// (never by deleting a field) so the signed set is stable even if ConfigVersion gains a field later.
function chainBoundBytes(v: Pick<ConfigVersion, "id" | "at" | "author" | "summary" | "contentHash" | "parentHash">): Uint8Array {
  return canonicalJSON({
    id: v.id,
    at: v.at,
    author: v.author,
    summary: v.summary,
    contentHash: v.contentHash,
    parentHash: v.parentHash,
  });
}

// configDigest computes the DO-local signature over a version's chain-bound fields, keyed with the
// engine's own in-DO session-signing key bytes. It is HMAC-SHA-256 over the canonical body. The key is
// the SAME 32-byte CSPRNG secret signSession/verifySession use (generated once, never leaving the DO), so
// this reuses the established DO signing primitive and key rather than introducing a new secret. We call
// crypto.subtle directly here (HMAC-SHA-256) to match the session MAC algorithm exactly; the content hash
// uses sha384 like the rest of the codebase's hashing.
export async function configDigest(
  rawKey: Uint8Array,
  v: Pick<ConfigVersion, "id" | "at" | "author" | "summary" | "contentHash" | "parentHash">,
): Promise<string> {
  const key = await crypto.subtle.importKey("raw", ab(rawKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, ab(chainBoundBytes(v))));
  return DIGEST_PREFIX + b64urlEncode(mac);
}

// buildConfigVersion is the ONE place a version record is constructed, so the append (DO) and any
// re-derivation share identical logic. Given the snapshot, the allocated seq, the timestamp, the author,
// the auto-summary, the parent's contentHash and the in-DO signing key, it computes the content hash and
// the signed digest and returns the full record. It is async (the hash + MAC are async) and pure (no
// storage, no clock - the DO supplies the seq, the ts and the key).
export async function buildConfigVersion(
  snapshot: ConfigSnapshot,
  seq: number,
  at: string,
  author: string | null,
  summary: string,
  parentHash: string,
  rawKey: Uint8Array,
): Promise<ConfigVersion> {
  const contentHash = await configContentHash(snapshot);
  const head = { id: seq, at, author, summary, contentHash, parentHash };
  const digest = await configDigest(rawKey, head);
  return { ...head, digest, snapshot };
}

// ---- Verification ------------------------------------------------------------------------------
// verifyConfigChain recomputes the chain over the versions (which MUST be in ascending id order) and
// reports the first break. A break is any of: a recomputed content hash that does not match the stored
// contentHash (the snapshot was edited); a recomputed signed digest that does not match the stored digest
// (any chain-bound field was tampered, or the record was forged without the key); a parentHash that does
// not equal the prior version's stored contentHash (a version was inserted/deleted/reordered); or an id
// that is not contiguous (each id must be exactly its predecessor's + 1, so a deleted middle version
// yields a gap reported at the version after the hole). The first version establishes the baseline id;
// by default its parentHash must be the genesis sentinel (so deleting the first version is detected),
// unless expectGenesis is false (a documented retention rollover legitimately pruned the genesis, so the
// baseline is taken from the first RETAINED version). This is the config-history analogue of
// audit.ts verifyChain, with the added signed-digest check (the audit chain is hash-only; this chain is
// additionally signed with the in-DO key, so a recompute proves both the hash link AND the signature).
export interface ConfigChainVerdict {
  intact: boolean;
  checkedThrough: number; // the highest id checked (the head), or -1 for an empty history
  earliestId: number; // the lowest id checked (the baseline), or -1 for an empty history
  brokenAt?: number; // the first id whose content hash, digest, parentHash link or id contiguity fails
  // causeClass: WHICH check failed. "Broken at version 41" was one answer for four different
  // investigations -- an edited snapshot, a forged digest, a deleted version, a re-anchored chain. The
  // digest failure maps to recompute-mismatch (the signed bytes no longer match), which is the same class
  // of finding as an edited snapshot: the record does not recompute.
  causeClass?: ChainBreakCause;
}

export interface VerifyConfigChainOptions {
  expectGenesis?: boolean; // default true; false after a documented retention rollover
}

// ---------------------------------------------------------------------------------------------------------
// THE BODY-RETENTION SCAN.
//
// The console's config history is a LIST OF HEADERS (id, at, author, summary, hashes). The thing a version is
// FOR -- the snapshot you would roll back TO -- is the `snapshot` body, and it is read separately (GET
// /config/version/:id). Nothing ever checked that the bodies are still THERE. A version whose body has been
// truncated, half-written, or written by a build with a different shape still lists perfectly: the operator
// sees ten restorable versions in the history and finds out which of them are real only at the moment they try
// to roll back, in the incident. That is a FALSE ASSURANCE about recoverability, which is the same class of
// harm as a backup you cannot restore.
//
// The chain verify cannot stand in for this. verifyConfigChain hashes the snapshot, so a MISSING body makes it
// THROW rather than report (configContentHash serialises it), and a body that is present but structurally
// wrong reports a generic brokenAt that reads identically to content TAMPER. The two need different answers:
// tamper is an investigation, a gone body is a lost rollback point.
//
// Redaction: the scan reads the bodies and returns COUNTS AND VERSION IDS ONLY (engine-minted integers). No
// field of a snapshot -- and a snapshot holds downpipe names, role e-mails, notify channels and webhook hosts
// -- is returned, logged or compared against anything.

// The ConfigSnapshot fields every version's body must carry to be a body you could ROLL BACK to. A snapshot
// missing one of these is not a snapshot: the restore would silently reconstruct an EMPTY posture for whatever
// it lacks (no downpipes, no roles, no notify rules), which is worse than refusing.
const SNAPSHOT_REQUIRED_ARRAYS = ["downpipes", "roles", "groupRoles", "customRoles", "notifyChannels", "notifyRules", "riskAccepts", "expiryItems"] as const;

/** The body-retention verdict over the retained version chain. Counts + engine-minted ids only. */
export interface ConfigBodyScan {
  listed: number; // versions the history LISTS (the number the console shows as restorable)
  readable: number; // versions whose body is actually there and structurally a snapshot: the TRUE rollback count
  missing: number; // versions with NO body at all: the header lists, the snapshot is gone
  unreadable: number; // versions with a body that is not a usable snapshot (truncated, half-written, shape-drifted)
  firstDefectiveId?: number; // the OLDEST version whose body is gone/unusable: everything at or before it is unrecoverable
  newestDefectiveId?: number; // the NEWEST such version: when this is the head, the most recent rollback point is the broken one
}

/**
 * scanConfigBodies checks, for every retained version, whether the BODY the header promises is still readable.
 * PURE and TOTAL: it never throws (a serialise fault is itself a verdict), so it can run BEFORE the chain
 * verify and still report when that verify is the thing that dies.
 *
 * @param versions - the retained chain, ascending by id.
 * @returns the counts + the boundary ids. No snapshot content is ever returned.
 */
export function scanConfigBodies(versions: ConfigVersion[]): ConfigBodyScan {
  const scan: ConfigBodyScan = { listed: versions.length, readable: 0, missing: 0, unreadable: 0 };
  for (const v of versions) {
    const snapshot = (v as { snapshot?: unknown }).snapshot;
    const id = typeof v.id === "number" && Number.isFinite(v.id) ? Math.max(0, Math.floor(v.id)) : 0;
    let verdict: "readable" | "missing" | "unreadable";
    if (snapshot === undefined || snapshot === null) {
      verdict = "missing";
    } else if (typeof snapshot !== "object") {
      verdict = "unreadable";
    } else {
      const s = snapshot as Record<string, unknown>;
      const shaped = SNAPSHOT_REQUIRED_ARRAYS.every((k) => Array.isArray(s[k]));
      let serialisable = false;
      try {
        serialisable = serialiseSnapshot(snapshot as ConfigSnapshot).length > 0;
      } catch {
        serialisable = false; // a body that cannot even be canonicalised can never be rolled back to
      }
      verdict = shaped && serialisable ? "readable" : "unreadable";
    }
    if (verdict === "readable") {
      scan.readable++;
      continue;
    }
    if (verdict === "missing") scan.missing++;
    else scan.unreadable++;
    if (scan.firstDefectiveId === undefined) scan.firstDefectiveId = id;
    scan.newestDefectiveId = id;
  }
  return scan;
}

/**
 * digestBreakCause names WHAT a failed keyed digest actually established about the version's BODY.
 *
 * The body is vouched for only by the SUCCESSOR: its parentHash commits to this version's contentHash and rides
 * inside its own keyed digest. So a successor whose digest verifies is a keyed witness to what this body hashed
 * to, and its verdict is the only one the code may report. With no successor, or a successor whose digest is
 * itself broken, nothing vouches for the body and the honest answer says so rather than asserting intactness.
 *
 * @param successor - the next version in the chain, if this is not the head.
 * @param v - the version whose digest failed.
 * @param rawKey - the in-DO config-history signing key.
 * @returns the closed chain-break cause.
 */
async function digestBreakCause(successor: ConfigVersion | undefined, v: ConfigVersion, rawKey: Uint8Array): Promise<ChainBreakCause> {
  if (successor === undefined) return "digest-unvouched"; // the head: no successor can speak for its body
  const successorDigest = await configDigest(rawKey, successor);
  if (!constantTimeEqual(utf8(successorDigest), utf8(successor.digest))) return "digest-unvouched"; // the witness is broken too
  return successor.parentHash === v.contentHash ? "envelope-digest-mismatch" : "content-swapped";
}

/**
 * verifyConfigChainUnkeyed runs the checks that need NO KEY AT ALL over the WHOLE chain.
 *
 * WHY IT EXISTS. verifyConfigChain returns at the FIRST break, and every keyed digest fails when the in-DO
 * signing key has been regenerated or lost -- which an OWNER can do with one audited button (POST
 * /passkey/session/terminate-all deletes the passkey session key). So on a rotated key the verify stopped at
 * version 1's digest, never looked at 2..N, and the recorder displaced the whole digest family to
 * signing-key-rotated, a class whose documentation asserted "nothing was tampered at all". The result was a
 * ONE-BUTTON MASK: press it, and every config-history tamper reads as a key rotation.
 *
 * The content hashes, the parent links and the id contiguity are UNKEYED. A rotated key cannot fake or break
 * ONE of them. So the key fact may only be reported as "nothing was tampered" once THIS pass has run over the
 * whole chain and come back clean; when it does not, its cause is latched too, at the version it broke on.
 *
 * Pure, and it never throws for a reason a verify would: an unhashable snapshot propagates exactly as it does
 * in verifyConfigChain (the caller already treats a throw as missing-version).
 *
 * @param versions - the retained chain, oldest first.
 * @param opts - genesis expectation, as verifyConfigChain.
 * @returns intact, or the FIRST unkeyed break with its closed cause.
 */
export async function verifyConfigChainUnkeyed(versions: ConfigVersion[], opts?: VerifyConfigChainOptions): Promise<ConfigChainVerdict> {
  if (versions.length === 0) return { intact: true, checkedThrough: -1, earliestId: -1 };
  const expectGenesis = opts?.expectGenesis ?? true;
  const earliestId = versions[0]!.id;
  let prev: ConfigVersion | null = null;
  for (const v of versions) {
    if (prev === null) {
      if (expectGenesis && v.parentHash !== CONFIG_GENESIS_PREV_HASH) return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "genesis-link" };
    } else if (v.parentHash !== prev.contentHash) {
      return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "prev-hash-mismatch" };
    }
    if (prev !== null && v.id !== prev.id + 1) return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "seq-gap" };
    const recomputedContent = await configContentHash(v.snapshot);
    if (recomputedContent !== v.contentHash) return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "recompute-mismatch" };
    prev = v;
  }
  return { intact: true, checkedThrough: versions[versions.length - 1]!.id, earliestId };
}

export async function verifyConfigChain(
  versions: ConfigVersion[],
  rawKey: Uint8Array,
  opts?: VerifyConfigChainOptions,
): Promise<ConfigChainVerdict> {
  if (versions.length === 0) return { intact: true, checkedThrough: -1, earliestId: -1 };
  const expectGenesis = opts?.expectGenesis ?? true;
  const earliestId = versions[0]!.id;
  let prev: ConfigVersion | null = null;
  for (let i = 0; i < versions.length; i++) {
    const v = versions[i]!;
    // The link: parentHash must equal the prior version's stored contentHash. For the first version
    // there is no retained predecessor: when expectGenesis is true it must link to the genesis sentinel;
    // when false (a rollover) its parentHash links to a now-pruned predecessor and is accepted as the
    // baseline. A mismatch from the second version onward means an insert/delete/reorder.
    if (prev === null) {
      if (expectGenesis && v.parentHash !== CONFIG_GENESIS_PREV_HASH) return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "genesis-link" };
    } else if (v.parentHash !== prev.contentHash) {
      return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "prev-hash-mismatch" };
    }
    // Contiguity: after the baseline, each id must be exactly prev.id + 1. A gap means a version was
    // deleted even if the hashes were re-linked around the hole.
    if (prev !== null && v.id !== prev.id + 1) return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "seq-gap" };
    // The content: the stored contentHash must recompute from the stored snapshot. A mismatch means the
    // snapshot was edited in place.
    const recomputedContent = await configContentHash(v.snapshot);
    if (recomputedContent !== v.contentHash) return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass: "recompute-mismatch" };
    // The signature: the stored digest must recompute from the chain-bound fields under the in-DO key. A
    // mismatch means a chain-bound field (id/at/author/summary/contentHash/parentHash) was tampered, or
    // the record was forged without the key.
    const recomputedDigest = await configDigest(rawKey, v);
    // Compare the HMAC digest in constant time (over the hex bytes) to avoid a timing side-channel,
    // matching session.ts/recovery.ts/saml dsig. constantTimeEqual returns false on differing lengths.
    //
    // G313 (R4): A DIGEST FAILURE DOES NOT ESTABLISH THAT THE BODY IS INTACT, and the shipped class said it did.
    //
    // The recompute above proves only that the snapshot hashes to its OWN STORED contentHash. contentHash is one
    // of the six fields the keyed envelope covers, and configContentHash takes NO KEY -- so an attacker with write
    // access to the stored version (the only actor who can reach either state) can rewrite the body AND refresh
    // its unkeyed contentHash. That version then PASSES the recompute and FAILS the digest, landing on a class
    // whose documentation told support "the body is intact and verifies cleanly" while the body was the
    // attacker's. That is the fault this gap exists to prevent, inverted.
    //
    // WHAT ACTUALLY VOUCHES FOR THE BODY is the SUCCESSOR. Its parentHash commits to this version's contentHash,
    // and the successor's parentHash is itself inside the successor's KEYED digest. So:
    //   the successor's digest verifies AND its parentHash equals this contentHash
    //       -> the body IS keyed-vouched: only the envelope's own fields were rewritten (attribution), or the
    //          record was minted without the key. envelope-digest-mismatch, honestly.
    //   the successor's digest verifies AND its parentHash does NOT equal this contentHash
    //       -> the successor's KEYED word is that this body hashed to something else. The body was swapped and
    //          re-hashed. content-swapped.
    //   there is NO successor (this is the head), or the successor's digest does not verify either
    //       -> NOTHING vouches for the body, and the code cannot separate the two. Say so. digest-unvouched.
    if (!constantTimeEqual(utf8(recomputedDigest), utf8(v.digest))) {
      const causeClass = await digestBreakCause(versions[i + 1], v, rawKey);
      return { intact: false, checkedThrough: v.id, earliestId, brokenAt: v.id, causeClass };
    }
    prev = v;
  }
  return { intact: true, checkedThrough: versions[versions.length - 1]!.id, earliestId };
}
