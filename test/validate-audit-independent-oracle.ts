// The HARNESS-OWNED independent audit-chain oracle. The shipped chain verifier re-verifies with
// the product's OWN verifyChain (validate-audit-chain.ts PROOF 7), so a hashing bug shared by the writer and
// the verifier -- a field silently dropped from the hashed set, a canonicalisation divergence -- would be
// invisible: the trail would "verify" against a hash that is wrong in the same way it was written. This
// module is the second opinion. It re-implements the SHA-384-over-canonical-JSON digest from the DOCUMENTED
// hashed-field set, importing NEITHER auditHash NOR verifyChain NOR the product's canonicalJSON, and it uses
// node:crypto (OpenSSL) rather than the runtime's Web Crypto (crypto.subtle) that the product hashes with, so
// the two implementations share no code path. It is TWO-SIDED and self-checking by construction: the positive
// control requires it to AGREE with every clean entry (so an oracle whose canonicalisation had drifted from
// the product's is caught before it can bless a tamper), and every tamper refuter requires it to DISAGREE
// with the tampered entry (so it cannot silently rubber-stamp the product's hashing).
//
// The ONLY product symbol imported is the AuditEvent TYPE, which is erased at runtime and carries no logic.

import { createHash } from "node:crypto";
import type { AuditEvent } from "../src/admin/audit.ts";

// The genesis prev-hash sentinel: "sha384:" followed by 96 hex zeros (a SHA-384 digest is 48 bytes = 96 hex
// chars). Defined here INDEPENDENTLY of the product's GENESIS_PREV_HASH so the oracle owns its own baseline
// and a change to the product constant cannot silently move the oracle's genesis expectation.
export const INDEP_GENESIS_PREV_HASH = `sha384:${"0".repeat(96)}`;

// indepCanon serialises a value to canonical JSON, matching SPEC 11.1 (object keys sorted by UTF-16 code
// unit, no insignificant whitespace, integers only, no HTML escaping) so that for a well-formed audit entry
// it produces byte-for-byte what the product's canonicalJSON produces. It is written from the spec, not
// copied from canonjson.ts, so a divergence in the product's canonicaliser would show up as a positive-
// control disagreement rather than being reproduced here. The lone-surrogate rejection and safe-integer
// ceiling the product enforces are omitted deliberately: no audit entry the harness mints carries either, so
// they cannot fire, and leaving them out keeps this a genuinely separate implementation.
function indepCanon(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v)) throw new Error(`independent oracle: non-integer number ${v} is not canonicalisable`);
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(indepCanon).join(",")}]`;
  if (typeof v === "object") {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj).sort(); // default JS sort is UTF-16 code-unit order, matching SPEC 11.1
    return `{${keys.map((k) => `${JSON.stringify(k)}:${indepCanon(obj[k])}`).join(",")}}`;
  }
  throw new Error(`independent oracle: unsupported value in canonical JSON: ${typeof v}`);
}

// independentAuditDigest recomputes an entry's chain hash from the DOCUMENTED hashed-field set (audit.ts
// auditHash: seq, ts, actorEmail, actorMethod, sourceIp, action, outcome, target, prevHash, plus actorSubject
// only when it is a string and advisory only when present). It hashes the independently-canonicalised bytes
// with node:crypto SHA-384 and lowercase-hex-encodes them, so a correct entry's stored hash reproduces here
// and a tampered entry's does not. It never reads the entry's own `hash` field, so it cannot be fooled by a
// stored hash the writer got wrong.
export function independentAuditDigest(e: AuditEvent): string {
  const hashed: Record<string, unknown> = {
    seq: e.seq,
    ts: e.ts,
    actorEmail: e.actorEmail,
    actorMethod: e.actorMethod,
    sourceIp: e.sourceIp,
    action: e.action,
    outcome: e.outcome,
    target: e.target,
    prevHash: e.prevHash,
  };
  // Fold actorSubject in ONLY when it is a string, and advisory ONLY when present: this is the documented
  // backward-compatible inclusion rule, so a null/omitted subject (an engine-observed or unattributed entry)
  // hashes exactly as a legacy entry did.
  if (typeof e.actorSubject === "string") hashed.actorSubject = e.actorSubject;
  if (e.advisory !== undefined) hashed.advisory = e.advisory;
  const hex = createHash("sha384").update(indepCanon(hashed), "utf8").digest("hex");
  return `sha384:${hex}`;
}

// IndepVerdict is the oracle's verdict over an ordered chain: intact through checkedThrough, or the first seq
// at which a break was found with the CLOSED cause that matches the product's four audit causes (genesis-link,
// prev-hash-mismatch, seq-gap, recompute-mismatch), so a cell can cross-check the oracle's cause against the
// product's without importing the product's verify.
export interface IndepVerdict {
  intact: boolean;
  earliestSeq: number;
  checkedThrough: number;
  brokenAt?: number;
  causeClass?: "genesis-link" | "prev-hash-mismatch" | "seq-gap" | "recompute-mismatch";
}

// walkChainIndependently re-derives the chain over entries in ASCENDING seq order and reports the first break,
// checking the SAME three invariants the product does and in the SAME order (the link, then seq contiguity,
// then the content recompute), so its cause lines up with verifyChain's. It imports no product logic: the link
// check compares stored hashes, the contiguity check compares seqs, and the content check calls the oracle's
// own independentAuditDigest. By default the first entry must be the true genesis; after a documented retention
// rollover the caller passes expectGenesis:false to take the baseline from the first RETAINED entry, exactly as
// the product's verifyChain does, so a legitimate rollover is not read as a genesis break. This walk is BLIND
// to a truncated tail by design (the survivors stay perfectly linked); the tail is the head-anchor witness's
// job, and the tail-truncation cell asserts the oracle's blindness here alongside the anchor catching it.
export function walkChainIndependently(entries: AuditEvent[], opts?: { expectGenesis?: boolean }): IndepVerdict {
  if (entries.length === 0) return { intact: true, earliestSeq: -1, checkedThrough: -1 };
  const expectGenesis = opts?.expectGenesis ?? true;
  const earliestSeq = entries[0]!.seq;
  let prev: AuditEvent | null = null;
  for (const e of entries) {
    if (prev === null) {
      if (expectGenesis && e.prevHash !== INDEP_GENESIS_PREV_HASH) {
        return { intact: false, earliestSeq, checkedThrough: e.seq, brokenAt: e.seq, causeClass: "genesis-link" };
      }
    } else if (e.prevHash !== prev.hash) {
      return { intact: false, earliestSeq, checkedThrough: e.seq, brokenAt: e.seq, causeClass: "prev-hash-mismatch" };
    }
    if (prev !== null && e.seq !== prev.seq + 1) {
      return { intact: false, earliestSeq, checkedThrough: e.seq, brokenAt: e.seq, causeClass: "seq-gap" };
    }
    if (independentAuditDigest(e) !== e.hash) {
      return { intact: false, earliestSeq, checkedThrough: e.seq, brokenAt: e.seq, causeClass: "recompute-mismatch" };
    }
    prev = e;
  }
  return { intact: true, earliestSeq, checkedThrough: entries[entries.length - 1]!.seq };
}
