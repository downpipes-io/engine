import { concat, utf8 } from "../crypto/bytes.ts";
import { hybridSign } from "../crypto/sign.ts";
import { canonicalJSON } from "./canonjson.ts";
import { validateCanonicalCounts } from "./canonnum.ts";
import { noteRunlogAnomaly } from "./integrity-fault-ledger.ts";

// The RUNLOG freshness anchor (SPEC 10): the writer's serialise/sign and the
// read-append-resign parse path. Split out of writer.ts so the archive writer stays under
// the structural ceiling while the public API (re-exported from writer.ts) is unchanged.

/**
 * One line of the signed _RECOVERY/RUNLOG freshness anchor (SPEC 10): the account-global index,
 * the run and downpipe ids, the time, the record count, the previous run id and the status. The
 * engine accumulates these across runs (read, append, re-sign, write); the writer serialises and
 * signs whatever list it is given.
 */
export interface RunlogEntry {
  index: number;
  runId: string;
  downpipeId: string;
  time: string;
  recordCount: number;
  prevRunId: string | null;
  status: string;
}

/**
 * Builds the RUNLOG entry for a single run from its write params, with status "active".
 *
 * @param p - the run's identity and counts (index, run and downpipe ids, createdAt, record count,
 *   previous run id).
 * @returns the RUNLOG entry for this run.
 */
export function thisRunEntry(p: { runlogIndex: number; runId: string; downpipeId: string; createdAt: string; records: { length: number }; prevRunId: string | null }): RunlogEntry {
  return { index: p.runlogIndex, runId: p.runId, downpipeId: p.downpipeId, time: p.createdAt, recordCount: p.records.length, prevRunId: p.prevRunId, status: "active" };
}

/**
 * Serialises an append-only RUNLOG (NDJSON of canonical entries) and produces its detached hybrid
 * signature. The pipeline uses this to write the accumulated log.
 *
 * @param entries - the RUNLOG entries to serialise, in order.
 * @param edPrivate - the run signer's Ed25519 private key.
 * @param mldsaSecret - the run signer's ML-DSA-87 secret key.
 * @returns the serialised RUNLOG bytes and the detached hybrid signature.
 */
export async function signRunlog(entries: RunlogEntry[], edPrivate: CryptoKey, mldsaSecret: Uint8Array): Promise<{ runlog: Uint8Array; sig: Uint8Array }> {
  const parts: Uint8Array[] = [];
  for (const e of entries) parts.push(canonicalJSON(e), utf8("\n"));
  const runlog = concat(...parts);
  const sig = await hybridSign(edPrivate, mldsaSecret, runlog);
  return { runlog, sig };
}

/**
 * Parses an NDJSON RUNLOG into its entries (for read-append-resign and the freshness anti-rollback
 * check). Each line's canonical-numeric form (the index and recordCount fields) is validated before
 * it is parsed, mirroring the Go reference ParseRunlog, so a signed RUNLOG carrying an out-of-range
 * or non-canonical index cannot defeat the anti-rollback min-pin. The security-critical fields the
 * freshness check anchors on (index, runId, downpipeId) are then shape-checked, so a line whose index
 * passes the canonical-number guard but whose other fields are missing or the wrong type is rejected
 * here rather than silently mis-anchoring the freshness check through a false-confidence cast.
 *
 * @param bytes - the serialised NDJSON RUNLOG bytes.
 * @returns the parsed RUNLOG entries.
 * @throws Error when any line's index or recordCount is non-canonical or out of range, or when a line
 *   is missing the index, runId or downpipeId field (or carries the wrong type for it).
 */
export function parseRunlog(bytes: Uint8Array): RunlogEntry[] {
  const text = new TextDecoder().decode(bytes);
  const lines = text.split("\n").filter((l) => l.length > 0);
  // G102: a RUNLOG that will not parse is the CORRUPTION half of the tamper-vs-corruption question. The line
  // ORDINAL (an int) and the document's line COUNT are the locus; the closed parse-field kind is the mode.
  // The line's CONTENT -- which is a customer's run ids, downpipe ids and timestamps -- never rides, and the
  // throw is unchanged.
  return lines.map((l, i) => {
    try {
      validateCanonicalCounts(l, "index", "recordCount");
      const e = JSON.parse(l) as Record<string, unknown>;
      if (typeof e.index !== "number" || !Number.isInteger(e.index)) throw new Error("RUNLOG entry index must be an integer");
      if (typeof e.runId !== "string" || e.runId === "") throw new Error("RUNLOG entry runId must be a non-empty string");
      if (typeof e.downpipeId !== "string" || e.downpipeId === "") throw new Error("RUNLOG entry downpipeId must be a non-empty string");
      return e as unknown as RunlogEntry;
    } catch (err) {
      noteRunlogAnomaly({ kind: "parse-field", lineOrdinal: i, entryCount: lines.length });
      throw err;
    }
  });
}
