// The D1 resume token: opaque engine-internal JSON the slice persists in checkpoint state. It carries
// the snapshot bookmark (so a resumed slice re-opens the SAME point in time) and a position:
//   - phase "header": next emit is the header (a fresh crawl before the header mark; not normally a
//     token value -- a fresh crawl uses a null token -- but accepted for completeness).
//   - phase "rows": next emit is table `ti`'s rows after rowid `afterRowid` (a decimal string, or
//     null to start the table). ti past the last table falls through to schema.
//   - phase "schema": next emit is the schema record.
//   - phase "done": nothing left.
// It carries NO value bytes and is safe to persist.

import { type ResumeTokenDefect, recordResumeFatal, recordResumeTokenDefect } from "./source-fault-ledger.ts";

export type TokenPhase = "header" | "rows" | "schema" | "done";

export type ResumeToken =
  | { bookmark: string | null; phase: "header" }
  | { bookmark: string | null; phase: "rows"; ti: number; afterRowid: string | null }
  | { bookmark: string | null; phase: "schema" }
  | { bookmark: string | null; phase: "done" };

export function encodeToken(t: ResumeToken): string {
  return JSON.stringify(t);
}

// parseToken REJECTS a malformed token rather than coercing it (support-pack gaps G096/G213). Coercing a
// corrupt field to null instead would be a DATA-INTEGRITY bug that surfaces only in the RESTORE, long after
// the run reports ok:
//   - a malformed `bookmark` coerced to null would re-open a DIFFERENT snapshot on resume, mixing two points
//     in time in the archive (restored rows referencing rows that do not exist);
//   - a malformed `afterRowid` coerced to null would RESTART the table and re-emit already-sealed rows
//     (duplicated rows in the restore).
// So both throw instead. A corrupt token is not a recoverable condition to paper over: failing the slice
// loudly is strictly safer than sealing an archive whose consistency the engine cannot vouch for, and the
// operator has a known remediation (clear the resume token). Every defect is recorded under its CLOSED class
// first, so the wedge is legible in the support pack instead of reading as a generic "run failed".
export function parseToken(token: string): ResumeToken {
  let parsed: unknown;
  try {
    parsed = JSON.parse(token);
  } catch {
    throw resumeTokenError("unparseable");
  }
  if (typeof parsed !== "object" || parsed === null) throw resumeTokenError("bad-shape");
  const o = parsed as Record<string, unknown>;
  // A bookmark must be null (a fresh crawl) or a string. Anything else is corruption: re-anchoring the crawl
  // to a fresh snapshot behind the operator's back is exactly the mixed-snapshot fault (G096).
  if (!(o.bookmark === null || typeof o.bookmark === "string")) throw resumeTokenError("bad-bookmark");
  const bookmark = o.bookmark as string | null;
  switch (o.phase) {
    case "header":
      return { bookmark, phase: "header" };
    case "rows": {
      if (typeof o.ti !== "number" || !Number.isInteger(o.ti) || o.ti < 0) throw resumeTokenError("bad-index");
      // A cursor must be null (start of table) or a decimal integer string. Coercing a corrupt cursor to null
      // silently re-emits sealed rows (G096); reject it instead.
      if (!(o.afterRowid === null || (typeof o.afterRowid === "string" && /^-?\d+$/.test(o.afterRowid)))) throw resumeTokenError("bad-cursor");
      const afterRowid = o.afterRowid as string | null;
      return { bookmark, phase: "rows", ti: o.ti, afterRowid };
    }
    case "schema":
      return { bookmark, phase: "schema" };
    case "done":
      return { bookmark, phase: "done" };
    default:
      throw resumeTokenError("bad-phase");
  }
}

// resumeTokenError records the CLOSED defect class (G213) and builds the throw. The message keeps its stable
// "malformed D1 resume token" prefix (callers and the coarse-error ladder match on it) and carries the closed
// class only: the token bytes and the offending field VALUE never enter the message or the ledger.
function resumeTokenError(defect: ResumeTokenDefect): Error {
  recordResumeTokenDefect("d1", defect);
  recordResumeFatal("d1"); // G144: the crawl throws from here, so the run row can finally say WHERE it died
  return new Error(`malformed D1 resume token (${defect})`);
}
