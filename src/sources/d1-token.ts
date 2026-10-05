// The D1 resume token: opaque engine-internal JSON the slice persists in checkpoint state. It carries
// the snapshot bookmark (so a resumed slice re-opens the SAME point in time) and a position:
//   - phase "header": next emit is the header (a fresh crawl before the header mark; not normally a
//     token value -- a fresh crawl uses a null token -- but accepted for completeness).
//   - phase "rows": next emit is table `ti`'s rows after rowid `afterRowid` (a decimal string, or
//     null to start the table). ti past the last table falls through to schema. For a WITHOUT ROWID
//     table the cursor is `afterKey` instead: the last emitted row's PRIMARY KEY cells in key order,
//     in the D1Cell encoding (d1-format.ts), with afterRowid null. A token without afterKey is a rowid
//     cursor or the start of a table. A mid-table cursor also carries `page`, the index of the next rows
//     page, so a resumed table continues the record names (d1.ts rowsName) and never repeats one that an
//     earlier slice sealed. A token without `page` starts at page 0.
//   - phase "schema": next emit is the schema record.
//   - phase "done": nothing left.
// A rowid cursor carries NO value bytes. A key cursor carries the PRIMARY KEY values of one row (customer
// row data, bounded by D1_KEY_CURSOR_MAX_BYTES in d1-reader.ts). The token is persisted only in the
// checkpoint, which wraps the whole cursor under the checkpoint key (src/seal/checkpoint.ts); it never
// enters a log or a ledger.

import { type D1Cell, validCell } from "./d1-format.ts";
import { type ResumeTokenDefect, recordResumeFatal, recordResumeTokenDefect } from "./source-fault-ledger.ts";

export type TokenPhase = "header" | "rows" | "schema" | "done";

export type ResumeToken =
  | { bookmark: string | null; phase: "header" }
  | { bookmark: string | null; phase: "rows"; ti: number; afterRowid: string | null; afterKey?: D1Cell[]; page?: number }
  | { bookmark: string | null; phase: "schema" }
  | { bookmark: string | null; phase: "done" };

export function encodeToken(t: ResumeToken): string {
  return JSON.stringify(t);
}

// parseToken REJECTS a malformed token rather than coercing it.
//
// Silently coercing either field to null would be a DATA-INTEGRITY bug that surfaces only in the RESTORE,
// long after the run reports ok:
//   - a malformed `bookmark` coerced to null re-opens a DIFFERENT snapshot on resume, so the archive
//     mixes two points in time (restored rows referencing rows that do not exist);
//   - a malformed `afterRowid` coerced to null restarts the table and re-emits already-sealed rows
//     (duplicated rows in the restore).
// Both throw instead. A corrupt token is not a recoverable condition to paper over: failing the slice loudly is
// strictly safer than sealing an archive whose consistency the engine cannot vouch for, and the operator has
// a known remediation (clear the resume token). Every defect is recorded under its CLOSED class first, so the
// wedge is legible in the support pack instead of reading as a generic "run failed".
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
  // to a fresh snapshot behind the operator's back is exactly the mixed-snapshot fault.
  if (!(o.bookmark === null || typeof o.bookmark === "string")) throw resumeTokenError("bad-bookmark");
  const bookmark = o.bookmark as string | null;
  switch (o.phase) {
    case "header":
      return { bookmark, phase: "header" };
    case "rows": {
      if (typeof o.ti !== "number" || !Number.isInteger(o.ti) || o.ti < 0) throw resumeTokenError("bad-index");
      // A cursor must be null (start of table) or a decimal integer string. Coercing a corrupt cursor to null
      // would silently re-emit sealed rows; reject it instead.
      if (!(o.afterRowid === null || (typeof o.afterRowid === "string" && /^-?\d+$/.test(o.afterRowid)))) throw resumeTokenError("bad-cursor");
      const afterRowid = o.afterRowid as string | null;
      // A page index is a positive integer, and it only travels with a mid-table cursor: a table start
      // always takes page 0. Anything else would misname the resumed pages.
      if (o.page !== undefined && (typeof o.page !== "number" || !Number.isInteger(o.page) || o.page < 1 || (afterRowid === null && o.afterKey === undefined))) {
        throw resumeTokenError("bad-index");
      }
      const page = o.page === undefined ? {} : { page: o.page as number };
      if (o.afterKey === undefined) return { bookmark, phase: "rows", ti: o.ti, afterRowid, ...page };
      // A key cursor is a non-empty array of non-NULL cells (a PRIMARY KEY of a WITHOUT ROWID table holds no
      // NULL), and it never travels with a rowid cursor. Anything else would restart or skip part of a table.
      if (
        afterRowid !== null ||
        !Array.isArray(o.afterKey) ||
        o.afterKey.length === 0 ||
        !o.afterKey.every((c) => c !== null && validCell(c))
      ) {
        throw resumeTokenError("bad-cursor");
      }
      return { bookmark, phase: "rows", ti: o.ti, afterRowid: null, afterKey: o.afterKey as D1Cell[], ...page };
    }
    case "schema":
      return { bookmark, phase: "schema" };
    case "done":
      return { bookmark, phase: "done" };
    default:
      throw resumeTokenError("bad-phase");
  }
}

// resumeTokenError records the CLOSED defect class and builds the throw. d1-reader.ts also uses it for a
// well-formed cursor whose kind does not match the table it resumes (a wedge of the same kind). The message keeps its stable
// "malformed D1 resume token" prefix (callers and the coarse-error ladder match on it) and carries the closed
// class only: the token bytes and the offending field VALUE never enter the message or the ledger.
export function resumeTokenError(defect: ResumeTokenDefect): Error {
  recordResumeTokenDefect("d1", defect);
  recordResumeFatal("d1"); // the crawl throws from here, so the run row can say WHERE it died
  return new Error(`malformed D1 resume token (${defect})`);
}
