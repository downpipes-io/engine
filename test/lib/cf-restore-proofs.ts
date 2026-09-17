// THE CF-CONFIG RESTORE PROOF LEDGER: the schema, the append, and the one rule that decides whether a
// banked row still counts.
//
// WHY THIS EXISTS. test/live-cf-suite.ts unions each stage's `LIVE-PROVED:` lines into `provedThisRun`
// and fails when a proven surface was not re-exercised and is not exempt. It is a good instrument, but it
// writes nothing: nothing commits a record that it ran, so a run that proved fifty surfaces and a run
// that never happened look the same from outside the terminal.
//
// That is not a gap in the prover. It is the reason there is no honest single number for the restore
// promise. Read three ways, the same tree says three different things:
//
//   through the product, current      the console round trip's own proven set
//   under a rule that needs a row     zero, because nothing banked one
//   ever, at a dated source comment   depends entirely on how you attribute a comment to an id, and three
//                                     defensible attributions of PROVEN_WRITE_SURFACES give 31, 52 and 60
//
// So this is the missing half of the prover, and deliberately NOT a second prover.
//
// THE COUNTING RULE, and its third input is the point. A row counts when all three hold:
//
//   1. its `kind` is a LIVE kind, so a row that records reasoning rather than a live drive can be banked
//      without ever being counted;
//   2. its `provedAt` is inside the expiry window, so a proof ages out rather than standing forever;
//   3. its `writerFingerprint` still matches the fingerprint derived from the engine checkout NOW.
//
// Without the third this is a tally: rows only accumulate, and the number rises whatever happens to the
// product. With it the number FALLS the moment the code path a row proved is edited. That is what makes it
// a measure. src/sources/cf-config-writer-fingerprint.ts carries what goes into a fingerprint.
//
// A CONSOLE-PRODUCT ROW CARRIES A SECOND FINGERPRINT, because it proves a second thing. The engine-API
// harnesses call a surface's write() directly and never touch the plan-building, diff-summary and
// approval-scoping layer a customer goes through. That layer is exercised ONLY by the console loop, it is
// engine code, and it moves: a change to src/admin/restore-cfconfig.ts can postdate every
// engine-API proof in the tree. A console-product row whose product-path fingerprint no longer matches has
// stopped proving the product path, whatever its writer did.
//
// THE LEDGER IS COMMITTED. A gitignored ledger written from a linked worktree is
// self-consistent, complete, and invisible to every gate and every other reader. A tracked JSON file cannot
// go missing quietly, because `git status` shows the row and CI reads the file.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { LIVE_ROUTE_ELSEWHERE, NO_LIVE_ROUTE_HERE, PROVEN_WRITE_SURFACES } from "../../src/sources/cf-config-write-generated.ts";
import { CONSOLE_RESTORE_PATH_FILES, cfWriterFingerprints } from "../../src/sources/cf-config-writer-fingerprint.ts";

/** The schema tag every ledger file carries. A reader that does not recognise it refuses rather than guesses. */
export const LEDGER_SCHEMA = "cf-restore-proofs/1";

/**
 * LIVE KINDS: the row kinds that describe a surface actually driven against live Cloudflare and read back.
 *
 * A CLOSED SET, and closed is the load-bearing part. The way a proof ledger becomes a press release is a
 * new kind arriving that means "we are confident about this one", and counting it because it is present.
 * A row of an unrecognised kind is banked, reported, and never counted.
 *
 *   engine-api       test/live-cf-suite.ts. Drives the surface's own write() against the throwaway proving
 *                    account. Proves the WRITER.
 *   console-product  a harness journey that damages the surface outside the
 *                    product, restores through the console's own plan, approval and apply screens, and
 *                    reads Cloudflare back. Proves the PRODUCT PATH, which is a superset and a different
 *                    claim, not a stronger wording of the same one.
 *
 * A REFUTING RUN BANKS TOO, under a kind that is deliberately NOT here: `console-product-refuted`. It
 * supersedes the successful row for the same surface and prover, is reported, and never counts. Without it
 * a surface that had stopped coming back would keep its last green row until the window ran out, and the
 * count would sit still through exactly the event it exists to report.
 */
export const LIVE_KINDS: ReadonlySet<string> = new Set(["engine-api", "console-product"]);

/**
 * How long a live proof stands before it must be driven again.
 *
 * Ninety days rather than a number that flatters the current state: the newest dated proof comment in
 * PROVEN_WRITE_SURFACES is recent, so a window shorter than about a fortnight would expire the whole
 * set immediately and a window of a year would let a proof outlive two release cycles. The
 * window is not the interesting control anyway. The fingerprint is: it expires a proof the moment the code
 * changes, whatever the date says.
 */
export const EXPIRY_DAYS = 90;

export interface ProofRow {
  /** The cf-config surface id. Must be in band, per the engine catalogue, or the row is UNKNOWN. */
  surface: string;
  /** One of LIVE_KINDS to count. Anything else is banked and reported, never counted. */
  kind: string;
  /** ISO 8601, when the drive happened. */
  provedAt: string;
  /** The prover, repo-relative. */
  prover: string;
  /** The repo the prover lives in. */
  repo: string;
  /** The engine HEAD at the time, full 40 characters, or "" when it could not be read. */
  engineSha: string;
  /** True when the engine tree was dirty, so engineSha does not describe what actually ran. */
  engineTreeDirty: boolean;
  /** The credential kit's NAME. Never a path, never a value. */
  kit: string;
  /** "sha256:<hex>" over the writer, from cfWriterFingerprints(). */
  writerFingerprint: string;
  /** "sha256:<hex>" over the console-only restore path. Required on a console-product row, absent elsewhere. */
  productPathFingerprint?: string;
}

export interface ProofLedger {
  schema: string;
  note?: string;
  rows: ProofRow[];
}

/** The empty ledger, so a first write does not have to invent the shape. */
export function emptyLedger(): ProofLedger {
  return {
    schema: LEDGER_SCHEMA,
    note: "Appended by a live prover, never by hand. See test/lib/cf-restore-proofs.ts for what banks a row and what refuses one.",
    rows: [],
  };
}

/** The engine's own ledger file. Overridable so a test can grade a scratch copy without touching the real one. */
export function engineLedgerPath(): string {
  const override = (process.env.DOWNPIPES_CF_PROOF_LEDGER ?? "").trim();
  if (override !== "") return resolve(override);
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "ledger", "cf-restore-proofs.json");
}

/**
 * Read a ledger file. A MISSING file is an empty ledger; a MALFORMED one throws.
 *
 * The asymmetry is deliberate. "No proofs have been banked" is a true and useful state that the gate must
 * be able to report. "There is a file here and it is not a ledger" is a destroyed record, and answering it
 * with an empty result would report zero proofs where the truth is that the count is unknown.
 */
export function readLedger(path: string): ProofLedger {
  if (!existsSync(path)) return emptyLedger();
  const raw = JSON.parse(readFileSync(path, "utf8")) as ProofLedger;
  if (raw === null || typeof raw !== "object" || !Array.isArray(raw.rows)) {
    throw new Error(`${path} is not a proof ledger: it carries no "rows" array`);
  }
  if (raw.schema !== LEDGER_SCHEMA) {
    throw new Error(`${path} declares schema "${String(raw.schema)}", and this reader knows ${LEDGER_SCHEMA}`);
  }
  return raw;
}

/**
 * Append rows, and SUPERSEDE rather than accumulate: one row per (surface, prover).
 *
 * KEYED ON THE PROVER AND NOT ON THE KIND, and that choice is what decides whether the number can fall. A
 * refuting run banks `console-product-refuted`, which is not a live kind. Key on the kind and that row
 * lands BESIDE the successful one rather than over it, so a surface that had stopped coming back would keep
 * its last green row until the window ran out. Keyed on the prover, the ledger holds the most recent thing
 * each prover said about each surface, which is the only reading under which a re-run that proves less
 * makes the count go down.
 */
export function appendRows(path: string, rows: readonly ProofRow[]): ProofLedger {
  const ledger = readLedger(path);
  const key = (r: ProofRow): string => `${r.surface}::${r.repo}/${r.prover}`;
  const keyed = new Map(ledger.rows.map((r) => [key(r), r]));
  for (const r of rows) keyed.set(key(r), r);
  ledger.schema = LEDGER_SCHEMA;
  if (ledger.note === undefined) ledger.note = emptyLedger().note ?? "";
  ledger.rows = [...keyed.values()].sort((a, b) => (a.surface === b.surface ? a.kind.localeCompare(b.kind) : a.surface.localeCompare(b.surface)));
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(ledger, null, 1)}\n`, "utf8");
  return ledger;
}

/** Why a row did not count. Every refusal names one of these, so a report can group by cause. */
export type RefusalCause = "not-a-live-kind" | "expired" | "writer-changed" | "product-path-changed" | "not-in-band" | "malformed";

export interface JudgedRow {
  row: ProofRow;
  counted: boolean;
  cause?: RefusalCause;
  detail?: string;
}

export interface LapsedExemption {
  surface: string;
  why: string;
  detail: string;
}

export interface ProofVerdict {
  /** cfConfigCatalogue().filter(inBand).length, derived from this checkout. Never pinned. */
  inBandTotal: number;
  judged: JudgedRow[];
  /** Surface ids with a counting row, by kind. */
  countedByKind: Map<string, string[]>;
  /** Surface ids with a counting row of ANY live kind. */
  countedAnyKind: string[];
  /** Rows that were banked and refused, which is the half a tally cannot show. */
  refused: JudgedRow[];
  /** LIVE_ROUTE_ELSEWHERE entries whose claim is no longer backed by anything. */
  lapsed: LapsedExemption[];
  /** True when a banked row has gone stale under a code change, which is a failure rather than a low count. */
  stale: JudgedRow[];
}

function ageDays(iso: string, now: Date): number | null {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return (now.getTime() - t) / 86_400_000;
}

/**
 * Grade a set of rows against the engine checkout as it is NOW.
 *
 * `fingerprints` and `productPath` are passed in rather than computed here so the caller decides which
 * checkout is being graded, and so a test can drive the writer-changed branch by handing over a fingerprint
 * map with one entry altered. A judge that could only ever read its own tree could not be shown to fail.
 */
export function judgeProofs(
  rows: readonly ProofRow[],
  fingerprints: ReadonlyMap<string, { fingerprint: string }>,
  productPath: string,
  now: Date = new Date(),
): ProofVerdict {
  const inBand = new Set(PROVEN_WRITE_SURFACES);
  const judged: JudgedRow[] = [];
  for (const row of rows) {
    const bad = (cause: RefusalCause, detail: string): void => {
      judged.push({ row, counted: false, cause, detail });
    };
    if (typeof row.surface !== "string" || row.surface === "" || typeof row.kind !== "string" || typeof row.writerFingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(row.writerFingerprint ?? "")) {
      bad("malformed", "a row needs a surface, a kind and a sha256: writer fingerprint");
      continue;
    }
    if (!inBand.has(row.surface)) {
      bad("not-in-band", "the engine catalogue does not carry this surface as in band, so the row grades nothing the product promises");
      continue;
    }
    if (!LIVE_KINDS.has(row.kind)) {
      bad("not-a-live-kind", `"${row.kind}" is not one of ${[...LIVE_KINDS].join(", ")}`);
      continue;
    }
    const age = ageDays(row.provedAt, now);
    if (age === null) {
      bad("malformed", `provedAt "${String(row.provedAt)}" is not a date`);
      continue;
    }
    if (age > EXPIRY_DAYS) {
      bad("expired", `proved ${Math.round(age)} days ago, and a proof stands for ${EXPIRY_DAYS}`);
      continue;
    }
    const current = fingerprints.get(row.surface);
    if (current === undefined) {
      bad("not-in-band", "no writer in this checkout, so there is nothing the row could still be a proof of");
      continue;
    }
    if (current.fingerprint !== row.writerFingerprint) {
      bad("writer-changed", `the writer was ${row.writerFingerprint.slice(0, 19)} when this was proved and is ${current.fingerprint.slice(0, 19)} now`);
      continue;
    }
    if (row.kind === "console-product") {
      if (typeof row.productPathFingerprint !== "string") {
        bad("malformed", "a console-product row must carry a product-path fingerprint, because the layer it proves is not the writer");
        continue;
      }
      if (row.productPathFingerprint !== productPath) {
        bad("product-path-changed", `the console restore path was ${row.productPathFingerprint.slice(0, 19)} when this was proved and is ${productPath.slice(0, 19)} now`);
        continue;
      }
    }
    judged.push({ row, counted: true });
  }

  const countedByKind = new Map<string, string[]>();
  for (const j of judged) {
    if (!j.counted) continue;
    const list = countedByKind.get(j.row.kind) ?? [];
    list.push(j.row.surface);
    countedByKind.set(j.row.kind, list);
  }
  for (const [k, v] of countedByKind) countedByKind.set(k, [...new Set(v)].sort());
  const countedAnyKind = [...new Set(judged.filter((j) => j.counted).map((j) => j.row.surface))].sort();

  // AN EXEMPTION IS A CLAIM, AND A CLAIM IS CHECKED. LIVE_ROUTE_ELSEWHERE says a prover outside this repo
  // re-exercises the surface. It is satisfied by a counting row of the kind it names. Failing that, its
  // `since` date is the claim standing on its own, and it stands only while it is inside the same expiry
  // window a row gets. This is the shape a refusal ledger uses for refusals: a row carries a probe that
  // can expire it, and a row carrying neither is refused.
  const lapsed: LapsedExemption[] = [];
  for (const [surface, claim] of LIVE_ROUTE_ELSEWHERE) {
    const backed = judged.some((j) => j.counted && j.row.surface === surface && j.row.kind === claim.banks);
    if (backed) continue;
    const age = ageDays(claim.since, now);
    if (age === null) {
      lapsed.push({ surface, why: claim.why, detail: `since "${claim.since}" is not a date, so the claim cannot be aged and cannot be believed` });
      continue;
    }
    if (age > EXPIRY_DAYS) {
      lapsed.push({
        surface,
        why: claim.why,
        detail: `no counting ${claim.banks} row, and the claim that ${claim.repo}/${claim.prover} covers it has stood unbacked for ${Math.round(age)} days`,
      });
    }
  }

  return {
    inBandTotal: inBand.size,
    judged,
    countedByKind,
    countedAnyKind,
    refused: judged.filter((j) => !j.counted),
    lapsed,
    stale: judged.filter((j) => j.cause === "writer-changed" || j.cause === "product-path-changed"),
  };
}

/** Surfaces with no counting row and no exemption of either kind: the honest remainder. */
export function unprovenRemainder(verdict: ProofVerdict): string[] {
  const counted = new Set(verdict.countedAnyKind);
  return [...PROVEN_WRITE_SURFACES]
    .filter((id) => !counted.has(id) && !NO_LIVE_ROUTE_HERE.has(id) && !LIVE_ROUTE_ELSEWHERE.has(id))
    .sort();
}

/** The fingerprints and product-path digest of THIS checkout, ready to hand to judgeProofs. */
export async function currentFingerprints(engineRootDir: string): Promise<{ writers: Map<string, { fingerprint: string }>; productPath: string }> {
  const writers = await cfWriterFingerprints();
  const productPath = await productPathFingerprintFrom(engineRootDir);
  return { writers, productPath };
}

/** SHA-256 over the console-only restore path, file by file, read from a checkout. */
export async function productPathFingerprintFrom(engineRootDir: string): Promise<string> {
  const per: Record<string, string> = {};
  for (const rel of CONSOLE_RESTORE_PATH_FILES) {
    const p = join(engineRootDir, rel);
    if (!existsSync(p)) throw new Error(`the console restore path names ${rel}, and ${p} does not exist. A digest over a file that is not there is not a digest of anything.`);
    const bytes = new TextEncoder().encode(readFileSync(p, "utf8"));
    const d = await crypto.subtle.digest("SHA-256", bytes);
    per[rel] = [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  const canonical = Object.keys(per)
    .sort()
    .map((k) => `${k}:${per[k]}`)
    .join("\n");
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return `sha256:${[...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}
