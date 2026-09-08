// SOURCE INTEGRITY / PRESSURE EVIDENCE validator.
//
// These four failure modes share one property that makes them the nastiest kind of support ticket: the run
// reports OK. Nothing throws, nothing is marked incomplete, and the damage surfaces days later in a restore
// or as a slow-motion degradation nobody can attribute.
//
//   SNAPSHOT CONSISTENCY - a D1 crawl that silently loses its point-in-time guarantee (no session, or a
//          resume that re-anchors to a DIFFERENT snapshot) seals a MIXED-SNAPSHOT archive: the restore
//          shows rows referencing rows that do not exist, or duplicated rows, behind a clean run.
//   RESUME-TOKEN CORRUPTION - a corrupt resume token wedges a downpipe (every slice fails) but matches no
//          coarse error class, so it reads as a generic "run failed" with no route to its known remedy
//          (clear the resume token).
//   THROTTLE PRESSURE - retry pressure is invisible unless recorded: withRetry only ever surfaces the
//          TERMINAL outcome, so a chronically throttled account looks healthy right up to the day the
//          retries exhaust.
//   SECURITY REFUSALS - a security refusal (a byte-fetch redirect, an off-Cloudflare download host) must
//          be named, not an anonymous "_refused" marker count sealed inside the archive.
//
// This validator drives each fault path with in-memory stubs (no network) and proves TWO things:
//
//   (a) RECORDED: the fault path writes coarse, diagnosable evidence into the source fault ledger -- the
//       closed snapshot-consistency class, the closed resume-token defect class, the throttle counters and
//       the closed security-refusal kind.
//   (b) REDACTION-SAFE (binding, NO-CUSTODY): a CUSTOMER VALUE planted at every one of those sites (a live
//       snapshot bookmark, a KV key, a customer video uid, an attacker/customer host, a signed download URL
//       with its token) NEVER appears in the recorded evidence. The final sweep asserts the serialised
//       ledger contains none of them, and that every enum member it carries is drawn from the closed
//       vocabularies.
//
// Run: node test/validate-source-integrity-evidence.ts

import { parseToken as parseD1Token } from "../src/sources/d1-token.ts";
import { makeSession, readDumpPlan } from "../src/sources/d1-reader.ts";
import { D1Source } from "../src/sources/d1.ts";
import { KVSource } from "../src/sources/kv.ts";
import { WorkersSource } from "../src/sources/workers.ts";
import { StreamSource } from "../src/sources/stream.ts";
import { ArtifactsSource } from "../src/sources/artifacts.ts";
import { CloudflareConfigSource } from "../src/sources/cloudflare-config.ts";
import { makeByteFetcher } from "../src/sources/byte-fetch.ts";
import {
  RESUME_TOKEN_DEFECTS,
  SNAPSHOT_CONSISTENCY_CLASSES,
  SOURCE_SECURITY_REFUSAL_KINDS,
  drainSourceFaultLedger,
  isEmptyFaultLedger,
  mergeSourceFaultLedgers,
  resetSourceFaultLedger,
  type ResumeTokenDefect,
  type SourceFaultLedger,
  type SourceSecurityRefusalKind,
} from "../src/sources/source-fault-ledger.ts";
import type { Selector } from "../src/sources/types.ts";

declare const process: { exit(code?: number): never; exitCode?: number };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ALL: Selector = { include: [], exclude: [] };

// POISON is the set of customer values planted at the fault sites. Every one is something the ledger must
// NEVER carry: a live D1 snapshot bookmark, a customer key/uid/host, and a signed URL carrying a token.
const POISON = {
  bookmark: "00000085-0000024f-00004ef1-ACME-LIVE-BOOKMARK",
  kvKey: "acme-prod-session-key",
  videoUid: "acmecustomervideo0001",
  attackerHost: "evil.acme-exfil.example",
  signedUrl: "https://evil.acme-exfil.example/v.mp4?token=9f3a-DEADBEEF&acct=acme",
  tableName: "acme_customer_invoices",
} as const;

// A drained snapshot per case, kept for the final redaction sweep over EVERYTHING recorded in this run.
const drained: Array<{ label: string; ledger: SourceFaultLedger }> = [];
function drain(label: string): SourceFaultLedger {
  const l = drainSourceFaultLedger();
  drained.push({ label, ledger: l });
  return l;
}

// exhaust drives an async iterable to completion and returns the error it threw, if any. The adapters'
// resume-token parsers run INSIDE the generator, so the throw only surfaces once the iterator is pulled.
async function threw(it: AsyncIterable<unknown>): Promise<Error | undefined> {
  try {
    for await (const _ of it) {
      /* drain */
    }
    return undefined;
  } catch (e) {
    return e as Error;
  }
}

// ---- D1 snapshot consistency -------------------------------------------------------------------------
// The three verdicts are the difference between "this archive is one point in time" and "this archive is a
// silent mixture of two". All three can ride on runs that report ok.
async function snapshotConsistency(): Promise<void> {
  console.log("D1 snapshot-consistency degradation is recorded, not silent");

  // (1) A binding that DOES expose withSession + getBookmark: pinned (the healthy state).
  resetSourceFaultLedger();
  const pinnedDb = {
    withSession: () => ({
      prepare: () => ({ raw: async () => [] }),
      getBookmark: () => POISON.bookmark, // a LIVE bookmark: must never be recorded
    }),
  } as unknown as Parameters<typeof makeSession>[0];
  makeSession(pinnedDb, "first-primary");
  const pinned = drain("snapshot-pinned");
  ok("a session with a bookmark records snapshotConsistency=pinned", pinned.snapshotConsistency === "pinned");
  ok("a pinned (healthy) run adds NOTHING else to the ledger", isEmptyFaultLedger(pinned));

  // (2) A binding with NO withSession at all: unpinned. Reads are not snapshot-isolated, so the archive can
  // be torn. The crawl still runs, but the run row must say the guarantee was not held.
  resetSourceFaultLedger();
  const unpinnedDb = { prepare: () => ({ raw: async () => [] }) } as unknown as Parameters<typeof makeSession>[0];
  makeSession(unpinnedDb, "first-primary");
  const unpinned = drain("snapshot-unpinned");
  ok("a binding with no withSession() records snapshotConsistency=unpinned", unpinned.snapshotConsistency === "unpinned");
  ok("an unpinned run is NOT empty (it is real evidence)", !isEmptyFaultLedger(unpinned));

  // (3) THE DATA-LOSS CASE: a RESUME whose token carries no bookmark cannot re-open the snapshot the earlier
  // slices read, so it re-anchors to a brand new one and the archive mixes two points in time.
  resetSourceFaultLedger();
  const db = {
    withSession: () => ({
      prepare: () => ({ raw: async () => [] }),
      getBookmark: () => POISON.bookmark,
    }),
  } as unknown as ConstructorParameters<typeof D1Source>[0];
  const src = new D1Source(db, "acme-db");
  // A structurally VALID token (so parseToken accepts it) that is mid-crawl with a null bookmark.
  const reanchorToken = JSON.stringify({ bookmark: null, phase: "rows", ti: 1, afterRowid: "42" });
  await threw(src.crawlFrom(ALL, reanchorToken));
  const reanchored = drain("snapshot-reanchored");
  ok("a resume with no bookmark records snapshotConsistency=re-anchored", reanchored.snapshotConsistency === "re-anchored");

  // (4) Worst-wins across slices: one re-anchored slice must colour the whole run, never be masked by the
  // pinned slices either side of it.
  const folded = mergeSourceFaultLedgers(mergeSourceFaultLedgers(pinned, reanchored), pinned);
  ok("worst-wins fold: a re-anchored slice is never masked by pinned slices", folded.snapshotConsistency === "re-anchored");

  // (5) A rowid probe that THROWS degrades the table to an unbounded single-pass read with no trace today.
  resetSourceFaultLedger();
  // readDumpPlan reads sqlite_master with .all(), then each table's header with .raw({columnNames:true}),
  // then probes _rowid_. Only the _rowid_ probe throws: the transient-fault case that silently degrades a
  // normal rowid table to an unbounded single-pass read.
  const reader = {
    prepare: (sql: string) => ({
      all: async () => ({
        results: [{ type: "table", name: POISON.tableName, tbl_name: POISON.tableName, sql: `CREATE TABLE ${POISON.tableName} (a)` }],
      }),
      raw: async () => {
        if (sql.includes("_rowid_")) throw new Error(`no such column: _rowid_ in ${POISON.tableName}`);
        return [["a"]]; // the LIMIT 0 column header
      },
    }),
  } as unknown as Parameters<typeof readDumpPlan>[0];
  await readDumpPlan(reader).catch(() => undefined);
  const fallback = drain("snapshot-rowid-fallback");
  ok("a failing _rowid_ probe increments rowidProbeFallbacks", fallback.rowidProbeFallbacks >= 1);
}

// ---- resume-token corruption --------------------------------------------------------------------------
// Every defect class must be distinguishable, because the remedy (clear the resume token) is only reachable
// once support can SEE that the run is wedged on resume-state corruption rather than "failing".
async function resumeTokenDefects(): Promise<void> {
  console.log("resume-token corruption carries a closed defect class");

  // Coercing a corrupt field to null would be a data-integrity bug (bad-bookmark -> mixed snapshot;
  // bad-cursor -> duplicated rows), so the D1 parser must REJECT both rather than coerce.
  const d1Cases: Array<{ defect: ResumeTokenDefect; token: string }> = [
    { defect: "unparseable", token: `{not json ${POISON.bookmark}` },
    { defect: "bad-shape", token: JSON.stringify("just-a-string") },
    { defect: "bad-phase", token: JSON.stringify({ bookmark: null, phase: "wat" }) },
    { defect: "bad-index", token: JSON.stringify({ bookmark: null, phase: "rows", ti: -1, afterRowid: null }) },
    // A corrupt cursor: coercing this to null RESTARTS the table and re-emits already-sealed rows.
    { defect: "bad-cursor", token: JSON.stringify({ bookmark: null, phase: "rows", ti: 0, afterRowid: POISON.kvKey }) },
    // A corrupt bookmark: coercing this to null silently RE-ANCHORS to a different snapshot.
    { defect: "bad-bookmark", token: JSON.stringify({ bookmark: 12345, phase: "header" }) },
  ];
  for (const c of d1Cases) {
    resetSourceFaultLedger();
    let rejected = false;
    try {
      parseD1Token(c.token);
    } catch {
      rejected = true;
    }
    const l = drain(`resume-token-d1-${c.defect}`);
    ok(`D1 REJECTS a ${c.defect} token (never coerces it)`, rejected);
    ok(`D1 records resume-token defect "${c.defect}"`, (l.resumeTokenDefects[c.defect] ?? 0) === 1);
    ok(`D1 attributes the defect to sourceType "d1"`, l.resumeTokenSourceTypes.includes("d1"));
  }

  // Every OTHER resumable adapter's token parser must classify too: a bare JSON.parse SyntaxError must not
  // escape unclassified and land in the generic "run failed" bucket.
  const bad = `{corrupt ${POISON.kvKey}`;
  const stub = () => ({ list: async () => ({ keys: [], list_complete: true }), get: async () => null }) as unknown as ConstructorParameters<typeof KVSource>[0];
  // Workers lists its scripts BEFORE it parses the resume token, so the list must SUCCEED for the token
  // parse to be reached at all. A one-page list of one script is enough.
  const listApi = () =>
    ({
      get: async () => ({}),
      getPage: async () => ({ result: [{ id: "acme-script" }], result_info: { page: 1, per_page: 50, count: 1, total_count: 1, total_pages: 1 } }),
      send: async () => ({}),
    }) as never;
  const adapters: Array<{ type: string; run: () => AsyncIterable<unknown> }> = [
    { type: "kv", run: () => new KVSource(stub(), "ns").crawlFrom(ALL, bad) },
    { type: "workers", run: () => new WorkersSource("acct", listApi()).crawlFrom(ALL, bad) },
    { type: "stream", run: () => new StreamSource("acct", listApi()).crawlFrom(ALL, bad) },
    { type: "artifacts", run: () => new ArtifactsSource("acct", listApi()).crawlFrom(ALL, bad) },
    { type: "cf-config", run: () => new CloudflareConfigSource("tok", "acct").crawlFrom(ALL, bad) },
  ];
  for (const a of adapters) {
    resetSourceFaultLedger();
    let err: Error | undefined;
    try {
      err = await threw(a.run());
    } catch {
      /* a constructor shape mismatch is reported by the assertion below */
    }
    const l = drain(`resume-token-${a.type}-unparseable`);
    ok(`${a.type} throws on a corrupt resume token`, err !== undefined);
    ok(`${a.type} records resume-token defect "unparseable"`, (l.resumeTokenDefects.unparseable ?? 0) >= 1);
    ok(`${a.type} attributes the defect to its own sourceType`, l.resumeTokenSourceTypes.includes(a.type));
  }

  // A WEDGE (every slice failing on the same corrupt token) must be distinguishable from a one-off, which is
  // what the COUNT is for.
  resetSourceFaultLedger();
  for (let i = 0; i < 3; i++) {
    try {
      parseD1Token(`{corrupt ${POISON.bookmark}`);
    } catch {
      /* expected */
    }
  }
  const wedge = drain("resume-token-wedge");
  ok("repeated corruption accumulates a count (a wedge, not a one-off)", (wedge.resumeTokenDefects.unparseable ?? 0) === 3);
}

// ---- throttle / retry pressure ------------------------------------------------------------------------
// The 429s a retry SWALLOWS are the whole point: they are the early warning that would otherwise be invisible.
async function throttlePressure(): Promise<void> {
  console.log("429 pressure and retry exhaustion are counted");

  resetSourceFaultLedger();
  // Every attempt answers 429 with a Retry-After, so the retry ladder absorbs several and then exhausts.
  const fetch429: typeof fetch = async () =>
    new Response("rate limited", { status: 429, headers: { "retry-after": "7" } });
  const fetcher = makeByteFetcher("tok", fetch429);
  const err = await fetcher.probe({ url: POISON.signedUrl }).catch((e: unknown) => e as Error);
  const l = drain("throttle-pressure");

  ok("the throttled fetch still fails loudly (never a silent empty body)", err instanceof Error);
  ok("every absorbed 429 is counted (not just the terminal one)", l.throttle429Count >= 2);
  ok("the retry ladder giving up is counted separately", l.retryExhaustedCount === 1);
  ok("the platform's Retry-After is carried as a clamped integer (7s)", l.maxRetryAfterSeconds === 7);
  ok("a throttled run is NOT empty (it is real evidence)", !isEmptyFaultLedger(l));

  // A run that is throttled but COPING (the retry succeeds) must still record the pressure: this is the
  // signal that lets support see mounting back-pressure in the runs that SUCCEEDED.
  resetSourceFaultLedger();
  let n = 0;
  const fetchRecovers: typeof fetch = async () => {
    n++;
    if (n === 1) return new Response("rate limited", { status: 429, headers: { "retry-after": "2" } });
    return new Response(new Uint8Array([1]), { status: 206, headers: { "content-range": "bytes 0-0/1" } });
  };
  await makeByteFetcher("tok", fetchRecovers).probe({ url: POISON.signedUrl }).catch(() => undefined);
  const coping = drain("throttle-coping");
  ok("a 429 the retry SWALLOWED is still recorded (the early warning)", coping.throttle429Count === 1);
  ok("a coping run records no retry exhaustion", coping.retryExhaustedCount === 0);
}

// ---- security refusals --------------------------------------------------------------------------------
// A refusal made on SECURITY grounds must not be an anonymous count sealed inside the archive.
async function securityRefusals(): Promise<void> {
  console.log("source-layer security refusals are named, never anonymous");

  // (1) A byte-fetch target that answers a redirect is refused, never followed: an attempt to steer a
  // validated read at an unvalidated host.
  resetSourceFaultLedger();
  const fetch302: typeof fetch = async () =>
    new Response(null, { status: 302, headers: { location: POISON.signedUrl } });
  const err = await makeByteFetcher("tok", fetch302).probe({ url: POISON.signedUrl }).catch((e: unknown) => e as Error);
  const redirect = drain("security-refusal-redirect");
  ok("a redirected byte-fetch target is refused (never followed)", err instanceof Error);
  ok('the refusal is recorded as securityRefusals["redirect-refused"]', (redirect.securityRefusals["redirect-refused"] ?? 0) === 1);

  // (2) A Stream download URL that fails the Cloudflare host allow-list is never fetched. The refused HOST is
  // the value that must never be recorded, so the KIND is all we keep.
  resetSourceFaultLedger();
  // The Stream list yields one video; the /downloads POST is SPOOFED to point the byte capture at an
  // attacker host (the compromised-or-spoofed API response the allow-list exists to defeat).
  const api = {
    get: async () => [{ uid: POISON.videoUid, created: "2026-01-01T00:00:00Z" }],
    getPage: async () => ({ result: [], result_info: { page: 1, per_page: 50, count: 0, total_count: 0, total_pages: 1 } }),
    send: async (_method: string, path: string) => {
      if (path.includes("/downloads")) return { default: { status: "ready", url: POISON.signedUrl, percentComplete: 100 } };
      return {};
    },
  };
  const stream = new StreamSource("acct", api as never, {
    includeContent: true,
    bytes: {
      probe: async () => ({ size: 1, acceptsRanges: false, etag: undefined, contentType: undefined }),
      wholeCapped: async () => ({ bytes: new Uint8Array([1]), truncated: false }),
      range: async () => new Uint8Array([1]),
    },
  } as never);
  // Drive the whole crawl: the off-host download URL must be refused, never fetched.
  await threw(stream.crawl(ALL));
  const host = drain("security-refusal-host");
  ok('an off-Cloudflare download host is recorded as securityRefusals["host-refused"]', (host.securityRefusals["host-refused"] ?? 0) >= 1);
}

// ---- redaction sweep -----------------------------------------------------------------------------------
function redactionSweep(): void {
  console.log("redaction sweep (NO-CUSTODY): no customer value, no raw error, closed enums only");
  const all = JSON.stringify(drained);

  for (const [k, v] of Object.entries(POISON)) {
    ok(`the recorded evidence never carries the planted ${k}`, !all.includes(v));
  }
  // The signed URL is also checked piecewise: no token fragment, no host, no query material.
  for (const frag of ["9f3a-DEADBEEF", "evil.acme-exfil.example", "token=", "acme_customer_invoices", "ACME-LIVE-BOOKMARK"]) {
    ok(`no fragment of the planted customer material survives ("${frag}")`, !all.includes(frag));
  }
  ok("no bearer/authorization material anywhere in the evidence", !/bearer|authorization/i.test(all));
  // A raw SyntaxError text ("Unexpected token", "is not valid JSON") would mean a parser leaked its message.
  ok("no raw JSON parser error text survives", !/Unexpected token|not valid JSON|SyntaxError/i.test(all));

  for (const { label, ledger } of drained) {
    if (ledger.snapshotConsistency !== undefined) {
      ok(
        `${label}: snapshotConsistency "${ledger.snapshotConsistency}" is in the closed vocabulary`,
        (SNAPSHOT_CONSISTENCY_CLASSES as readonly string[]).includes(ledger.snapshotConsistency),
      );
    }
    for (const d of Object.keys(ledger.resumeTokenDefects)) {
      ok(`${label}: resume-token defect "${d}" is in the closed vocabulary`, (RESUME_TOKEN_DEFECTS as readonly string[]).includes(d));
    }
    for (const k of Object.keys(ledger.securityRefusals)) {
      ok(`${label}: security refusal "${k}" is in the closed vocabulary`, (SOURCE_SECURITY_REFUSAL_KINDS as readonly string[]).includes(k as SourceSecurityRefusalKind));
    }
    // Every numeric field must be a bounded, non-negative integer: a pathological run can never write an
    // unbounded / NaN / negative number onto a run row.
    for (const [field, v] of Object.entries({
      rowidProbeFallbacks: ledger.rowidProbeFallbacks,
      throttle429Count: ledger.throttle429Count,
      retryExhaustedCount: ledger.retryExhaustedCount,
      maxRetryAfterSeconds: ledger.maxRetryAfterSeconds ?? 0,
    })) {
      ok(`${label}: ${field} is a bounded non-negative integer`, Number.isInteger(v) && v >= 0 && v <= 1_000_000);
    }
    // The source types carried alongside a token defect are ENGINE product tokens, never customer names.
    for (const t of ledger.resumeTokenSourceTypes) {
      ok(`${label}: resume-token sourceType "${t}" is an engine product token`, /^[a-z0-9-]{1,32}$/.test(t));
    }
  }
}

async function main(): Promise<void> {
  await snapshotConsistency();
  await resumeTokenDefects();
  await throttlePressure();
  await securityRefusals();
  redactionSweep();
  console.log(failures === 0 ? "\nvalidate-source-integrity-evidence: PASS" : `\nvalidate-source-integrity-evidence: ${failures} FAILURES`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

await main();
