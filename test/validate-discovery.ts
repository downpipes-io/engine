// Validates listPaged, the paginated discovery helper behind listAccountProducts. It covers both
// pagination models (page-based result_info.total_pages and cursor-based result_info.cursor) and the
// boundary cases: a single page, two-page exhaustion, a cap hit mid-page, an empty first page, and
// the page-style short-batch termination. Each case drives a stubbed api callback (no network), so a
// wrong termination condition or an off-by-one in the cap surfaces here rather than as a silent truncation.
// The R2 cases drive listAccountProducts through a fetch stub that answers as the live R2 bucket list does.

import { DISCOVERY_LIST_CAP, listAccountProducts, listPaged } from "../src/admin/router-sources-discovery.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}

const pick = (b: unknown): number[] => (b as { result?: number[] }).result ?? [];

// A page-based stub: pages 1..total of `per`-sized batches, the last possibly short, with total_pages set.
function pageStub(total: number, per: number): (path: string) => Promise<unknown> {
  let next = 1;
  return async (_path: string) => {
    const page = next++;
    const start = (page - 1) * per;
    const count = Math.min(per, total - start);
    const result = Array.from({ length: Math.max(0, count) }, (_v, i) => start + i);
    return { result, result_info: { total_pages: Math.ceil(total / per) || 1 } };
  };
}

console.log("-- single-page result --");
ok("returns the one short page and stops", (await listPaged(pageStub(7, 100), "/x", pick, 500)).length === 7);

console.log("\n-- two-page exhaustion (page style) --");
const twoPage = await listPaged(pageStub(150, 100), "/x", pick, 500);
ok("collects both pages", twoPage.length === 150);
ok("preserves order across pages", twoPage[0] === 0 && twoPage[149] === 149);

console.log("\n-- cursor-style pagination --");
function cursorStub(pages: number[][]): (path: string) => Promise<unknown> {
  let i = 0;
  return async (_path: string) => {
    const result = pages[i] ?? [];
    const hasNext = i < pages.length - 1;
    i++;
    return hasNext ? { result, result_info: { cursor: `c${i}` } } : { result, result_info: { cursor: "" } };
  };
}
const cur = await listPaged(cursorStub([[1, 2, 3], [4, 5], [6]]), "/x", pick, 500);
ok("follows the cursor to exhaustion", cur.length === 6 && cur[5] === 6);

console.log("\n-- cap hit mid-page --");
const capped = await listPaged(pageStub(1000, 100), "/x", pick, 250);
ok("stops exactly at the cap", capped.length === 250);

console.log("\n-- empty first page --");
ok("returns nothing and stops", (await listPaged(pageStub(0, 100), "/x", pick, 500)).length === 0);

console.log("\n-- page-style short-batch termination without total_pages --");
let pageNo = 0;
const shortBatch = async (_path: string) => {
  pageNo++;
  // first page full (100), second page short (10): no total_pages, so a short batch ends it.
  const result = pageNo === 1 ? Array.from({ length: 100 }, (_v, i) => i) : Array.from({ length: 10 }, (_v, i) => 100 + i);
  return { result };
};
const sb = await listPaged(shortBatch, "/x", pick, 500);
ok("ends on the short batch", sb.length === 110 && pageNo === 2);

// ---- R2: the live paging model --------------------------------------------------------------------------
// r2Stub answers GET /accounts/{id}/r2/buckets as the live API did on 28 Sep 2026 (read with a read-only token):
// ?page=N is IGNORED (every request without a cursor returns the first page), per_page is honoured, and
// result_info {cursor, per_page} is present ONLY when more buckets remain. The last page, full or short, has no
// result_info. The cursor encodes the last name returned, so a follow-up starts after it. Every other product
// answers an empty single page.
function r2Stub(total: number): { fetch: typeof fetch; calls: string[] } {
  const names = Array.from({ length: total }, (_v, i) => `bucket-${String(i).padStart(4, "0")}`);
  const calls: string[] = [];
  const f: typeof fetch = async (input) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
    const json = (b: unknown): Response => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });
    if (!url.pathname.endsWith("/r2/buckets")) return json({ success: true, result: [], result_info: { total_pages: 1 } });
    calls.push(url.search);
    const per = Number(url.searchParams.get("per_page") ?? "20");
    const cur = url.searchParams.get("cursor");
    const start = cur === null ? 0 : names.indexOf(cur) + 1;
    const pageNames = names.slice(start, start + per);
    const more = start + per < names.length;
    const body: Record<string, unknown> = { success: true, result: { buckets: pageNames.map((name) => ({ name, creation_date: "2026-09-28T00:00:00Z" })) } };
    if (more) body.result_info = { cursor: pageNames[pageNames.length - 1], per_page: per };
    return json(body);
  };
  return { fetch: f, calls };
}

async function listR2With(total: number): Promise<{ names: string[]; calls: string[]; errors: string[] }> {
  const stub = r2Stub(total);
  const real = globalThis.fetch;
  globalThis.fetch = stub.fetch;
  try {
    const l = await listAccountProducts("tok", "acct-1");
    return { names: l.r2.map((b) => b.name), calls: stub.calls, errors: l.errors };
  } finally {
    globalThis.fetch = real;
  }
}

console.log("\n-- R2: exactly one full page (100 buckets) --");
{
  const r = await listR2With(100);
  ok("lists 100 buckets, not the same page five times", r.names.length === 100);
  ok("lists each bucket once", new Set(r.names).size === r.names.length);
  ok("reads the list in one call", r.calls.length === 1);
  ok("never sends ?page= to R2", r.calls.every((q) => !/[?&]page=/.test(q)));
  ok("is not taken as a capped listing", r.names.length < DISCOVERY_LIST_CAP);
  ok("records no error", r.errors.length === 0);
}

console.log("\n-- R2: more than one page (250 buckets) --");
{
  const r = await listR2With(250);
  ok("lists all 250 buckets", r.names.length === 250 && new Set(r.names).size === 250);
  ok("follows the cursor: three calls", r.calls.length === 3);
  ok("keeps the last bucket", r.names.includes("bucket-0249"));
}

console.log("\n-- R2: an exact multiple of the page (200 buckets) --");
{
  const r = await listR2With(200);
  ok("lists all 200 buckets once", r.names.length === 200 && new Set(r.names).size === 200 && r.calls.length === 2);
}

console.log("\n-- R2: an empty account --");
{
  const r = await listR2With(0);
  ok("lists nothing in one call", r.names.length === 0 && r.calls.length === 1);
}

console.log("\n-- a page-style endpoint that ignores ?page= --");
{
  // A full page with no total_pages and no cursor, returned again for every page number. The listing
  // stops at the repeat, so it holds each item once and costs two calls, not a walk to the cap.
  let n = 0;
  const ignoresPage = async (_path: string) => {
    n++;
    return { result: Array.from({ length: 100 }, (_v, i) => i) };
  };
  const got = await listPaged(ignoresPage, "/x", pick, 500);
  ok("stops at the repeated page", got.length === 100 && n === 2);
}

console.log("\n-- keyOf drops an item already listed --");
{
  const dup = await listPaged(cursorStub([[1, 2, 3], [3, 4]]), "/x", pick, 500, { keyOf: (v) => String(v) });
  ok("each key once", dup.length === 4 && dup.join(",") === "1,2,3,4");
}

verdictReached(failures);
if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall discovery pagination checks passed");
