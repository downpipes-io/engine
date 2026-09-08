// Validates listPaged, the paginated discovery helper behind listAccountProducts. It covers both
// pagination models (page-based result_info.total_pages and cursor-based result_info.cursor) and the
// boundary cases: a single page, two-page exhaustion, a cap hit mid-page, an empty first page, and
// the page-style short-batch termination. Each case drives a stubbed api callback (no network), so a
// wrong termination condition or an off-by-one in the cap surfaces here rather than as a silent truncation.

import { listPaged } from "../src/admin/router-sources-discovery.ts";

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

if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall discovery pagination checks passed");
