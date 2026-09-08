// Validates the Cloudflare Images source adapter: the account-level variant record, one record per
// image (name = id, value = metadata) paged in full via the v2 continuation token, selector scoping
// by id, the honest truncation marker, and the per-record fail-open on the variant read. No network:
// an in-memory CfApi stub drives every path.

import { ImagesSource } from "../src/sources/images.ts";
import type { CfApi } from "../src/sources/cf-config-surfaces.ts";
import type { SourceRecord, Selector, CrawlEvent } from "../src/sources/types.ts";
import { isResumable } from "../src/sources/types.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}
const ALL: Selector = { include: [], exclude: [] };
const dec = (u: Uint8Array) => JSON.parse(new TextDecoder().decode(u));

// stubApi answers GET /images/v1/variants with `variants` and successive GET /images/v2 calls with
// `pages` (in order; a page with continuation_token signals more). variantsThrows makes the variant
// read fail (to exercise the per-record fail-open). get() is the only method the adapter uses.
function stubApi(opts: { variants?: unknown; variantsThrows?: boolean; pages: Array<{ images: unknown[]; continuation_token?: string }> }): CfApi {
  let pageIdx = 0;
  return {
    get: async (path: string) => {
      if (path.includes("/images/v1/variants")) {
        if (opts.variantsThrows) throw new Error("403");
        return opts.variants ?? { variants: {} };
      }
      if (path.includes("/images/v2")) {
        const p = opts.pages[pageIdx] ?? { images: [] };
        pageIdx++;
        return p;
      }
      return null;
    },
    getPage: async () => ({ result: [] }),
    send: async () => null,
  };
}
async function collect(src: ImagesSource, sel: Selector = ALL): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of src.crawl(sel)) out.push(r);
  return out;
}

console.log("-- variant record + one record per image (metadata) --");
const recs = await collect(new ImagesSource("acct", stubApi({
  variants: { variants: { hero: { id: "hero" } } },
  pages: [{ images: [{ id: "img1", filename: "a.png", requireSignedURLs: true }, { id: "img2", filename: "b.jpg" }, { filename: "no-id-skip" }] }],
})));
ok("emits the account variant-definitions record", recs.some((r) => r.name === "_variants"));
ok("emits one record per image WITH an id (2 of 3)", recs.filter((r) => r.name === "img1" || r.name === "img2").length === 2);
ok("record sourceType is 'images'", recs.every((r) => r.sourceType === "images"));
ok("image record value is the full metadata", dec(recs.find((r) => r.name === "img1")!.value!).filename === "a.png");
ok("an image without an id is skipped", !recs.some((r) => r.name === "no-id-skip"));

console.log("\n-- v2 continuation token pages the FULL inventory --");
const paged = await collect(new ImagesSource("acct", stubApi({
  pages: [
    { images: [{ id: "p1a" }, { id: "p1b" }], continuation_token: "t2" },
    { images: [{ id: "p2a" }] }, // no token -> last page
  ],
})));
ok("captures images across BOTH continuation pages", ["p1a", "p1b", "p2a"].every((id) => paged.some((r) => r.name === id)));

console.log("\n-- selector scopes by image id --");
const scoped = await collect(new ImagesSource("acct", stubApi({ pages: [{ images: [{ id: "k1" }, { id: "k2" }] }] })), { include: ["k2"], exclude: [] });
ok("include ['k2'] yields only k2 (variants still allowed)", scoped.some((r) => r.name === "k2") && !scoped.some((r) => r.name === "k1"));

console.log("\n-- fail-open: a failing variant read emits an _unavailable MARKER (no longer silent), inventory intact --");
const fo = await collect(new ImagesSource("acct", stubApi({ variantsThrows: true, pages: [{ images: [{ id: "still-here" }] }] })));
const foVar = fo.find((r) => r.name === "_variants");
ok("variant read throws -> an _unavailable _variants marker is emitted (visible shortfall), images still captured",
  foVar !== undefined && (JSON.parse(new TextDecoder().decode(foVar.value!)) as { _unavailable?: unknown })._unavailable !== undefined && fo.some((r) => r.name === "still-here"));

console.log("\n-- estimate counts in-scope images + the variant record --");
const est = await new ImagesSource("acct", stubApi({ pages: [{ images: [{ id: "e1" }, { id: "e2" }] }] })).estimate(ALL);
ok("estimate.records = images + variants (2 + 1)", est.records === 3);
ok("estimate.bytes is unknown (-1)", est.bytes === -1);

// ---------------------------------------------------------------------------
// RESUMABILITY: a library larger than one slice resumes from the cursor and
// captures the FULL set across two crawl calls, rather than restarting. crawlFrom
// emits a {mark} after the variant config and after each fully-yielded image; a
// resume from a mark re-fetches the recorded continuation page and skips the yielded
// prefix. tokenApi is keyed by continuation_token (stateless across calls) so a
// resume re-fetching a page returns the SAME page, unlike the index-counter stubApi.
// ---------------------------------------------------------------------------
console.log("\n-- crawlFrom is RESUMABLE (marks after the variants + each image, resume skips the yielded prefix) --");
{
  // A library across two continuation pages. tokenApi maps the continuation_token query to a page so a
  // re-fetch of the same page is deterministic (a real resume re-fetches the recorded page).
  type Page = { images: Array<{ id: string }>; continuation_token?: string };
  function tokenApi(pages: Record<string, Page>): CfApi {
    return {
      get: async (path: string) => {
        if (path.includes("/images/v1/variants")) return { variants: {} };
        if (path.includes("/images/v2")) {
          const m = /[?&]continuation_token=([^&]+)/.exec(path);
          const key = m ? decodeURIComponent(m[1]!) : "";
          return pages[key] ?? { images: [] };
        }
        return null;
      },
      getPage: async () => ({ result: [] }),
      send: async () => null,
    };
  }
  // "" is the first page (no continuation_token), then "t2" the second.
  const pages: Record<string, Page> = {
    "": { images: [{ id: "i1" }, { id: "i2" }], continuation_token: "t2" },
    t2: { images: [{ id: "i3" }, { id: "i4" }] },
  };
  ok("ImagesSource is resumable (implements crawlFrom)", isResumable(new ImagesSource("acct", tokenApi(pages))));

  const evs: CrawlEvent[] = [];
  for await (const ev of new ImagesSource("acct", tokenApi(pages)).crawlFrom(ALL, null)) evs.push(ev);
  const marks = evs.filter((e) => e.kind === "mark") as Array<{ kind: "mark"; token: string }>;
  const fromScratch = evs.filter((e) => e.kind === "record").map((e) => (e as { record: SourceRecord }).record.name);
  ok("from scratch yields the variants record + every image", ["_variants", "i1", "i2", "i3", "i4"].every((n) => fromScratch.includes(n)));
  ok("a mark follows the variants record and each of the 4 images (5 marks)", marks.length === 5);

  // Resume from the mark after i1 (page 1): the resume must yield i2, i3, i4 and never re-read i1 or
  // re-emit the variants record (the seal would otherwise double-capture them).
  const afterI1 = marks[1]!.token; // marks[0] = variants, marks[1] = after i1
  const resumed: string[] = [];
  for await (const ev of new ImagesSource("acct", tokenApi(pages)).crawlFrom(ALL, afterI1))
    if (ev.kind === "record") resumed.push(ev.record.name);
  ok("resume after i1 yields i2, i3, i4 in order", resumed.join(",") === "i2,i3,i4");
  ok("resume never re-emits the variants record", !resumed.includes("_variants"));
  ok("resume never re-reads i1 (the yielded prefix is skipped)", !resumed.includes("i1"));

  // Resume from a mark on PAGE 2 (after i3): the resume re-fetches page 2 and yields only i4, never
  // re-listing page 1 nor re-reading i3.
  const afterI3 = marks[3]!.token; // variants, i1, i2, i3, i4 -> index 3 is after i3
  const resumedP2: string[] = [];
  for await (const ev of new ImagesSource("acct", tokenApi(pages)).crawlFrom(ALL, afterI3))
    if (ev.kind === "record") resumedP2.push(ev.record.name);
  ok("a resume from a page-2 mark yields only the tail (i4), no page-1 image re-read", resumedP2.join(",") === "i4");

  // The FULL set across two slices: slice 1 stops at the first image mark, slice 2 resumes; the union
  // is the whole library captured exactly once, with NO restart-from-the-beginning duplication.
  const sliceOne: string[] = [];
  let firstImageMark: string | null = null;
  for await (const ev of new ImagesSource("acct", tokenApi(pages)).crawlFrom(ALL, null)) {
    if (ev.kind === "record") sliceOne.push(ev.record.name);
    else if (ev.kind === "mark" && ev.token.includes('"afterId"')) { firstImageMark = ev.token; break; } // first image-level mark
  }
  const sliceTwo: string[] = [];
  for await (const ev of new ImagesSource("acct", tokenApi(pages)).crawlFrom(ALL, firstImageMark))
    if (ev.kind === "record") sliceTwo.push(ev.record.name);
  ok("two slices together capture variants + every image exactly once (no restart)",
    [...sliceOne, ...sliceTwo].filter((n) => n !== "_variants").sort().join(",") === "i1,i2,i3,i4" &&
    [...sliceOne, ...sliceTwo].filter((n) => n === "_variants").length === 1);
}

console.log(failures === 0 ? "\nIMAGES SOURCE PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
