// Validates the Cloudflare Artifact Registry source adapter: the 2-level namespaces -> repos expand
// (one record per repo, name = "<namespace>/<repo>", value = repo metadata), selector scoping,
// per-namespace fail-open, and that namespaces/repos without a name are skipped. No network: an
// in-memory CfApi stub drives paginate()'s getPage for both levels.
//
// It also drives the OPT-IN content walk (includeContent + a byte fetcher): the git-style log ->
// commit -> tree -> blob history walk, the shared dedup set + per-repo object budget (the honest
// "_truncated" cap marker), the per-step fail-open markers (an unreadable log/commit/tree/blob never
// voids the run), the captureBlob size-gated shapes (buffered value, streamed value, skip marker), and
// the tolerant log/commit/tree shape parsers (commitHashes, treeHashOf, treeEntries).

import { ArtifactsSource, ARTIFACTS_MAX_OBJECTS } from "../src/sources/artifacts.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";
import type { ByteFetcher, ByteTarget } from "../src/sources/byte-fetch.ts";
import type { SourceRecord, Selector, Meter, CrawlEvent } from "../src/sources/types.ts";
import { isResumable } from "../src/sources/types.ts";
import { isIncompleteMarkerValue } from "../src/seal/marker.ts";

// This file runs its checks as top-level await statements rather than inside an async main().
// Register an error boundary so an unhandled rejection from any top-level await prints the
// failing error and exits non-zero, matching the diagnostic the main().catch() sibling
// validators give. See engine-test-001-15.
process.on("unhandledRejection", (e) => {
  console.error(e);
  process.exit(1);
});

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}
const ALL: Selector = { include: [], exclude: [] };
const dec = (u: Uint8Array) => JSON.parse(new TextDecoder().decode(u));
const page = (result: unknown[]): CfPage => ({ result, result_info: { page: 1, total_pages: 1 } });

// stubApi answers the namespaces list with `namespaces` and each namespace's repos list with
// `reposByNs[ns]` (or throws for a namespace in `throwNs`, to exercise per-namespace fail-open).
function stubApi(opts: { namespaces: unknown[]; reposByNs: Record<string, unknown[]>; throwNs?: string }): CfApi {
  return {
    get: async () => null,
    getPage: async (path: string): Promise<CfPage> => {
      const m = /artifacts\/namespaces\/([^/?]+)\/repos/.exec(path);
      if (m) {
        const ns = decodeURIComponent(m[1]!);
        if (opts.throwNs === ns) throw new Error("403");
        return page(opts.reposByNs[ns] ?? []);
      }
      if (path.includes("/artifacts/namespaces")) return page(opts.namespaces);
      return page([]);
    },
    send: async () => null,
  };
}
async function collect(src: ArtifactsSource, sel: Selector = ALL): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of src.crawl(sel)) out.push(r);
  return out;
}

console.log("-- 2-level expand: one record per repo, name = ns/repo --");
const recs = await collect(new ArtifactsSource("acct", stubApi({
  namespaces: [{ name: "ns1" }, { name: "ns2" }, { id: "no-name-ns" }],
  reposByNs: { ns1: [{ name: "r1" }, { name: "r2" }], ns2: [{ name: "r3" }], "no-name-ns": [{ name: "x" }] },
})));
ok("emits one record per repo across namespaces", recs.length === 4); // ns1/r1, ns1/r2, ns2/r3, no-name-ns/x (ns has id fallback)
ok("record name is namespace/repo", recs.some((r) => r.name === "ns1/r1") && recs.some((r) => r.name === "ns2/r3"));
ok("sourceType is 'artifacts'", recs.every((r) => r.sourceType === "artifacts"));
ok("value carries namespace + repo metadata", dec(recs.find((r) => r.name === "ns1/r1")!.value!).namespace === "ns1");

console.log("\n-- selector scopes by ns/repo --");
const scoped = await collect(new ArtifactsSource("acct", stubApi({ namespaces: [{ name: "ns1" }], reposByNs: { ns1: [{ name: "r1" }, { name: "r2" }] } })), { include: ["ns1/r2"], exclude: [] });
ok("include ['ns1/r2'] yields only that repo", scoped.length === 1 && scoped[0]!.name === "ns1/r2");

console.log("\n-- per-namespace fail-open: an UNAVAILABLE MARKER, never a silent drop (A1) --");
// A1 (HIGH, silent data loss): a transient 5xx that survives retry (or a scope gap, or an inner
// CfPaginationTruncated) on ONE namespace's repo list must NOT silently drop every repo in that
// namespace with no marker and no recordsIncomplete signal. The OLD code did exactly that (a bare
// `continue`): `fo` would have held only "good/ok" and the run would have reported a clean "ok". The
// fix emits a "<namespace>/_unavailable" sentinel record naming the namespace, the same shape
// stream/images emit and that seal/marker.ts isIncompleteMarkerValue + the recordsIncomplete counter
// detect, so the operator is told the namespace is short.
const fo = await collect(new ArtifactsSource("acct", stubApi({ namespaces: [{ name: "good" }, { name: "bad" }], reposByNs: { good: [{ name: "ok" }] }, throwNs: "bad" })));
ok("the readable namespace's repos are still captured", fo.some((r) => r.name === "good/ok"));
const badMarker = fo.find((r) => r.name === "bad/_unavailable");
ok("a 'bad/_unavailable' marker record is emitted for the failed namespace (not a silent drop)", badMarker !== undefined);
ok("the marker names the namespace and the failure reason in its value", (() => badMarker?.value !== undefined && dec(badMarker.value)._unavailable.includes("403"))());
ok("the marker is detected by seal/marker.ts isIncompleteMarkerValue (drives recordsIncomplete)", badMarker?.value !== undefined && isIncompleteMarkerValue(badMarker.value));
ok("the failed namespace is NOT silently dropped: a record stands in for it", fo.some((r) => r.name.startsWith("bad/")));

console.log("\n-- repos without a name are skipped --");
const noname = await collect(new ArtifactsSource("acct", stubApi({ namespaces: [{ name: "ns" }], reposByNs: { ns: [{ name: "keep" }, { size: 1 }] } })));
ok("a repo with no name is skipped", noname.length === 1 && noname[0]!.name === "ns/keep");

console.log("\n-- a null namespace entry is skipped (optional-chaining short-circuit) --");
// A null entry in the namespaces list: `ns?.name ?? ns?.id` short-circuits to undefined (ns is nullish),
// so the entry is skipped; the real namespace beside it is still expanded.
const nullNs = await collect(new ArtifactsSource("acct", stubApi({ namespaces: [null, { name: "real" }], reposByNs: { real: [{ name: "r" }] } })));
ok("a null namespace entry is skipped, the real one is captured", nullNs.length === 1 && nullNs[0]!.name === "real/r");

console.log("\n-- estimate returns the namespace floor --");
const est = await new ArtifactsSource("acct", stubApi({ namespaces: [{ name: "a" }, { name: "b" }], reposByNs: {} })).estimate(ALL);
ok("estimate.records = namespace count (floor)", est.records === 2);
ok("estimate.bytes unknown (-1)", est.bytes === -1);

console.log("\n-- estimate fail-open: a broken namespaces token -> zero floor --");
const estBroken = await new ArtifactsSource("acct", {
  get: async () => null,
  getPage: async () => { throw new Error("403"); },
  send: async () => null,
}).estimate(ALL);
ok("estimate.records = 0 when the namespaces list throws", estBroken.records === 0);
ok("estimate.bytes still -1 on the error path", estBroken.bytes === -1);

// ---------------------------------------------------------------------------
// CONTENT WALK (includeContent + a byte fetcher). The following scaffolding drives the git-style
// log -> commit -> tree -> blob walk with an in-memory CfApi for the metadata and an in-memory
// ByteFetcher for the blob bytes, so no network is touched.
// ---------------------------------------------------------------------------

function strip(p: string): string {
  return p.split("?", 1)[0]!;
}

// ThrowRaw wraps a NON-Error value a route should throw (a string, say), to drive the `String(e)` arm of
// the fail-open `e instanceof Error ? e.message : String(e)` markers (a normal Error route drives the
// `e.message` arm).
class ThrowRaw {
  value: unknown;
  constructor(value: unknown) { this.value = value; }
}

// repoApi serves a single namespace "ns" with a single repo "r"; the `routes` map answers the
// repo-relative content paths ("/log", "/commit/<h>", "/tree/<h>"). A route value that is an Error
// instance is thrown (to drive the per-step fail-open Error markers); a ThrowRaw throws its non-Error
// payload (the String(e) arm); anything else is returned as the parsed JSON. An unmapped content path
// returns null.
function repoApi(routes: Record<string, unknown>): CfApi {
  const base = "/accounts/acct/artifacts/namespaces/ns/repos/r";
  return {
    get: async (path: string): Promise<unknown> => {
      const rel = strip(path).slice(base.length);
      if (rel in routes) {
        const v = routes[rel];
        if (v instanceof ThrowRaw) throw v.value;
        if (v instanceof Error) throw v;
        return v;
      }
      return null;
    },
    getPage: async (path: string): Promise<CfPage> => {
      const p = strip(path);
      if (p.endsWith("/namespaces/ns/repos")) return page([{ name: "r" }]);
      if (p.endsWith("/artifacts/namespaces")) return page([{ name: "ns" }]);
      return page([]);
    },
    send: async () => null,
  };
}

// blobFetcher serves blob bytes from `map` keyed by the blob hash (not the full url). `sizes` overrides
// the probed size for a hash (to drive the captureBlob skip/stream paths); `ranges` marks a hash as
// range-capable. A hash in `fail` throws from probe (to drive the per-blob fail-open marker). Default:
// a small buffered value.
function blobFetcher(opts: {
  map?: Record<string, Uint8Array>;
  sizes?: Record<string, number>;
  ranges?: Set<string>;
  fail?: Set<string>;
}): ByteFetcher {
  const hashOf = (t: ByteTarget): string => decodeURIComponent(strip(t.url).split("/blob/")[1] ?? "");
  const bytesOf = (h: string): Uint8Array => opts.map?.[h] ?? new TextEncoder().encode(`BYTES-${h}`);
  return {
    probe: async (t) => {
      const h = hashOf(t);
      if (opts.fail?.has(h)) throw new Error(`403 blob ${h}`);
      const declared = opts.sizes?.[h];
      const size = declared ?? bytesOf(h).length;
      return { size, acceptsRanges: opts.ranges?.has(h) === true, etag: '"e"' };
    },
    wholeCapped: async (t, cap) => {
      const b = bytesOf(hashOf(t));
      return b.length > cap ? { overCap: true as const, read: b.length } : { bytes: b };
    },
    range: async (t, o, l) => bytesOf(hashOf(t)).slice(o, o + l),
    streamedRange: async function* (t, o, l) {
      yield bytesOf(hashOf(t)).slice(o, o + l);
    },
  };
}

const withBytes = (api: CfApi, fetcher: ByteFetcher) =>
  new ArtifactsSource("acct", api, { includeContent: true, bytes: fetcher });

console.log("\n-- captureBytes gate: includeContent without a byte fetcher stays metadata-only --");
// includeContent true but bytes undefined -> captureBytes() short-circuits false (the && right operand)
// so no content walk happens: just the inventory record.
const noFetcher = new ArtifactsSource("acct", repoApi({ "/log": [{ hash: "c1" }] }), { includeContent: true });
const noFetcherRecs = await collect(noFetcher);
ok("includeContent without bytes: only the inventory record (no walk)", noFetcherRecs.length === 1 && noFetcherRecs[0]!.name === "ns/r");

console.log("\n-- content walk: log + commit + tree + blob (a value blob) --");
const walkRecs = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: "t1" },
    "/tree/t1": { entries: [{ type: "blob", hash: "b1", name: "f1" }] },
  }),
  blobFetcher({ map: { b1: new TextEncoder().encode("BLOB-ONE") } }),
));
ok("inventory + log + commit + tree + blob records present", ["ns/r", "ns/r/log", "ns/r/commit/c1", "ns/r/tree/t1", "ns/r/blob/b1"].every((n) => walkRecs.some((r) => r.name === n)));
ok("the blob is captured as a buffered value with the exact bytes", (() => { const r = walkRecs.find((x) => x.name === "ns/r/blob/b1"); return r?.value !== undefined && new TextDecoder().decode(r.value) === "BLOB-ONE"; })());
ok("the log record carries the log payload", (() => { const r = walkRecs.find((x) => x.name === "ns/r/log"); return r?.value !== undefined && Array.isArray(dec(r.value).log); })());

console.log("\n-- meter is charged one cfApiRead per content GET --");
let spent = 0;
const meter: Meter = { spend: (n = 1) => { spent += n; } };
const meterSrc = withBytes(
  repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": { entries: [{ type: "blob", hash: "b1" }] } }),
  blobFetcher({}),
);
{
  const out: SourceRecord[] = [];
  for await (const r of meterSrc.crawl(ALL, meter)) out.push(r);
  // log + commit + tree = at least 3 content GETs charged (paginate also charges; just assert the floor).
  ok("meter.spend was charged for the content GETs (log/commit/tree)", spent >= 3);
}

console.log("\n-- log fail-open: an unreadable log yields a marker and stops the walk --");
const logFail = await collect(withBytes(repoApi({ "/log": new Error("500 log") }), blobFetcher({})));
ok("a /log record marked _unavailable is emitted", (() => { const r = logFail.find((x) => x.name === "ns/r/log"); return r?.value !== undefined && dec(r.value)._unavailable.includes("500 log"); })());
ok("no commit/tree/blob records once the log is unreadable", !logFail.some((r) => /\/(commit|tree|blob)\//.test(r.name)));
ok("the inventory record still captured the repo", logFail.some((r) => r.name === "ns/r"));

console.log("\n-- empty repo: a log with no commits walks nothing past the log --");
const empty = await collect(withBytes(repoApi({ "/log": [] }), blobFetcher({})));
ok("inventory + log only for an empty repo", empty.length === 2 && empty.some((r) => r.name === "ns/r") && empty.some((r) => r.name === "ns/r/log"));

console.log("\n-- duplicate commit hashes in the log are walked once --");
const dupCommit = await collect(withBytes(
  repoApi({ "/log": [{ hash: "c1" }, { hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": { entries: [] } }),
  blobFetcher({}),
));
ok("a commit hash repeated in the log is captured once", dupCommit.filter((r) => r.name === "ns/r/commit/c1").length === 1);

console.log("\n-- commit fail-open: an unreadable commit is marked, the rest of history continues --");
const commitFail = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "bad" }, { hash: "good" }],
    "/commit/bad": new Error("404 commit"),
    "/commit/good": { tree: "tg" },
    "/tree/tg": { entries: [{ type: "blob", hash: "bg" }] },
  }),
  blobFetcher({}),
));
ok("the unreadable commit is an _unavailable marker", (() => { const r = commitFail.find((x) => x.name === "ns/r/commit/bad"); return r?.value !== undefined && dec(r.value)._unavailable.includes("404 commit"); })());
ok("the next commit + its tree + blob are still captured (history not voided)", ["ns/r/commit/good", "ns/r/tree/tg", "ns/r/blob/bg"].every((n) => commitFail.some((r) => r.name === n)));

console.log("\n-- a commit with no tree hash yields the commit record then moves on --");
const noTree = await collect(withBytes(
  repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { message: "no tree here" } }),
  blobFetcher({}),
));
ok("the commit record is captured", noTree.some((r) => r.name === "ns/r/commit/c1"));
ok("no tree/blob records when the commit has no tree hash", !noTree.some((r) => /\/(tree|blob)\//.test(r.name)));

console.log("\n-- tree fail-open: an unreadable tree is marked, the walk continues --");
const treeFail = await collect(withBytes(
  repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": new Error("502 tree") }),
  blobFetcher({}),
));
ok("the unreadable tree is an _unavailable marker", (() => { const r = treeFail.find((x) => x.name === "ns/r/tree/t1"); return r?.value !== undefined && dec(r.value)._unavailable.includes("502 tree"); })());
ok("no blob records once that tree could not be read", !treeFail.some((r) => r.name.includes("/blob/")));

console.log("\n-- nested trees (dir entries) are pushed and walked; blobs deduped across them --");
const nested = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: "t1" },
    // t1 has a subtree (type "dir") and a blob; the subtree shares b1 with t1.
    "/tree/t1": { entries: [{ type: "dir", hash: "t2", name: "sub" }, { type: "blob", hash: "b1", name: "top" }] },
    "/tree/t2": { entries: [{ type: "blob", hash: "b1", name: "dup" }, { type: "blob", hash: "b2", name: "deep" }] },
  }),
  blobFetcher({}),
));
ok("the nested 'dir' subtree is walked", nested.some((r) => r.name === "ns/r/tree/t2"));
ok("a blob reachable from two trees is captured once (deduped)", nested.filter((r) => r.name === "ns/r/blob/b1").length === 1);
ok("the deep-only blob b2 is captured", nested.some((r) => r.name === "ns/r/blob/b2"));

console.log("\n-- tree entries without a hash, or already-seen as a tree, are skipped --");
const badEntries = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: "t1" },
    // entries: one with a non-string hash (skipped), one good blob, and a dir whose hash duplicates a
    // blob we have already captured (seen -> skipped, never walked as a tree).
    "/tree/t1": { entries: [{ type: "blob", hash: 42 }, { type: "blob", hash: "keep" }, { type: "dir", hash: "keep" }] },
  }),
  blobFetcher({}),
));
ok("an entry with a non-string hash is skipped", !badEntries.some((r) => r.name === "ns/r/blob/42"));
ok("the good blob is captured", badEntries.some((r) => r.name === "ns/r/blob/keep"));
ok("a dir entry whose hash was already seen as a blob is not re-walked as a tree", !badEntries.some((r) => r.name === "ns/r/tree/keep"));

console.log("\n-- captureBlob shapes: a large no-range blob is skipped, a large range blob is streamed --");
const shapes = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: "t1" },
    "/tree/t1": { entries: [{ type: "blob", hash: "big" }, { type: "blob", hash: "stream" }] },
  }),
  // "big" probes huge with no range support -> captureBlob returns a skip; "stream" probes huge AND
  // range-capable -> captureBlob returns a streamed StreamingValue.
  blobFetcher({ sizes: { big: 64 * 1024 * 1024, stream: 64 * 1024 * 1024 }, ranges: new Set(["stream"]) }),
));
ok("a large blob with no range support is a _skipped marker carrying the size", (() => { const r = shapes.find((x) => x.name === "ns/r/blob/big"); return r?.value !== undefined && dec(r.value)._skipped !== undefined && dec(r.value).size === 64 * 1024 * 1024; })());
ok("a large range-capable blob is captured as a stream record (no buffered value)", (() => { const r = shapes.find((x) => x.name === "ns/r/blob/stream"); return r !== undefined && r.stream !== undefined && r.value === undefined; })());

console.log("\n-- blob fail-open: an unreadable blob is a marker, the run is intact --");
const blobFail = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: "t1" },
    "/tree/t1": { entries: [{ type: "blob", hash: "ok" }, { type: "blob", hash: "boom" }] },
  }),
  blobFetcher({ fail: new Set(["boom"]) }),
));
ok("the good blob is captured", (() => { const r = blobFail.find((x) => x.name === "ns/r/blob/ok"); return r?.value !== undefined && new TextDecoder().decode(r.value) === "BYTES-ok"; })());
ok("the failing blob is an _unavailable marker (fail-open)", (() => { const r = blobFail.find((x) => x.name === "ns/r/blob/boom"); return r?.value !== undefined && dec(r.value)._unavailable.includes("403 blob boom"); })());

console.log("\n-- fail-open markers stringify a NON-Error throw (the String(e) arm) --");
// Each fail-open catch is `e instanceof Error ? e.message : String(e)`. The Error arm is covered above;
// here every step throws a bare string so the String(e) arm is exercised end to end.
const rawLog = await collect(withBytes(repoApi({ "/log": new ThrowRaw("raw-log-failure") }), blobFetcher({})));
ok("a non-Error log throw is stringified into the marker", (() => { const r = rawLog.find((x) => x.name === "ns/r/log"); return r?.value !== undefined && dec(r.value)._unavailable === "raw-log-failure"; })());

const rawCommit = await collect(withBytes(repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": new ThrowRaw("raw-commit-failure") }), blobFetcher({})));
ok("a non-Error commit throw is stringified into the marker", (() => { const r = rawCommit.find((x) => x.name === "ns/r/commit/c1"); return r?.value !== undefined && dec(r.value)._unavailable === "raw-commit-failure"; })());

const rawTree = await collect(withBytes(repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": new ThrowRaw("raw-tree-failure") }), blobFetcher({})));
ok("a non-Error tree throw is stringified into the marker", (() => { const r = rawTree.find((x) => x.name === "ns/r/tree/t1"); return r?.value !== undefined && dec(r.value)._unavailable === "raw-tree-failure"; })());

// The blob catch: a fetcher whose probe throws a bare string drives the blob marker's String(e) arm.
const rawBlobFetcher: ByteFetcher = {
  probe: async () => { throw "raw-blob-failure"; },
  wholeCapped: async () => ({ bytes: new Uint8Array(0) }),
  range: async () => new Uint8Array(0),
  streamedRange: async function* () { yield new Uint8Array(0); },
};
const rawBlob = await collect(withBytes(
  repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": { entries: [{ type: "blob", hash: "b1" }] } }),
  rawBlobFetcher,
));
ok("a non-Error blob throw is stringified into the marker", (() => { const r = rawBlob.find((x) => x.name === "ns/r/blob/b1"); return r?.value !== undefined && dec(r.value)._unavailable === "raw-blob-failure"; })());

console.log("\n-- a tree hash pushed onto the stack twice is walked once (stack-level dedup) --");
// One tree lists the same subtree hash "ts" TWICE. The entry-level guard only skips a hash already in
// `seen` (a popped tree); two not-yet-popped entries both push "ts", so the stack holds two "ts". The
// first pop walks + records it (adds to seen); the second pop hits the walkTree loop's `seen.has(th)`
// guard and is skipped. The result: one tree record for "ts", never two.
const treeDedup = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: "t1" },
    "/tree/t1": { entries: [{ type: "dir", hash: "ts", name: "a" }, { type: "dir", hash: "ts", name: "b" }] },
    "/tree/ts": { entries: [{ type: "blob", hash: "leaf" }] },
  }),
  blobFetcher({}),
));
ok("a subtree hash pushed twice is captured once (stack-level dedup)", treeDedup.filter((r) => r.name === "ns/r/tree/ts").length === 1);
ok("the shared subtree's blob is captured", treeDedup.some((r) => r.name === "ns/r/blob/leaf"));

console.log("\n-- budget runs out between trees on the stack (the walkTree loop-top guard) --");
// A budget set to ARTIFACTS_MAX_OBJECTS commits/trees so it is exhausted while the tree stack still has
// pending trees: one commit whose root tree fans out to many sibling subtrees, each with no blobs. The
// commit (1) + trees are captured until the budget hits 0 at the top of the walkTree while-loop, popping
// the next pending tree -> a _truncated marker.
const fanCount = ARTIFACTS_MAX_OBJECTS + 5;
const fanRoots = Array.from({ length: fanCount }, (_v, i) => ({ type: "dir", hash: `sub${i}`, name: `d${i}` }));
const fanRoutes: Record<string, unknown> = { "/log": [{ hash: "c1" }], "/commit/c1": { tree: "root" }, "/tree/root": { entries: fanRoots } };
for (let i = 0; i < fanCount; i++) fanRoutes[`/tree/sub${i}`] = { entries: [] };
const fan = await collect(withBytes(repoApi(fanRoutes), blobFetcher({})));
ok("a _truncated marker is emitted when the budget runs out mid-tree-stack", fan.some((r) => r.name === "ns/r/_truncated"));
ok("not every fanned subtree was captured (the loop-top guard cut it short)", fan.filter((r) => r.name.startsWith("ns/r/tree/")).length < fanCount + 1);

console.log("\n-- object budget: a repo over ARTIFACTS_MAX_OBJECTS emits a _truncated marker --");
// One commit, one tree, and (MAX + 50) distinct blobs. The walk captures the commit (1), the tree (1),
// then blobs until the shared budget is exhausted, after which it emits exactly one _truncated marker.
const many = ARTIFACTS_MAX_OBJECTS + 50;
const bigEntries = Array.from({ length: many }, (_v, i) => ({ type: "blob", hash: `b${i}` }));
const truncated = await collect(withBytes(
  repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": { entries: bigEntries } }),
  blobFetcher({}),
));
ok("exactly one _truncated marker is emitted at the object cap", truncated.filter((r) => r.name === "ns/r/_truncated").length === 1);
ok("the truncated marker explains the cap was exceeded", (() => { const r = truncated.find((x) => x.name === "ns/r/_truncated"); return r?.value !== undefined && dec(r.value)._truncated.includes(String(ARTIFACTS_MAX_OBJECTS)); })());
ok("fewer than the full blob set was captured (the walk stopped at the cap)", truncated.filter((r) => r.name.startsWith("ns/r/blob/")).length < many);

console.log("\n-- budget exhausted exactly at a commit boundary -> truncated before the next commit --");
// A budget of MAX commits-plus-trees: with many commits each pointing at its own tiny tree, the budget
// is spent on commits/trees and a later commit trips the budget<=0 guard at the top of the loop.
const manyCommits = Array.from({ length: ARTIFACTS_MAX_OBJECTS + 10 }, (_v, i) => ({ hash: `c${i}` }));
const commitRoutes: Record<string, unknown> = { "/log": manyCommits };
for (let i = 0; i < manyCommits.length; i++) {
  commitRoutes[`/commit/c${i}`] = { tree: `t${i}` };
  commitRoutes[`/tree/t${i}`] = { entries: [] };
}
const commitBudget = await collect(withBytes(repoApi(commitRoutes), blobFetcher({})));
ok("a _truncated marker is emitted when the budget runs out across commits", commitBudget.some((r) => r.name === "ns/r/_truncated"));
ok("not every commit was captured (the budget cut the history short)", commitBudget.filter((r) => r.name.startsWith("ns/r/commit/")).length < manyCommits.length);

// ---------------------------------------------------------------------------
console.log("\n-- log/commit/tree shape tolerance (commitHashes, treeHashOf, treeEntries) --");
// ---------------------------------------------------------------------------

// commitHashes: log as {commits:[...]} with mixed shapes (a bare string hash, {sha}, {id}, an empty
// string filtered out, and an object with none of hash/sha/id which contributes nothing).
const mixedLog = await collect(withBytes(
  repoApi({
    "/log": { commits: ["s1", { sha: "s2" }, { id: "s3" }, "", { note: "no hash" }] },
    "/commit/s1": { tree: "ta" }, "/commit/s2": { tree: "tb" }, "/commit/s3": { tree: "tc" },
    "/tree/ta": { entries: [] }, "/tree/tb": { entries: [] }, "/tree/tc": { entries: [] },
  }),
  blobFetcher({}),
));
ok("a {commits:[...]} log with string/{sha}/{id} hashes resolves all three commits", ["ns/r/commit/s1", "ns/r/commit/s2", "ns/r/commit/s3"].every((n) => mixedLog.some((r) => r.name === n)));
ok("an empty-string hash and a hash-less object contribute no commit records", mixedLog.filter((r) => r.name.startsWith("ns/r/commit/")).length === 3);

// commitHashes: a log that is neither an array nor {commits:[]} (here a bare object) yields zero commits
// -> inventory + log only.
const oddLog = await collect(withBytes(repoApi({ "/log": { not: "a list" } }), blobFetcher({})));
ok("a log of an unrecognised shape walks nothing past the log", oddLog.length === 2 && oddLog.some((r) => r.name === "ns/r/log"));

// treeHashOf: a commit whose tree is the object form {hash}; and treeEntries reading {children:[...]}.
const objTree = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: { hash: "t1" } },
    "/tree/t1": { children: [{ type: "blob", hash: "b1" }] },
  }),
  blobFetcher({}),
));
ok("a commit tree given as {hash} is resolved", objTree.some((r) => r.name === "ns/r/tree/t1"));
ok("a tree given as {children:[...]} yields its blob", objTree.some((r) => r.name === "ns/r/blob/b1"));

// treeHashOf: a commit whose tree is a non-string, non-{hash} value -> undefined -> no tree walked.
const weirdTree = await collect(withBytes(
  repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { tree: 12345 } }),
  blobFetcher({}),
));
ok("a commit with a non-string, non-{hash} tree walks no tree", weirdTree.some((r) => r.name === "ns/r/commit/c1") && !weirdTree.some((r) => r.name.includes("/tree/")));

// treeEntries: a tree returned as a BARE array. The tolerant reader is `entries ?? children ?? tree`,
// but a JS array always carries an Array.prototype.entries method, so `tree.entries` is truthy (a
// function, not the entry list) and the `?? children ?? tree` fallbacks never fire; that function is not
// an array, so treeEntries reads no entries. The tree record is still emitted; no blobs are walked from
// a bare-array tree. (Trees in practice arrive wrapped as {entries:[...]} / {children:[...]}.)
const bareTree = await collect(withBytes(
  repoApi({
    "/log": [{ hash: "c1" }],
    "/commit/c1": { tree: "t1" },
    "/tree/t1": [{ type: "blob", hash: "b1" }],
  }),
  blobFetcher({}),
));
ok("a bare-array tree still yields the tree record", bareTree.some((r) => r.name === "ns/r/tree/t1"));
ok("a bare-array tree walks no blobs (Array.prototype.entries shadows the entry list)", !bareTree.some((r) => r.name.includes("/blob/")));

// treeEntries: a tree object with no entries/children and not an array -> no entries, no blobs.
const emptyTree = await collect(withBytes(
  repoApi({ "/log": [{ hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": { meta: "no entries" } }),
  blobFetcher({}),
));
ok("a tree object with no entries/children yields the tree record but no blobs", emptyTree.some((r) => r.name === "ns/r/tree/t1") && !emptyTree.some((r) => r.name.includes("/blob/")));

// ---------------------------------------------------------------------------
// R2-3 RESUMABILITY: a registry with more repos than fit one slice resumes from the
// cursor and captures the FULL set across two crawl calls, rather than restarting.
// crawlFrom emits a {mark} after each fully-yielded repo; a resume from a mark re-lists
// the namespaces + repos and skips every repo up to and including the recorded
// "<ns>/<repo>" watermark. (stubApi above is stateless across calls, so a resume re-lists
// the same order.)
// ---------------------------------------------------------------------------
console.log("\n-- R2-3: crawlFrom is RESUMABLE (marks after each repo, resume skips the yielded prefix) --");
{
  const mkApi = (): CfApi => stubApi({
    namespaces: [{ name: "ns1" }, { name: "ns2" }],
    reposByNs: { ns1: [{ name: "r1" }, { name: "r2" }], ns2: [{ name: "r3" }, { name: "r4" }] },
  });
  ok("ArtifactsSource is resumable (implements crawlFrom)", isResumable(new ArtifactsSource("acct", mkApi())));

  const evs: CrawlEvent[] = [];
  for await (const ev of new ArtifactsSource("acct", mkApi()).crawlFrom(ALL, null)) evs.push(ev);
  const marks = evs.filter((e) => e.kind === "mark") as Array<{ kind: "mark"; token: string }>;
  const fromScratch = evs.filter((e) => e.kind === "record").map((e) => (e as { record: SourceRecord }).record.name);
  ok("from scratch yields every repo across both namespaces", ["ns1/r1", "ns1/r2", "ns2/r3", "ns2/r4"].every((n) => fromScratch.includes(n)));
  ok("a mark is emitted after each of the 4 repos", marks.length === 4);

  // Resume from the mark after ns1/r2 (the 2nd repo, end of namespace 1): the resume must yield ns2/r3
  // and ns2/r4 and never re-read any ns1 repo (the seal would otherwise double-capture them).
  const afterNs1r2 = marks[1]!.token;
  ok("the 2nd mark is the watermark after ns1/r2", (JSON.parse(afterNs1r2) as { afterRecName: string }).afterRecName === "ns1/r2");
  const resumed: string[] = [];
  for await (const ev of new ArtifactsSource("acct", mkApi()).crawlFrom(ALL, afterNs1r2))
    if (ev.kind === "record") resumed.push(ev.record.name);
  ok("resume after ns1/r2 yields only ns2/r3, ns2/r4 (crossing the namespace boundary)", resumed.join(",") === "ns2/r3,ns2/r4");
  ok("resume re-reads no ns1 repo", !resumed.some((n) => n.startsWith("ns1/")));

  // The FULL set across two slices: slice 1 stops at the first repo's mark, slice 2 resumes; the union
  // is the whole registry captured exactly once, with NO restart-from-the-beginning duplication.
  const sliceOne: string[] = [];
  let firstMark: string | null = null;
  for await (const ev of new ArtifactsSource("acct", mkApi()).crawlFrom(ALL, null)) {
    if (ev.kind === "record") sliceOne.push(ev.record.name);
    else if (ev.kind === "mark") { firstMark = ev.token; break; }
  }
  const sliceTwo: string[] = [];
  for await (const ev of new ArtifactsSource("acct", mkApi()).crawlFrom(ALL, firstMark))
    if (ev.kind === "record") sliceTwo.push(ev.record.name);
  ok("slice 1 captured the first repo only (budget yielded at its mark)", sliceOne.join(",") === "ns1/r1");
  ok("two slices together capture every repo exactly once (no restart)",
    [...sliceOne, ...sliceTwo].sort().join(",") === "ns1/r1,ns1/r2,ns2/r3,ns2/r4");
}

// ---------------------------------------------------------------------------
// A2 (HIGH, can wedge a run): a repo whose CONTENT walk (includeContent) exceeds one invocation's
// subrequest budget must NOT run to the platform cap with no checkpoint and wedge/restart the run. The
// R2-3 fix made the source-LIST resumable but the per-repo content walk only emitted a {mark} at the
// COARSE per-repo boundary, so a single huge repo's content walk never yielded a resume mark and the run
// wedged. The fix emits an INTRA-repo {mark} (carrying an `inRepo` cursor) after a content record whenever
// the slice budget is low, and a resume from that cursor replays the repo's deterministic walk, skipping
// the already-yielded content records, then continues to completion across slices.
//
// The seal slice passes a SliceBudget as the Meter; the budget's shouldYield() is what the walk reads to
// decide when to checkpoint. The validator drives the same contract with a fake budget whose shouldYield()
// flips true after a chosen number of subrequest spends, so a mid-repo {mark} is forced deterministically.
console.log("\n-- A2: the per-repo content walk CHECKPOINTS mid-repo and resumes across slices --");

// FakeBudget is a Meter that ALSO exposes shouldYield() (the structural BudgetLike the source detects):
// shouldYield() returns true once at least `yieldAfter` subrequests have been spent, so a long content
// walk trips an intra-repo mark. A plain Meter (no shouldYield) never trips one, so the walk runs whole.
class FakeBudget implements Meter {
  spent = 0;
  private readonly yieldAfter: number;
  constructor(yieldAfter: number) { this.yieldAfter = yieldAfter; }
  spend(n = 1): void { this.spent += n; }
  shouldYield(): boolean { return this.spent >= this.yieldAfter; }
}

// A repo with one commit, one tree, and six blobs: enough content records that an early budget-yield lands
// MID content walk (not at the repo boundary). The content record order is deterministic:
//   ns/r/log, ns/r/commit/c1, ns/r/tree/t1, ns/r/blob/b0 .. ns/r/blob/b5
const a2Blobs = Array.from({ length: 6 }, (_v, i) => ({ type: "blob", hash: `b${i}` }));
const a2Routes: Record<string, unknown> = { "/log": [{ hash: "c1" }], "/commit/c1": { tree: "t1" }, "/tree/t1": { entries: a2Blobs } };
const mkA2Api = (): CfApi => repoApi(a2Routes);
// a2Fetcher meters its probe (like the production byte fetcher, which charges a subrequest per blob read),
// so a per-blob spend advances the FakeBudget and the intra-repo checkpoint lands AFTER some blobs rather
// than only in the cheap metadata phase. yieldAfter is tuned so the watermark falls a couple of blobs in.
const a2Fetcher = (): ByteFetcher => {
  const base = blobFetcher({});
  return { ...base, probe: async (t, m) => { m?.spend(1, "cfApiRead"); return base.probe(t, m); } };
};
// Spends before the blobs: paginate namespaces(1) + repos(1) + log(1) + commit(1) + tree(1) = 5, then one
// per blob probe. yieldAfter 7 trips shouldYield after the SECOND blob (b1), so the watermark is mid-blobs.
const A2_YIELD_AFTER = 7;

// The WHOLE walk's record names (no budget pressure), the ground truth the sliced runs must reproduce
// exactly once.
const wholeNames: string[] = [];
for await (const ev of withBytes(mkA2Api(), a2Fetcher()).crawlFrom(ALL, null))
  if (ev.kind === "record") wholeNames.push(ev.record.name);
ok("the whole content walk yields the inventory + log + commit + tree + 6 blobs", wholeNames.length === 1 + 3 + 6);

// RED-BEFORE-GREEN: with a budget that wants to yield early, the content walk must emit an intra-repo
// {mark} (a mark whose token carries an `inRepo` cursor) PART-WAY through the repo. The OLD code only
// emitted a mark at the per-repo boundary (no inRepo cursor), so this assertion fails against it: a huge
// repo's walk never yielded and the run wedged.
{
  const budget = new FakeBudget(A2_YIELD_AFTER);
  const events: CrawlEvent[] = [];
  for await (const ev of withBytes(mkA2Api(), a2Fetcher()).crawlFrom(ALL, null, budget)) events.push(ev);
  const intraRepoMarks = events
    .filter((e): e is { kind: "mark"; token: string } => e.kind === "mark")
    .map((e) => JSON.parse(e.token) as { afterRecName: string; inRepo?: { recName: string; afterContent: string } })
    .filter((t) => t.inRepo !== undefined);
  ok("an INTRA-repo mark (carrying an inRepo cursor) is emitted mid content walk (A2; OLD code never did)", intraRepoMarks.length > 0);
  ok("the inRepo cursor names the repo and a content record within it", (() => {
    const c = intraRepoMarks[0]?.inRepo; return c?.recName === "ns/r" && c.afterContent.startsWith("ns/r/");
  })());
}

// The repo's content is captured to COMPLETION across two crawl calls without re-reading already-yielded
// records: slice 1 runs under budget pressure and stops at the FIRST intra-repo mark; slice 2 resumes from
// that mark (no pressure) and finishes. The union is the whole walk, exactly once, with no duplication.
{
  const budget = new FakeBudget(A2_YIELD_AFTER);
  const sliceOne: string[] = [];
  let resumeToken: string | null = null;
  for await (const ev of withBytes(mkA2Api(), a2Fetcher()).crawlFrom(ALL, null, budget)) {
    if (ev.kind === "record") { sliceOne.push(ev.record.name); continue; }
    if (ev.kind !== "mark") continue; // only marks carry a resume token (record events do not)
    const t = JSON.parse(ev.token) as { inRepo?: unknown };
    if (t.inRepo !== undefined) { resumeToken = ev.token; break; } // stop at the first MID-repo checkpoint
  }
  ok("slice 1 stopped at an intra-repo checkpoint (a mark with an inRepo cursor)", resumeToken !== null);
  ok("slice 1 captured the inventory record and some but NOT all content", sliceOne.includes("ns/r") && sliceOne.length < wholeNames.length);

  const sliceTwo: string[] = [];
  for await (const ev of withBytes(mkA2Api(), a2Fetcher()).crawlFrom(ALL, resumeToken))
    if (ev.kind === "record") sliceTwo.push(ev.record.name);
  ok("slice 2 re-yields NO record slice 1 already yielded (no mid-repo duplication)", !sliceTwo.some((n) => sliceOne.includes(n)));
  ok("the two slices together capture the whole repo walk exactly once", [...sliceOne, ...sliceTwo].sort().join(",") === [...wholeNames].sort().join(","));
}

// Resuming from a mid-repo cursor does NOT re-yield the repo's INVENTORY record (it was yielded in the
// earlier slice) and does NOT re-fetch the already-captured blob bytes: the replay rebuilds the dedup set
// from the cheap metadata reads and skips the blob fetches it would only discard.
{
  const budget = new FakeBudget(A2_YIELD_AFTER);
  let resumeToken: string | null = null;
  for await (const ev of withBytes(mkA2Api(), a2Fetcher()).crawlFrom(ALL, null, budget)) {
    if (ev.kind !== "mark") continue;
    const t = JSON.parse(ev.token) as { inRepo?: unknown };
    if (t.inRepo !== undefined) { resumeToken = ev.token; break; }
  }
  let fetches = 0;
  const baseFetcher = blobFetcher({});
  const countingFetcher: ByteFetcher = {
    ...baseFetcher,
    probe: async (t, m) => { fetches++; return baseFetcher.probe(t, m); },
  };
  const resumed: string[] = [];
  for await (const ev of new ArtifactsSource("acct", mkA2Api(), { includeContent: true, bytes: countingFetcher }).crawlFrom(ALL, resumeToken))
    if (ev.kind === "record") resumed.push(ev.record.name);
  ok("the resume does NOT re-yield the repo inventory record", !resumed.includes("ns/r"));
  // Only the blobs AFTER the watermark are fetched on resume; the replayed (pre-watermark) blobs are not.
  ok("the resume re-fetches only the blobs past the watermark (replayed blobs are not re-fetched)", fetches < 6 && fetches > 0);
}

// A malformed inRepo cursor throws rather than silently restarting the whole crawl (mirrors the
// afterRecName guard). A present-but-shapeless inRepo is corruption, not a fresh start.
{
  let threw = false;
  try {
    const bad = JSON.stringify({ afterRecName: "", inRepo: { recName: 123 } });
    for await (const _ev of withBytes(mkA2Api(), a2Fetcher()).crawlFrom(ALL, bad)) void _ev;
  } catch { threw = true; }
  ok("a malformed inRepo cursor throws (never a silent whole-crawl restart)", threw);
}

console.log(failures === 0 ? "\nARTIFACTS SOURCE PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
