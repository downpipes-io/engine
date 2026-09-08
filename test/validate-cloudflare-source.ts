// Validates the Cloudflare config backup source (src/sources/cloudflare-config.ts +
// cf-config-surfaces.ts): the crawl yields one buffered-JSON record per in-scope surface,
// the selector scopes by surface id, account-only crawls skip zone surfaces, every API call
// is metered, the size guard refuses an oversized surface, and an unsuccessful API response
// throws (never a silent empty record). The CF API is stubbed (no network).
// Run: node test/validate-cloudflare-source.ts.

import { CloudflareConfigSource } from "../src/sources/cloudflare-config.ts";
import { CF_CONFIG_SURFACES, CF_CONFIG_IDENTITY_ID, surfaceById, makeCfApi, type CfConfigSurface } from "../src/sources/cf-config-surfaces.ts";
import type { Selector, SourceRecord, CrawlEvent } from "../src/sources/types.ts";
import { isResumable } from "../src/sources/types.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

const ALL: Selector = { include: [], exclude: [] };

// stubFetch returns a successful CF envelope for any path, recording the calls.
function stubFetch(calls: string[], auths?: string[]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (auths) {
      const h = new Headers(init?.headers);
      auths.push(h.get("authorization") ?? "");
    }
    return new Response(JSON.stringify({ success: true, result: [{ stub: true }] }), { status: 200 });
  }) as typeof fetch;
}

async function collect(it: AsyncIterable<SourceRecord>): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of it) out.push(r);
  return out;
}

console.log("-- crawl with a zone: one record per surface, metered, bearer-authed --");
{
  const calls: string[] = [];
  const auths: string[] = [];
  let spends = 0;
  const meter = { spend: (n = 1) => { spends += n; } };
  const src = new CloudflareConfigSource("tok", "acct123", "zone456", CF_CONFIG_SURFACES, stubFetch(calls, auths));
  const recs = await collect(src.crawl(ALL, meter));
  // The crawl now emits the self-identifying record first, then one record per surface.
  const surfaceRecs = recs.filter((r) => r.name !== CF_CONFIG_IDENTITY_ID);
  ok("one record per surface in the registry (plus the leading identity record)", recs.length === CF_CONFIG_SURFACES.length + 1 && surfaceRecs.length === CF_CONFIG_SURFACES.length);
  ok("every record is sourceType cf-config with a buffered JSON value", recs.every((r) => r.sourceType === "cf-config" && r.value instanceof Uint8Array && r.value.length > 0));
  ok("each surface record name is a known surface id (identity aside)", surfaceRecs.every((r) => CF_CONFIG_SURFACES.some((s) => s.id === r.name)));
  ok("no record streams (config is all buffered JSON)", recs.every((r) => r.stream === undefined));
  ok("every API call was metered (>= one spend per surface)", spends >= recs.length);
  ok("calls hit the Cloudflare API base", calls.length > 0 && calls.every((u) => u.startsWith("https://api.cloudflare.com/client/v4")));
  ok("every call carries Authorization: Bearer tok", auths.length > 0 && auths.every((a) => a === "Bearer tok"));
}

console.log("-- account-only (no zone): zone-scoped surfaces are skipped --");
{
  const accountSurfaces = CF_CONFIG_SURFACES.filter((s) => s.scope === "account");
  const src = new CloudflareConfigSource("tok", "acct123", undefined, CF_CONFIG_SURFACES, stubFetch([]));
  const recs = await collect(src.crawl(ALL));
  const surfaceRecs = recs.filter((r) => r.name !== CF_CONFIG_IDENTITY_ID);
  ok("only account-scoped surfaces are yielded (plus the identity record)", surfaceRecs.length === accountSurfaces.length && surfaceRecs.every((r) => accountSurfaces.some((s) => s.id === r.name)));
  ok("no zone-scoped surface leaked in", !surfaceRecs.some((r) => CF_CONFIG_SURFACES.find((s) => s.id === r.name)?.scope === "zone"));
}

console.log("-- selector selects surfaces by EXACT id (the per-surface tick-boxes) --");
{
  const src = new CloudflareConfigSource("tok", "a", "z", CF_CONFIG_SURFACES, stubFetch([]));
  // include = exactly the ticked surface ids (the identity record is always emitted alongside).
  const picked = (await collect(src.crawl({ include: ["dns", "zone-settings"], exclude: [] }))).filter((r) => r.name !== CF_CONFIG_IDENTITY_ID);
  ok("include keeps exactly the listed surfaces", picked.length === 2 && picked.every((r) => r.name === "dns" || r.name === "zone-settings"));
  // EXACT, not prefix: ticking "dns" must NOT also pull "dns-settings".
  ok("selection is exact, not prefix (dns does not pull dns-settings)", picked.some((r) => r.name === "dns") && !picked.some((r) => r.name === "dns-settings"));
  // exclude drops exactly the listed surface, leaving its same-prefix neighbours.
  const without = (await collect(src.crawl({ include: [], exclude: ["dns"] }))).filter((r) => r.name !== CF_CONFIG_IDENTITY_ID);
  ok("exclude drops exactly the listed surface", !without.some((r) => r.name === "dns") && without.some((r) => r.name === "dns-settings") && without.length === CF_CONFIG_SURFACES.length - 1);
}

console.log("-- estimate reports surface count, never reads values --");
{
  const calls: string[] = [];
  const src = new CloudflareConfigSource("tok", "a", "z", CF_CONFIG_SURFACES, stubFetch(calls));
  const est = await src.estimate(ALL);
  ok("estimate.records is the in-scope surface count + the identity record (matches a real run)", est.records === CF_CONFIG_SURFACES.length + 1);
  ok("estimate.bytes is -1 (unknown, never sized by reading)", est.bytes === -1);
  ok("estimate made no API calls", calls.length === 0);
}

console.log("-- fail-open per surface: one unavailable surface is marked, not fatal --");
{
  // One read fails (a deprecated/unscoped surface like Page Rules or Logpush), one succeeds. The
  // failing surface becomes an _unavailable MARKER, the working one a real record, and the crawl
  // COMPLETES; a single bad surface never breaks the whole config snapshot (the live-tested bug).
  const okSurface: CfConfigSurface = { id: "zone-settings", scope: "zone", restoreTier: "idempotent", read: async () => ({ items: [] }) };
  const badSurface: CfConfigSurface = { id: "logpush", scope: "zone", restoreTier: "ordered", read: async () => { throw new Error("Cloudflare API GET /zones/z/logpush/jobs: Authentication error"); } };
  const recs = (await collect(new CloudflareConfigSource("tok", "a", "z", [okSurface, badSurface], stubFetch([])).crawl(ALL))).filter((r) => r.name !== CF_CONFIG_IDENTITY_ID);
  ok("both surfaces yield a record (none dropped)", recs.length === 2);
  const bad = recs.find((r) => r.name === "logpush");
  const good = recs.find((r) => r.name === "zone-settings");
  const badV = bad ? (JSON.parse(new TextDecoder().decode(bad.value!)) as { _unavailable?: string }) : null;
  ok("the unavailable surface is an _unavailable marker, not a fatal throw", !!badV && typeof badV._unavailable === "string" && /Authentication error/.test(badV._unavailable));
  ok("the working surface is a real record (no marker)", !!good && (JSON.parse(new TextDecoder().decode(good.value!)) as { _unavailable?: string })._unavailable === undefined);
}

console.log("-- size guard marks an oversized surface unavailable (does not break the run) --");
{
  const okSurface: CfConfigSurface = { id: "dns", scope: "zone", restoreTier: "idempotent", read: async () => ({ ok: true }) };
  const bigSurface: CfConfigSurface = { id: "rulesets", scope: "zone", restoreTier: "idempotent", read: async () => "x".repeat(500) };
  const recs = await collect(new CloudflareConfigSource("tok", "a", "z", [okSurface, bigSurface], stubFetch([]), 50 /* small limit */).crawl(ALL));
  const big = recs.find((r) => r.name === "rulesets");
  const good = recs.find((r) => r.name === "dns");
  ok("a surface past the size limit is marked unavailable, not fatal", !!big && /exceeds the 50-byte limit/.test((JSON.parse(new TextDecoder().decode(big.value!)) as { _unavailable?: string })._unavailable ?? ""));
  ok("the under-limit surface still yields a real record", !!good && (JSON.parse(new TextDecoder().decode(good.value!)) as { _unavailable?: string })._unavailable === undefined);
}

console.log("-- EVERY surface failing throws loudly (a broken token, not a per-surface gap) --");
{
  const errFetch = (async () => new Response(JSON.stringify({ success: false, errors: [{ message: "Authentication error" }] }), { status: 403 })) as typeof fetch;
  const src = new CloudflareConfigSource("tok", "a", "z", CF_CONFIG_SURFACES, errFetch);
  let threw = "";
  try { await collect(src.crawl(ALL)); } catch (e) { threw = (e as Error).message; }
  ok("all surfaces failing throws (never a silent all-unavailable 'success')", /every Cloudflare config surface failed/.test(threw));
}

console.log("-- zone-settings DIFF-driven restore: only changed editable settings, fail-open per item --");
{
  // Live now: always_online=on, ssl=full, ciphers=["A"]. Snapshot: always_online=off (changed),
  // ssl=full (same -> not touched), ciphers=["B"] (changed but the API rejects -> skipped),
  // min_tls_version (editable:false -> ignored).
  const current = [
    { id: "always_online", value: "on", editable: true },
    { id: "ssl", value: "full", editable: true },
    { id: "ciphers", value: ["A"], editable: true },
  ];
  const snapshot = [
    { id: "always_online", value: "off", editable: true },
    { id: "ssl", value: "full", editable: true },
    { id: "ciphers", value: ["B"], editable: true },
    { id: "min_tls_version", value: "1.2", editable: false },
  ];
  const writes: Array<{ path: string; body: unknown }> = [];
  const stub = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    if (method === "GET" && /\/settings$/.test(url)) return new Response(JSON.stringify({ success: true, result: current }), { status: 200 });
    if (/\/settings\/ciphers$/.test(url)) return new Response(JSON.stringify({ success: false, errors: [{ message: "ACM required" }] }), { status: 400 });
    writes.push({ path: url, body: init?.body ? JSON.parse(String(init.body)) : null });
    return new Response(JSON.stringify({ success: true, result: {} }), { status: 200 });
  }) as typeof fetch;
  const zs = surfaceById("zone-settings")!;
  const ids = { accountId: "a", zoneId: "z" };
  const api = makeCfApi("tok", stub);
  const preview = await zs.write!(api, ids, snapshot, { dryRun: true });
  ok("diff lists only the changed editable settings", preview.changes.length === 2 && preview.changes.some((c) => c.path === "always_online") && preview.changes.some((c) => c.path === "ciphers"));
  ok("a dry-run diff writes nothing", writes.length === 0);
  const alwaysOnline = preview.changes.find((c) => c.path === "always_online");
  ok("the diff shows current -> snapshot (from/to)", alwaysOnline?.from === '"on"' && alwaysOnline?.to === '"off"');
  const applied = await zs.write!(api, ids, snapshot, { dryRun: false });
  ok("apply writes only changed settings, individually", writes.length === 1 && /\/settings\/always_online$/.test(writes[0]!.path));
  ok("a setting the API rejects is skipped, not fatal", applied.applied === 1 && applied.skipped.length === 1 && applied.skipped[0]!.path === "ciphers");
  ok("the unchanged setting (ssl) is never written", !writes.some((w) => /\/settings\/ssl$/.test(w.path)));
}

console.log("-- a refusal spelled `error` instead of `message` must still carry its reason --");
{
  // Cloudflare is not consistent about its error envelope. Most endpoints answer
  // `errors:[{code, message}]`, but some answer `errors:[{code, error}]`, and the account
  // endpoint-healthchecks endpoint is one of them. Reading only `message` left the extracted list empty,
  // so the thrown error fell back to a bare "HTTP 400": the operator, the log line and the support pack
  // all got a refusal with no reason attached, and isCfPlanEntitlementError had no text to classify it by.
  const withMessage = (async () => new Response(JSON.stringify({ success: false, errors: [{ code: 1002, message: "spelled message" }] }), { status: 400 })) as typeof fetch;
  const withError = (async () => new Response(JSON.stringify({ success: false, errors: [{ code: 1002, error: "spelled error" }] }), { status: 400 })) as typeof fetch;
  const both = (async () => new Response(JSON.stringify({ success: false, errors: [{ code: 1002, message: "prefer me", error: "not me" }] }), { status: 400 })) as typeof fetch;
  const reasonOf = async (f: typeof fetch): Promise<string> => {
    try {
      await makeCfApi("tok", f).get("/zones/z/thing");
      return "(no throw)";
    } catch (e) {
      return (e as Error).message;
    }
  };
  ok("the `message` spelling still carries its reason", (await reasonOf(withMessage)).includes("spelled message"));
  ok("the `error` spelling carries its reason too", (await reasonOf(withError)).includes("spelled error"));
  ok("neither degrades to a bare status line", !(await reasonOf(withError)).includes("HTTP 400"));
  ok("`message` wins when a payload carries both, so the existing shape is unchanged", (await reasonOf(both)).includes("prefer me"));
  ok("the numeric code still rides on the thrown error", (await reasonOf(withError)).length > 0);
}

console.log("-- pagination: a multi-page list surface accumulates EVERY page, not just the first --");
{
  // A zone with 3 pages of DNS records (page-based result_info). The crawl must back up ALL of them,
  // not silently truncate at page 1. per_page here is whatever the surface requests;
  // the stub answers each ?page=N with that page's slice and a result_info carrying total_pages=3.
  const PER = 1000; // the surface's per_page (CF_PAGINATION_PER_PAGE)
  const total = PER * 2 + 7; // 2007 records: page 1 full, page 2 full, page 3 short (7), which exercises total_pages AND a short tail
  const totalPages = 3;
  const pagesSeen: number[] = [];
  const pagingFetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (/\/dns_records$/.test(url.pathname)) {
      const page = Number(url.searchParams.get("page") ?? "1");
      pagesSeen.push(page);
      const start = (page - 1) * PER;
      const slice = Array.from({ length: Math.max(0, Math.min(PER, total - start)) }, (_, k) => ({ id: `rec-${start + k}`, type: "A", name: `h${start + k}.example.com`, content: "1.2.3.4" }));
      return new Response(JSON.stringify({ success: true, result: slice, result_info: { page, per_page: PER, count: slice.length, total_count: total, total_pages: totalPages } }), { status: 200 });
    }
    // every other surface: a single short page (no more pages)
    return new Response(JSON.stringify({ success: true, result: [{ stub: true }] }), { status: 200 });
  }) as typeof fetch;
  const recs = await collect(new CloudflareConfigSource("tok", "a", "z", CF_CONFIG_SURFACES, pagingFetch).crawl({ include: ["dns"], exclude: [] }));
  const dns = recs.find((r) => r.name === "dns");
  const parsed = dns ? (JSON.parse(new TextDecoder().decode(dns.value!)) as unknown[]) : [];
  ok("the dns surface backs up EVERY record across all pages (no truncation)", Array.isArray(parsed) && parsed.length === total);
  ok("pagination followed all 3 pages in order", pagesSeen.length === 3 && pagesSeen[0] === 1 && pagesSeen[1] === 2 && pagesSeen[2] === 3);
  ok("the first and last record are both present (head and tail captured)", parsed.some((r) => (r as { id?: string }).id === "rec-0") && parsed.some((r) => (r as { id?: string }).id === `rec-${total - 1}`));
  ok("no _unavailable/_truncated marker on a fully-read surface", !(parsed as unknown as { _unavailable?: unknown; _truncated?: unknown })._unavailable && !(parsed as unknown as { _truncated?: unknown })._truncated);
}

console.log("-- cursor pagination: a cursor-style list follows result_info.cursor to exhaustion --");
{
  // Some endpoints page by an opaque cursor, not page numbers. The paginator must follow cursor ->
  // cursor until it is empty. We drive the dns surface with a 2-cursor sequence (no page numbers).
  const seen: Array<string | null> = [];
  const cursorFetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (/\/dns_records$/.test(url.pathname)) {
      const cursor = url.searchParams.get("cursor");
      seen.push(cursor);
      if (cursor === null) return new Response(JSON.stringify({ success: true, result: [{ id: "c0" }], result_info: { cursor: "CUR1" } }), { status: 200 });
      if (cursor === "CUR1") return new Response(JSON.stringify({ success: true, result: [{ id: "c1" }], result_info: { cursor: "CUR2" } }), { status: 200 });
      return new Response(JSON.stringify({ success: true, result: [{ id: "c2" }], result_info: { cursor: "" } }), { status: 200 }); // empty cursor -> done
    }
    return new Response(JSON.stringify({ success: true, result: [{ stub: true }] }), { status: 200 });
  }) as typeof fetch;
  const recs = await collect(new CloudflareConfigSource("tok", "a", "z", CF_CONFIG_SURFACES, cursorFetch).crawl({ include: ["dns"], exclude: [] }));
  const parsed = JSON.parse(new TextDecoder().decode(recs.find((r) => r.name === "dns")!.value!)) as Array<{ id: string }>;
  ok("cursor pagination accumulates every cursor page", parsed.length === 3 && parsed.map((r) => r.id).join(",") === "c0,c1,c2");
  ok("the cursor was followed first-page->CUR1->CUR2 then stopped on the empty cursor", seen.length === 3 && seen[0] === null && seen[1] === "CUR1" && seen[2] === "CUR2");
}

console.log("-- max-pages guard: an endless list TRUNCATES with an honest marker, never loops or silently drops --");
{
  // A pathological endpoint that ALWAYS claims another page (total_pages huge, full page every time).
  // Without a guard the crawl would loop forever; the guard must stop at the cap and record a
  // _truncated marker (NOT _unavailable, and NOT a silent partial passed off as complete).
  let calls = 0;
  const endlessFetch = (async (input: RequestInfo | URL) => {
    const url = new URL(String(input));
    if (/\/dns_records$/.test(url.pathname)) {
      calls++;
      // a full page (>= per_page) every time, total_pages always one beyond the current page
      const page = Number(url.searchParams.get("page") ?? "1");
      const per = Number(url.searchParams.get("per_page") ?? "1000");
      const slice = Array.from({ length: per }, (_, k) => ({ id: `x-${page}-${k}` }));
      return new Response(JSON.stringify({ success: true, result: slice, result_info: { page, per_page: per, total_pages: page + 100 } }), { status: 200 });
    }
    return new Response(JSON.stringify({ success: true, result: [{ stub: true }] }), { status: 200 });
  }) as typeof fetch;
  // Use a surface stub whose read paginates with a TINY maxPages so the test is fast and deterministic.
  const { paginate } = await import("../src/sources/cf-config-surfaces.ts");
  const tinyDns: CfConfigSurface = { id: "dns", scope: "zone", restoreTier: "idempotent", read: (api, ids, meter) => paginate(api, `/zones/${ids.zoneId}/dns_records`, meter, 1000, 5 /* maxPages */) };
  const recs = await collect(new CloudflareConfigSource("tok", "a", "z", [tinyDns], endlessFetch).crawl({ include: ["dns"], exclude: [] }));
  const marker = JSON.parse(new TextDecoder().decode(recs.find((r) => r.name === "dns")!.value!)) as { _truncated?: string; _unavailable?: string; pagesRead?: number; recordsRead?: number };
  ok("the guard stopped the loop at the page cap (did NOT spin forever)", calls === 5);
  ok("the surface is marked _truncated (honest), NOT silently complete", typeof marker._truncated === "string" && /truncated/i.test(marker._truncated));
  ok("the truncation marker is NOT an _unavailable marker (we DID read records)", marker._unavailable === undefined);
  ok("the truncation marker reports how much was read", marker.pagesRead === 5 && typeof marker.recordsRead === "number" && marker.recordsRead === 5000);
}

console.log("-- RESUMABLE: crawlFrom marks after each surface and resumes without re-reading --");
{
  const surf = (id: string): CfConfigSurface => ({ id, scope: "account", restoreTier: "idempotent", read: async () => ({ id }) });
  const surfaces = [surf("s1"), surf("s2"), surf("s3")];
  const mk = (): CloudflareConfigSource => new CloudflareConfigSource("tok", "acct", undefined, surfaces, stubFetch([]));
  ok("CloudflareConfigSource is resumable (implements crawlFrom)", isResumable(mk()));

  const evs: CrawlEvent[] = [];
  for await (const ev of mk().crawlFrom(ALL, null)) evs.push(ev);
  const marks = evs.filter((e) => e.kind === "mark") as Array<{ kind: "mark"; token: string }>;
  const names = evs.filter((e) => e.kind === "record").map((e) => (e as { kind: "record"; record: SourceRecord }).record.name);
  // The crawl now leads with the identity record + its own mark, then one record + mark per surface.
  const surfaceNames = names.filter((n) => n !== CF_CONFIG_IDENTITY_ID);
  ok("a mark is emitted after the identity record and after each of the 3 surfaces", marks.length === surfaces.length + 1);
  ok("from scratch yields the identity record first, then all 3 surfaces in order", names[0] === CF_CONFIG_IDENTITY_ID && JSON.stringify(surfaceNames) === JSON.stringify(["s1", "s2", "s3"]));
  const afterS1 = marks.find((m) => (JSON.parse(m.token) as { after: string }).after === "s1")!.token;
  ok("a watermark after s1 is emitted", afterS1 !== undefined);

  const resumed: string[] = [];
  for await (const ev of mk().crawlFrom(ALL, afterS1)) if (ev.kind === "record") resumed.push(ev.record.name);
  ok("resume after s1 yields s2 + s3 only (s1 not re-read, identity not re-emitted)", JSON.stringify(resumed) === JSON.stringify(["s2", "s3"]));
}

console.log("-- RESUMABLE: a stale/unknown resume watermark FAILS LOUD, never an empty crawl --");
{
  const surf = (id: string): CfConfigSurface => ({ id, scope: "account", restoreTier: "idempotent", read: async () => ({ id }) });
  const surfaces = [surf("s1"), surf("s2"), surf("s3")];
  const src = new CloudflareConfigSource("tok", "acct", undefined, surfaces, stubFetch([]));
  // A resume token naming a surface id that is no longer in the registry (removed/renamed surface). An
  // unrecognised watermark must not let the skip-through loop return ZERO records with no signal.
  const staleToken = JSON.stringify({ after: "surface-that-no-longer-exists" });
  let threw = "";
  const yielded: string[] = [];
  try {
    for await (const ev of src.crawlFrom(ALL, staleToken)) if (ev.kind === "record") yielded.push(ev.record.name);
  } catch (e) {
    threw = (e as Error).message;
  }
  ok("a stale watermark throws rather than returning an empty crawl", threw !== "" && yielded.length === 0);
  ok("the thrown error names the unknown watermark and is actionable", /surface-that-no-longer-exists/.test(threw) && /not a known surface id/.test(threw));
}

if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nCLOUDFLARE CONFIG SOURCE VECTORS PASS");
