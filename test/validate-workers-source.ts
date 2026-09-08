// Validates the Workers scripts backup source (src/sources/workers.ts) and its restore honesty
// (src/admin/restore.ts). The Cloudflare API is an in-memory WorkersCfApi double; no network.
// Proves:
//   - the adapter LISTS scripts and emits a CONTENT record (the raw code bytes) + a SETTINGS record
//     + a VERSIONS record per script, name-prefixed by script id;
//   - a SETTINGS record reduces every secret binding (secret_text / secret_key /
//     secrets_store_secret) to a {name,type} reprovision-checklist entry with NO value present
//     anywhere in the record bytes (the no-secret-value guarantee);
//   - the crawl is FAIL-OPEN per script/aspect (an unreadable script becomes an _unavailable marker,
//     never a hard throw) and FAILS LOUDLY when every aspect fails or the list itself fails;
//   - the SELECTOR includes/excludes records by name (content vs "<id>/settings" vs "<id>/versions");
//   - RESTORE treats a workers record as REPROVISION: it is routed out of band with re-deploy
//     guidance, and there is NO write sink for it (resolveSink throws "unsupported sink").
// Run: node test/validate-workers-source.ts.

import { WorkersSource, redactSettings, type WorkersCfApi } from "../src/sources/workers.ts";
import { CfPaginationTruncated, type CfPage } from "../src/sources/cf-config-core.ts";
import { workersRestoreGuidance, resolveSink } from "../src/admin/restore.ts";
import type { Selector, SourceRecord, CrawlEvent } from "../src/sources/types.ts";
import { isResumable } from "../src/sources/types.ts";
import type { ShardRecord } from "../src/format/manifest.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}

const ALL: Selector = { include: [], exclude: [] };
const dec = (v?: Uint8Array): string => new TextDecoder().decode(v ?? new Uint8Array(0));
const parse = (v?: Uint8Array): Record<string, unknown> => JSON.parse(dec(v)) as Record<string, unknown>;

async function collect(it: AsyncIterable<SourceRecord>): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of it) out.push(r);
  return out;
}

// A SECRET VALUE that must NEVER appear in any emitted record. The settings double offers it as the
// (impossible-in-reality, but defensive) "text" of a secret_text binding; the adapter must drop it.
const SECRET_VALUE = "SUPER_SECRET_VALUE_ce9f0a";

// makeApi builds an in-memory WorkersCfApi. scripts lists the ids; content/settings/versions are
// keyed by script id; a per-aspect entry may be an Error to exercise fail-open.
type ApiSpec = {
  scripts: string[] | Error;
  content?: Record<string, Uint8Array | Error>;
  settings?: Record<string, unknown | Error>;
  versions?: Record<string, unknown | Error>;
  schedules?: Record<string, unknown | Error>;
};
function makeApi(spec: ApiSpec, calls?: string[]): WorkersCfApi {
  const idOf = (path: string, suffix: string): string => {
    const m = path.match(new RegExp(`/workers/scripts/([^/]+)/${suffix}$`));
    return m ? decodeURIComponent(m[1]!) : "";
  };
  const settle = <T,>(v: T | Error): Promise<T> => (v instanceof Error ? Promise.reject(v) : Promise.resolve(v));
  const isListPath = (path: string): boolean => /\/workers\/scripts(\?|$)/.test(path);
  const queryNum = (path: string, key: string): number | undefined => {
    const m = path.match(new RegExp(`[?&]${key}=([^&]+)`));
    return m ? Number(decodeURIComponent(m[1]!)) : undefined;
  };
  return {
    get: (path) => {
      calls?.push(`GET ${path}`);
      // The real list endpoint returns objects with an `id`; the double mirrors that shape. The list
      // is now read via getPage (paginate), so get() of the list path remains for completeness.
      if (isListPath(path)) return spec.scripts instanceof Error ? settle(spec.scripts) : settle(spec.scripts.map((id) => ({ id })));
      if (/\/settings$/.test(path)) return settle((spec.settings ?? {})[idOf(path, "settings")] ?? {});
      if (/\/versions$/.test(path)) return settle((spec.versions ?? {})[idOf(path, "versions")] ?? []);
      if (/\/schedules$/.test(path)) return settle((spec.schedules ?? {})[idOf(path, "schedules")] ?? []);
      return Promise.resolve(null);
    },
    // getPage serves the scripts LIST one page at a time so paginate() can follow pages to
    // exhaustion. It honours the ?page=&per_page= the paginator adds and returns a page-based
    // result_info ({page,total_pages}) so the paginator stops at the last page (never truncates,
    // never loops). A scripts-list Error rejects (the under-scoped-token path).
    getPage: (path): Promise<CfPage> => {
      calls?.push(`PAGE ${path}`);
      if (!isListPath(path)) return Promise.resolve({ result: [] });
      if (spec.scripts instanceof Error) return Promise.reject(spec.scripts);
      const perPage = queryNum(path, "per_page") ?? (spec.scripts.length || 1);
      const page = queryNum(path, "page") ?? 1;
      const totalPages = Math.max(1, Math.ceil(spec.scripts.length / perPage));
      const slice = spec.scripts.slice((page - 1) * perPage, page * perPage).map((id) => ({ id }));
      return Promise.resolve({ result: slice, result_info: { page, per_page: perPage, total_pages: totalPages, total_count: spec.scripts.length } });
    },
    getRaw: (path) => {
      calls?.push(`RAW ${path}`);
      const id = idOf(path, "content");
      const c = (spec.content ?? {})[id];
      if (c === undefined) return Promise.resolve({ bytes: new TextEncoder().encode(`export default {} // ${id}`), contentType: "application/javascript" });
      if (c instanceof Error) return Promise.reject(c);
      return Promise.resolve({ bytes: c, contentType: "application/javascript" });
    },
  };
}

console.log("-- lists scripts; emits content + settings + versions per script, name-prefixed --");
{
  const calls: string[] = [];
  let spends = 0;
  const meter = { spend: (n = 1) => { spends += n; } };
  const api = makeApi(
    {
      scripts: ["api-worker", "cron-worker"],
      content: { "api-worker": new TextEncoder().encode("export default { fetch(){} }") },
      settings: {
        "api-worker": { compatibility_date: "2026-01-01", bindings: [{ type: "kv_namespace", name: "CACHE", namespace_id: "abc" }] },
        "cron-worker": { compatibility_date: "2026-02-02", bindings: [] },
      },
      versions: { "api-worker": [{ id: "v1", number: 1, created_on: "2026-01-01T00:00:00Z" }] },
      schedules: { "cron-worker": [{ cron: "0 */6 * * *", created_on: "2026-02-02T00:00:00Z", modified_on: "2026-02-02T00:00:00Z" }] },
    },
    calls,
  );
  const recs = await collect(new WorkersSource("acct123", api).crawl(ALL, meter));
  ok("four records per script (content + settings + versions + schedules)", recs.length === 8);
  ok("a schedules record is named '<id>/schedules'", recs.some((r) => r.name === "cron-worker/schedules"));
  const sched = parse(recs.find((r) => r.name === "cron-worker/schedules")!.value);
  ok("schedules record captures the cron trigger verbatim (data-loss gap closed)", Array.isArray(sched.schedules) && (sched.schedules as Array<{ cron?: string }>)[0]?.cron === "0 */6 * * *");
  ok("the schedules endpoint was read", calls.some((c) => /\/schedules$/.test(c)));
  ok("every record is sourceType workers with buffered bytes", recs.every((r) => r.sourceType === "workers" && r.value instanceof Uint8Array && r.value.length > 0));
  ok("no record streams (all buffered)", recs.every((r) => r.stream === undefined));
  ok("a content record is named exactly the script id", recs.some((r) => r.name === "api-worker") && recs.some((r) => r.name === "cron-worker"));
  ok("a settings record is named '<id>/settings'", recs.some((r) => r.name === "api-worker/settings"));
  ok("a versions record is named '<id>/versions'", recs.some((r) => r.name === "api-worker/versions"));
  ok("content record carries the raw code bytes verbatim", dec(recs.find((r) => r.name === "api-worker")!.value) === "export default { fetch(){} }");
  ok("every API call was metered (>= one spend per record)", spends >= recs.length);
  ok("the list endpoint was paged", calls.some((c) => c.startsWith("PAGE ") && /\/workers\/scripts(\?|$)/.test(c)));
  ok("the content endpoint was read via getRaw (not get)", calls.some((c) => c.startsWith("RAW ") && /\/content$/.test(c)));
  const versions = parse(recs.find((r) => r.name === "api-worker/versions")!.value);
  ok("versions record is an inventory of {id,number,created_on}", Array.isArray(versions.versions) && (versions.versions as unknown[]).length === 1);
}

console.log("-- SETTINGS reduce secret bindings to a name/type checklist with NO value --");
{
  const api = makeApi({
    scripts: ["secretful"],
    settings: {
      secretful: {
        compatibility_date: "2026-03-03",
        bindings: [
          { type: "kv_namespace", name: "CACHE", namespace_id: "ns1" },
          { type: "secret_text", name: "API_KEY", text: SECRET_VALUE },
          { type: "secret_key", name: "SIGNING_KEY", key_base64: SECRET_VALUE },
          { type: "secrets_store_secret", name: "DB_PASSWORD", store_id: "store1", secret_name: "db" },
          { type: "plain_text", name: "PUBLIC_FLAG", text: "not-a-secret" },
        ],
      },
    },
  });
  const recs = await collect(new WorkersSource("acct123", api).crawl({ include: ["secretful/settings"], exclude: [] }));
  ok("only the settings record is in scope", recs.length === 1 && recs[0]!.name === "secretful/settings");
  const body = dec(recs[0]!.value);
  const v = JSON.parse(body) as { bindings: Array<Record<string, unknown>>; reprovisionChecklist: Array<{ name: string; type: string }> };
  // THE CENTRAL GUARANTEE: the secret value never appears anywhere in the serialised record bytes.
  ok("NO secret VALUE appears anywhere in the settings record bytes", !body.includes(SECRET_VALUE));
  ok("the reprovision checklist lists the 3 secret bindings by name + type", v.reprovisionChecklist.length === 3
    && v.reprovisionChecklist.some((c) => c.name === "API_KEY" && c.type === "secret_text")
    && v.reprovisionChecklist.some((c) => c.name === "SIGNING_KEY" && c.type === "secret_key")
    && v.reprovisionChecklist.some((c) => c.name === "DB_PASSWORD" && c.type === "secrets_store_secret"));
  ok("a checklist entry carries ONLY name + type (no other field, e.g. no store_id/text/key)", v.reprovisionChecklist.every((c) => Object.keys(c).sort().join(",") === "name,type"));
  ok("secret bindings are REMOVED from the kept bindings list", !v.bindings.some((b) => ["secret_text", "secret_key", "secrets_store_secret"].includes(String(b.type))));
  ok("non-secret bindings (kv_namespace, plain_text) are kept verbatim", v.bindings.some((b) => b.type === "kv_namespace" && b.name === "CACHE") && v.bindings.some((b) => b.type === "plain_text" && b.name === "PUBLIC_FLAG"));
  ok("the non-secret compatibility_date is preserved", (JSON.parse(body) as { compatibility_date?: string }).compatibility_date === "2026-03-03");
}

console.log("-- redactSettings is total + value-free over odd shapes (degrades, never throws) --");
{
  // No bindings array, a non-object binding, a secret binding missing its name: must not throw and
  // must never carry a value.
  const r1 = redactSettings({ compatibility_date: "x" });
  ok("missing bindings -> empty bindings + empty checklist", Array.isArray(r1.bindings) && r1.bindings.length === 0 && r1.reprovisionChecklist.length === 0);
  const r2 = redactSettings({ bindings: ["weird", 42, null, { type: "secret_text", name: "" }] });
  ok("an unnamed secret binding still goes to the checklist (name '')", r2.reprovisionChecklist.length === 1 && r2.reprovisionChecklist[0]!.type === "secret_text");
  ok("odd non-object binding entries are kept verbatim, not crashed", r2.bindings.includes("weird") && r2.bindings.includes(42 as unknown as never));
  ok("redactSettings(non-object) is the empty value-free shape", JSON.stringify(redactSettings(null)) === JSON.stringify({ bindings: [], reprovisionChecklist: [] }));
}

console.log("-- fail-open: an unreadable script/aspect becomes a marker, others still yield --");
{
  const api = makeApi({
    scripts: ["good", "bad"],
    content: { good: new TextEncoder().encode("ok"), bad: new Error("Cloudflare API GET /accounts/a/workers/scripts/bad/content: Authentication error") },
    settings: { good: { bindings: [] }, bad: new Error("Cloudflare API GET /accounts/a/workers/scripts/bad/settings: Authentication error") },
    versions: { good: [], bad: [] },
  });
  const recs = await collect(new WorkersSource("acct123", api).crawl(ALL));
  ok("no record is dropped (both scripts, all aspects yield)", recs.length === 8);
  const badContent = parse(recs.find((r) => r.name === "bad")!.value);
  ok("the unreadable content is an _unavailable marker, not a throw", typeof badContent._unavailable === "string" && /Authentication error/.test(badContent._unavailable as string));
  const badSettings = parse(recs.find((r) => r.name === "bad/settings")!.value);
  ok("the unreadable settings is an _unavailable marker", typeof badSettings._unavailable === "string");
  // A real content record holds RAW code bytes (not JSON), so it must NOT be an _unavailable marker.
  const goodContent = dec(recs.find((r) => r.name === "good")!.value);
  ok("the good content is a real record (raw code, no _unavailable marker)", goodContent === "ok" && !goodContent.includes("_unavailable"));
}

console.log("-- schedules failing ALONE is fail-open (a marker), the data aspects still yield real --");
{
  // Isolates the schedules aspect's fail-open (the shipped fail-open test never set schedules, so it
  // defaulted to a trivial empty success and never exercised this path).
  const api = makeApi({
    scripts: ["cron-w"],
    content: { "cron-w": new TextEncoder().encode("code") },
    settings: { "cron-w": { bindings: [] } },
    versions: { "cron-w": [] },
    schedules: { "cron-w": new Error("Cloudflare API GET /accounts/a/workers/scripts/cron-w/schedules: 500 upstream") },
  });
  const recs = await collect(new WorkersSource("acct123", api).crawl(ALL));
  const sched = parse(recs.find((r) => r.name === "cron-w/schedules")!.value);
  ok("a failed schedules read is an _unavailable marker, not a throw", typeof sched._unavailable === "string" && /500 upstream/.test(sched._unavailable as string));
  ok("the crawl still completes with the data aspects real (content is raw bytes)", dec(recs.find((r) => r.name === "cron-w")!.value) === "code" && recs.find((r) => r.name === "cron-w/settings") !== undefined);
}

console.log("-- a malformed schedule entry (non-string cron) is dropped, real crons kept --");
{
  const api = makeApi({
    scripts: ["mix-w"],
    content: { "mix-w": new TextEncoder().encode("c") },
    settings: { "mix-w": { bindings: [] } },
    schedules: { "mix-w": [{ cron: "0 * * * *", created_on: "2026-01-01T00:00:00Z" }, { cron: 12345 }, { created_on: "no-cron" }] },
  });
  const recs = await collect(new WorkersSource("acct123", api).crawl(ALL));
  const sched = parse(recs.find((r) => r.name === "mix-w/schedules")!.value);
  const crons = sched.schedules as Array<{ cron?: unknown }>;
  ok("only the well-formed cron entry survives (malformed ones dropped, never captured as junk)", Array.isArray(crons) && crons.length === 1 && crons[0]!.cron === "0 * * * *");
}

console.log("-- a script whose content exceeds the size cap is marked, never OOM --");
{
  const api = makeApi({ scripts: ["huge"], content: { huge: new TextEncoder().encode("x".repeat(500)) }, settings: { huge: { bindings: [] } } });
  const recs = await collect(new WorkersSource("acct123", api, 50 /* tiny limit */).crawl(ALL));
  const huge = parse(recs.find((r) => r.name === "huge")!.value);
  ok("an oversized script content is marked unavailable, not fatal", typeof huge._unavailable === "string" && /exceeds the 50-byte limit/.test(huge._unavailable as string));
  ok("the under-limit settings record still yields real", parse(recs.find((r) => r.name === "huge/settings")!.value)._unavailable === undefined);
}

console.log("-- EVERY aspect failing throws loudly (a broken token, not a per-script gap) --");
{
  const api = makeApi({
    scripts: ["a", "b"],
    content: { a: new Error("status 403"), b: new Error("status 403") },
    settings: { a: new Error("status 403"), b: new Error("status 403") },
    versions: { a: new Error("status 403"), b: new Error("status 403") },
    schedules: { a: new Error("status 403"), b: new Error("status 403") },
  });
  let threw = "";
  try { await collect(new WorkersSource("acct123", api).crawl(ALL)); } catch (e) { threw = (e as Error).message; }
  ok("all aspects failing throws (never a silent all-unavailable success)", /every Workers script aspect failed/.test(threw));
}

console.log("-- the LIST itself failing throws loudly (under-scoped token) --");
{
  const api = makeApi({ scripts: new Error("Cloudflare API GET /accounts/a/workers/scripts: Authentication error") });
  let threw = "";
  try { await collect(new WorkersSource("acct123", api).crawl(ALL)); } catch (e) { threw = (e as Error).message; }
  ok("a failed scripts list throws with a Workers-scope hint", /Workers scripts list failed/.test(threw) && /Workers Scripts/.test(threw));
}

console.log("-- selector includes/excludes records by name --");
{
  const src = () => new WorkersSource("acct123", makeApi({ scripts: ["w1", "w2"], content: { w1: new TextEncoder().encode("a"), w2: new TextEncoder().encode("b") }, settings: { w1: { bindings: [] }, w2: { bindings: [] } } }));
  // The selector is a PREFIX match (the SPEC 12.2 / KV semantics): include a script id -> ALL of
  // that script's records (content + settings + versions), and exclude the other script entirely.
  const picked = await collect(src().crawl({ include: ["w1"], exclude: [] }));
  ok("a prefix include pulls all of a script's records (content+settings+versions+schedules)", picked.length === 4 && picked.every((r) => r.name === "w1" || r.name.startsWith("w1/")));
  ok("a non-included script is excluded entirely", !picked.some((r) => r.name.startsWith("w2")));
  // include a specific suffix -> only that record (no other w1 record starts with "w1/settings").
  const settingsOnly = await collect(src().crawl({ include: ["w1/settings", "w2/settings"], exclude: [] }));
  ok("including '<id>/settings' selects exactly the settings records", settingsOnly.length === 2 && settingsOnly.every((r) => r.name.endsWith("/settings")));
  // exclude drops the versions records across the board (exclude wins over an empty include=all).
  const noVersions = await collect(src().crawl({ include: [], exclude: ["w1/versions", "w2/versions"] }));
  ok("exclude drops the named records, keeps the rest", !noVersions.some((r) => r.name.endsWith("/versions")) && noVersions.length === 6);
}

console.log("-- estimate counts in-scope records, reads no content --");
{
  const calls: string[] = [];
  const api = makeApi({ scripts: ["w1", "w2"] }, calls);
  const est = await new WorkersSource("acct123", api).estimate(ALL);
  ok("estimate.records is 4 per script (content+settings+versions+schedules)", est.records === 8);
  ok("estimate.bytes is -1 (never sized by reading)", est.bytes === -1);
  ok("estimate read NO content (no RAW calls)", !calls.some((c) => c.startsWith("RAW ")));
  // a failed list degrades estimate to zero records, never throws.
  const est2 = await new WorkersSource("acct123", makeApi({ scripts: new Error("status 403") })).estimate(ALL);
  ok("estimate of an unreadable account is zero records, not a throw", est2.records === 0);
}

console.log("-- RESTORE treats workers records as REPROVISION (out of band, no write) --");
{
  // The guidance is reprovision-only re-deploy text, differentiated per record kind, and the
  // settings guidance explicitly states secret VALUES were never captured.
  const contentG = workersRestoreGuidance("my-worker");
  const settingsG = workersRestoreGuidance("my-worker/settings");
  const versionsG = workersRestoreGuidance("my-worker/versions");
  const schedulesG = workersRestoreGuidance("my-worker/schedules");
  ok("content guidance says re-deploy the code from the snapshot", /Workers script/.test(contentG) && /re-deploy the script code/.test(contentG));
  ok("settings guidance says secret VALUES were never captured (reprovision)", /secret VALUES were never captured/.test(settingsG) && /re-provision/.test(settingsG));
  ok("versions guidance is informational only", /inventory only/.test(versionsG));
  ok("schedules guidance says re-create the cron triggers from the snapshot", /cron triggers/.test(schedulesG) && /schedule/.test(schedulesG));
  ok("no guidance ever implies a blind/auto re-deploy", ![contentG, settingsG, versionsG, schedulesG].some((g) => /automatically|blind|will re-?deploy for you/i.test(g)));

  // There is NO write sink for a workers record: resolveSink throws "unsupported sink for sourceType".
  const rec = (name: string): ShardRecord => ({
    kind: "record", sourceType: "workers", name, keyNameHash: "h", recordId: "r", plaintextSize: 1,
    plaintextSha384: "s", recordHash: "rh", codec: "none", segments: [],
  });
  for (const name of ["my-worker", "my-worker/settings", "my-worker/versions"]) {
    let threw = "";
    try { resolveSink({} as never, rec(name), undefined, false); } catch (e) { threw = (e as Error).message; }
    ok(`resolveSink has NO write path for a workers record (${name})`, /unsupported sink for sourceType/.test(threw));
  }
}

console.log("-- RESUMABLE: crawlFrom marks after each script and resumes without re-reading --");
{
  const mk = (): WorkersSource =>
    new WorkersSource("acct123", makeApi({
      scripts: ["a", "b", "c"],
      content: { a: new TextEncoder().encode("A"), b: new TextEncoder().encode("B"), c: new TextEncoder().encode("C") },
      settings: { a: { bindings: [] }, b: { bindings: [] }, c: { bindings: [] } },
    }));
  ok("WorkersSource is resumable (implements crawlFrom)", isResumable(mk()));

  const evs: CrawlEvent[] = [];
  for await (const ev of mk().crawlFrom(ALL, null)) evs.push(ev);
  const marks = evs.filter((e) => e.kind === "mark") as Array<{ kind: "mark"; token: string }>;
  const names = evs.filter((e) => e.kind === "record").map((e) => (e as { kind: "record"; record: SourceRecord }).record.name);
  ok("a mark is emitted after each of the 3 scripts", marks.length === 3);
  ok("from scratch yields every script's content record", ["a", "b", "c"].every((n) => names.includes(n)));
  const afterA = marks[0]!.token;
  ok("the first mark is the watermark after script 'a'", (JSON.parse(afterA) as { after: string }).after === "a");

  const resumed: string[] = [];
  for await (const ev of mk().crawlFrom(ALL, afterA)) if (ev.kind === "record") resumed.push(ev.record.name);
  ok("resume after 'a' skips 'a' (never re-read) and yields b + c", resumed.includes("b") && resumed.includes("c") && !resumed.some((n) => n === "a" || n.startsWith("a/")));
}

console.log("-- PAGINATION: the scripts list is paged to exhaustion (no tail dropped) --");
{
  // More scripts than fit on one page: with a small per_page, the list spans several pages. EVERY
  // script across ALL pages must yield its content record (the old single-GET dropped pages 2+).
  // To force multiple pages we shrink the page size via the WorkersSource path: the source passes
  // WORKERS_LIST_PER_PAGE to paginate, which is large, so instead we rely on the double honouring
  // the paginator's per_page. We assert the paginator's own bound by counting list PAGE calls.
  const ids = Array.from({ length: 25 }, (_, i) => `w${String(i).padStart(2, "0")}`); // sorted-stable
  const content: Record<string, Uint8Array> = {};
  const settings: Record<string, unknown> = {};
  for (const id of ids) {
    content[id] = new TextEncoder().encode(`code-${id}`);
    settings[id] = { bindings: [] };
  }
  // makeApi's getPage honours the per_page the paginator adds; the production source passes a large
  // WORKERS_LIST_PER_PAGE, so to actually exercise MULTI-PAGE we wrap getPage to cap per_page small.
  const calls: string[] = [];
  const base = makeApi({ scripts: ids, content, settings }, calls);
  const PER = 10; // force 3 pages over 25 scripts
  const paged: WorkersCfApi = {
    get: base.get,
    getRaw: base.getRaw,
    getPage: (path) => {
      // Override the per_page the paginator chose with our small PER so the double slices into pages.
      const forced = path.replace(/([?&]per_page=)\d+/, `$1${PER}`);
      return base.getPage(forced);
    },
  };
  const recs = await collect(new WorkersSource("acct123", paged).crawl(ALL));
  const contentNames = recs.filter((r) => !r.name.includes("/")).map((r) => r.name);
  ok("every script id across ALL pages yields a content record", ids.every((id) => contentNames.includes(id)));
  ok("the content record count equals the FULL script set (no page dropped)", contentNames.length === ids.length);
  ok("each content record carries that script's bytes (right page mapped to right id)",
    ids.every((id) => dec(recs.find((r) => r.name === id)!.value) === `code-${id}`));
  const pageCalls = calls.filter((c) => c.startsWith("PAGE "));
  ok("the list was paged in multiple calls (3 pages over 25 scripts at per_page 10)", pageCalls.length === 3);
  // Each page is requested exactly once (page=1,2,3), never re-listed per script.
  ok("each list page is requested exactly once", new Set(pageCalls).size === pageCalls.length);
}

console.log("-- PAGINATION + RESUME: resume re-lists every page then skips already-yielded ids --");
{
  const ids = Array.from({ length: 25 }, (_, i) => `w${String(i).padStart(2, "0")}`);
  const content: Record<string, Uint8Array> = {};
  const settings: Record<string, unknown> = {};
  for (const id of ids) { content[id] = new TextEncoder().encode(id); settings[id] = { bindings: [] }; }
  const PER = 10;
  const mk = (): WorkersSource => {
    const base = makeApi({ scripts: ids, content, settings });
    const paged: WorkersCfApi = {
      get: base.get,
      getRaw: base.getRaw,
      getPage: (path) => base.getPage(path.replace(/([?&]per_page=)\d+/, `$1${PER}`)),
    };
    return new WorkersSource("acct123", paged);
  };
  // Resume from the watermark of the 12th script (an id on page 2): every id after it (across the
  // remaining pages) must still yield, and no id at or before it is re-read.
  const watermark = ids[11]!; // "w11"
  const resumed: string[] = [];
  for await (const ev of mk().crawlFrom(ALL, JSON.stringify({ after: watermark })))
    if (ev.kind === "record") resumed.push(ev.record.name);
  const resumedContent = resumed.filter((n) => !n.includes("/"));
  ok("resume yields exactly the ids after the watermark across all pages", resumedContent.join(",") === ids.slice(12).join(","));
  ok("resume re-lists (pages) but re-reads no already-yielded script", !resumedContent.some((n) => n <= watermark));
}

console.log("-- PAGINATION CAP: a list exceeding the page cap throws CfPaginationTruncated, not a silent partial --");
{
  // A double whose getPage NEVER reports the last page (always says there is one more) forces the
  // paginator to its page cap. The crawl must throw CfPaginationTruncated, NOT silently return the
  // pages read so far, and the wrapper must NOT rewrap it as a token-scope error.
  const calls: string[] = [];
  const CAP = 5; // exercise a tiny cap; the source uses CF_PAGINATION_MAX_PAGES in production.
  const endless: WorkersCfApi = {
    get: (path) => { calls?.push(`GET ${path}`); return Promise.resolve(null); },
    getRaw: () => Promise.resolve({ bytes: new TextEncoder().encode("x"), contentType: "application/javascript" }),
    // Always return a full page AND always claim more pages remain (total_pages far above the cap).
    getPage: (path) => {
      calls.push(`PAGE ${path}`);
      const m = path.match(/[?&]page=(\d+)/);
      const page = m ? Number(m[1]) : 1;
      return Promise.resolve({ result: [{ id: `s${page}` }], result_info: { page, per_page: 1, total_pages: 9999 } });
    },
  };
  // Reach into the source's paginate via a tiny cap: we can't pass maxPages through crawl, so we
  // assert the wiring by checking that the PRODUCTION cap behaviour is the paginate() contract using
  // a direct paginate call mirroring listScripts, then that crawlFrom surfaces it unwrapped.
  let threw: unknown;
  try {
    // Drive the same paginate() the source uses, with a tiny cap, to prove the loud-throw contract.
    const { paginate } = await import("../src/sources/cf-config-core.ts");
    const cfApi = { get: endless.get, getPage: endless.getPage, send: () => Promise.reject(new Error("ro")) };
    await paginate(cfApi, "/accounts/a/workers/scripts", undefined, 1, CAP);
  } catch (e) { threw = e; }
  ok("paginate over an endless list throws CfPaginationTruncated (never a silent partial)", threw instanceof CfPaginationTruncated);
  ok("the truncation reports the pages read at the cap", threw instanceof CfPaginationTruncated && threw.pagesRead === CAP);

  // And the source's crawlFrom must surface a CfPaginationTruncated UNWRAPPED (never rewritten as a
  // token-scope hint), so a truncation is always loud and visible, never a silent partial snapshot.
  // The double's getPage rejects with the truncation error paginate would raise; crawlFrom's catch
  // must re-throw it as-is rather than rewrap it as "the token likely lacks scope".
  const truncating: WorkersCfApi = {
    get: () => Promise.resolve(null),
    getRaw: () => Promise.resolve({ bytes: new TextEncoder().encode("x"), contentType: "application/javascript" }),
    getPage: () => Promise.reject(new CfPaginationTruncated(5, 5)),
  };
  let crawlThrew: unknown;
  try {
    for await (const _ev of new WorkersSource("acct123", truncating).crawlFrom(ALL, null)) void _ev;
  } catch (e) { crawlThrew = e; }
  ok("crawlFrom surfaces CfPaginationTruncated UNWRAPPED (not rewritten as a scope hint)", crawlThrew instanceof CfPaginationTruncated);
  ok("a truncation is NOT silently swallowed into a partial snapshot", !(crawlThrew instanceof Error && /Workers scripts list failed/.test(crawlThrew.message)));
  ok("pagination stopped at the cap (CAP page reads)", calls.filter((c) => c.startsWith("PAGE ")).length === CAP);
}

if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.error(`\n${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("\nWORKERS SOURCE VECTORS PASS");
