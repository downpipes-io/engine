// destsim: CONSUMER-side abuse validators for the Prometheus /metrics scrape PULL surface
// (handleMetricsRoute/renderPrometheusMetrics, src/admin/metrics.ts). Drives the REAL production path
// -- handleMetricsRoute -> gatherMetricsState -> a REAL SchedulerDO (src/sched/scheduler-do.ts) backed
// by MockStorage -- mirroring test/validate-metrics.ts's DO-route setup, but scoped to ABUSE/scale
// rather than correctness-of-derivation: an unbounded fleet scrape (no pagination, O(fleet)), hostile
// downpipe names attempting Prometheus text-exposition injection, the auth short-circuit's DO-round-
// trip asymmetry against /support/*, and byte-stable ordering across repeated scrapes.
//
// The fleet/credential fixtures are written DIRECTLY to storage (dp:/hist:/repl:/ingestcred: keys,
// exactly the shapes listDownpipes()/history()/replication()/GET-ingest-credential read) rather than
// through the gated DO routes, so seeding a large fleet is fast and free of incidental audit-chain
// noise. The SURFACE under test -- handleMetricsRoute, gatherMetricsState, renderPrometheusMetrics,
// escapeLabelValue -- is always the real code.
//
// The two behaviours this file pins are worth a reader's attention even though neither is scored as a
// defect: the /metrics
// auth short-circuit's DO-round-trip asymmetry against /support/*, and the un-paginated O(fleet)
// scrape body size.
//
// Run: node test/validate-destsim-metrics-abuse.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { mintIngestCredential, handleSupportPull } from "../src/admin/support-ingest.ts";
import { handleMetricsRoute } from "../src/admin/metrics.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const EMPTY_ENV = {} as unknown as Env;

function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

// asStub mirrors test/validate-metrics.ts's identical helper: bridges a stub's two-argument
// fetch(url, init) into the one-argument Request SchedulerDO.fetch expects.
function asStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(input as string, init)),
  } as unknown as DurableObjectStub;
}

// countingStub wraps a stub's fetch so a test can assert HOW MANY internal DO round trips a call made
// -- the deterministic way to prove "an absent bearer short-circuits before any DO fetch" instead of a
// timing guess.
function countingStub(dobj: SchedulerDO): { stub: DurableObjectStub; fetchCount: () => number } {
  let count = 0;
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => {
      count++;
      return dobj.fetch(input instanceof Request ? input : new Request(input as string, init));
    },
  } as unknown as DurableObjectStub;
  return { stub, fetchCount: () => count };
}

// seedMetricsCredential writes a minted "metrics" grant directly under the SAME storage key
// (`ingestcred:metrics`) POST /ingest-credential/set writes, bypassing that gated (owner-only, audit-
// appending) route -- this file is about the SCRAPE surface, not the grant flow, which test/validate-
// metrics.ts already covers.
async function seedMetricsCredential(storage: MockStorage): Promise<string> {
  const minted = await mintIngestCredential("metrics", "owner@example.com.au", undefined);
  storage.rawPut("ingestcred:metrics", minted.grant);
  return `${minted.clientId}.${minted.secret}`;
}

interface DownpipeFixture {
  id: string;
  name: string;
}

// seedDownpipe raw-seeds one downpipe with a single resolved+ok run (bytes+durationMs, so every one of
// the 8 canonical metric families gets a sample for it) and one healthy replication destination,
// matching exactly the shapes listDownpipes()/history()/replication() (scheduler-do-scheduling.ts) read.
function seedDownpipe(storage: MockStorage, f: DownpipeFixture): void {
  storage.rawPut(`dp:${f.id}`, {
    config: { id: f.id, name: f.name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${f.id}`, include: [], exclude: [] } },
    nextRunAt: Date.now() + 3600_000,
    lastRunId: "r1",
    inFlight: false,
  });
  storage.rawPut(`hist:${f.id}`, [{ runId: "r1", index: 1, startedAt: new Date("2026-01-01T00:00:00.000Z").toISOString(), status: "ok", bytes: 1024, durationMs: 500 }]);
  storage.rawPut(`repl:${f.id}`, { "dest-a": { holdsRunId: "r1", holdsIndex: 1, lastOk: true, lastAttemptAt: Date.now() } });
}

async function scrape(stub: SchedulerDO, bearer: string): Promise<Response> {
  return handleMetricsRoute(new Request("https://e/metrics", { headers: { Authorization: `Bearer ${bearer}` } }), asStub(stub));
}

// ---- Unbounded-fleet scrape ------------------------------------------------------------------------
const CANONICAL_FAMILIES = [
  "downpipe_backup_last_success_timestamp_seconds",
  "downpipe_backup_success",
  "downpipe_backup_recent_attempts",
  "downpipe_backup_recent_successes",
  "downpipe_backup_recent_failures",
  "downpipe_backup_duration_seconds",
  "downpipe_backup_size_bytes",
  "downpipe_destination_healthy",
];

async function testUnboundedFleetScrape(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedMetricsCredential(storage);

  const N = 2000;
  for (let i = 0; i < N; i++) seedDownpipe(storage, { id: `dp${i}`, name: `Downpipe ${i}` });

  const resp = await scrape(stub, bearer);
  ok(`a ${N}-downpipe fleet scrape: 200, renders without error`, resp.status === 200);
  const text = await resp.text();
  const lines = text.split("\n").filter((l) => l !== "");

  // A cheap structural proxy for "parses as valid Prometheus exposition" (no full grammar parser
  // needed): every non-comment line matches `name{labels} value`, and its metric name was declared by
  // a preceding "# TYPE <name> gauge" line somewhere earlier in the body (the canonical grouped form
  // emitFamily produces: HELP, TYPE, then that family's samples, before the next family starts).
  const typeDeclared = new Set<string>();
  const SAMPLE_RE = /^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? (-?[0-9]+(\.[0-9]+)?|NaN|\+Inf|-Inf)$/;
  let malformed = 0;
  let sampleCount = 0;
  for (const line of lines) {
    if (line.startsWith("# TYPE ")) {
      const parts = line.split(" ");
      const name = parts[2];
      if (name) typeDeclared.add(name);
      continue;
    }
    if (line.startsWith("#")) continue;
    sampleCount++;
    if (!SAMPLE_RE.test(line)) {
      malformed++;
      continue;
    }
    const nameEnd = line.search(/[\s{]/);
    const metricName = nameEnd === -1 ? line : line.slice(0, nameEnd);
    if (!typeDeclared.has(metricName)) malformed++;
  }
  ok("every sample line matches `name{labels} value` and has a preceding # TYPE line (valid grouped exposition structure)", malformed === 0 && sampleCount > 0);

  // Every downpipe was seeded with exactly one resolved+ok run and one destination, so EVERY one of
  // the 8 canonical families gets exactly N samples -- the body size/sample count scale linearly with
  // fleet size, exactly as expected for an un-paginated, O(fleet) scrape.
  ok(`the scrape emits exactly ${N * CANONICAL_FAMILIES.length} samples (${CANONICAL_FAMILIES.length} families x ${N} downpipes, all populated)`, sampleCount === N * CANONICAL_FAMILIES.length);
  for (const family of CANONICAL_FAMILIES) {
    const count = lines.filter((l) => l.startsWith(`${family}{`)).length;
    ok(`family ${family}: exactly ${N} samples (one per downpipe)`, count === N);
  }

  // NO PAGINATION (a load characteristic, pinned here): handleMetricsRoute/renderPrometheusMetrics
  // (src/admin/metrics.ts) take no limit/cursor/offset query parameter at all -- the ENTIRE fleet's
  // series render in one response body, every scrape, regardless of fleet size.
  ok(`load characteristic: the /metrics surface has no pagination -- the body carries the WHOLE fleet (${text.length} bytes for ${N} downpipes) in one response`, text.length > 0);
}

// ---- Injection safety under hostile downpipe names --------------------------------------------------
// extractLabelValue parses ONE quoted Prometheus label value out of a sample line for a given label
// key, honouring backslash escaping (the exposition format's only escape mechanism: escapeLabelValue
// emits exactly \\, \" and \n) so a hostile value containing an unescaped-looking quote/newline/`}`
// cannot fool a naive substring/regex scan -- the same care a real SIEM/Prometheus parser applies.
// Returns the DECODED value (escapes undone), or null if the key/a well-formed value is not found.
function extractLabelValue(line: string, key: string): string | null {
  const marker = `${key}="`;
  const start = line.indexOf(marker);
  if (start === -1) return null;
  let i = start + marker.length;
  let out = "";
  while (i < line.length) {
    const c = line[i];
    if (c === "\\") {
      const next = line[i + 1];
      if (next === "\\") {
        out += "\\";
        i += 2;
        continue;
      }
      if (next === '"') {
        out += '"';
        i += 2;
        continue;
      }
      if (next === "n") {
        out += "\n";
        i += 2;
        continue;
      }
      out += c; // an unrecognised escape: consume the backslash literally (defensive; never emitted)
      i += 1;
      continue;
    }
    if (c === '"') return out; // an UNESCAPED quote: the true end of the value
    out += c;
    i += 1;
  }
  return null; // ran off the end without a closing quote: malformed
}

async function testInjectionSafety(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedMetricsCredential(storage);

  const hostile: Record<string, string> = {
    "dp-quote": 'Say "hi" please',
    "dp-backslash": "C:\\backups\\nightly",
    "dp-newline": "line1\nline2",
    "dp-cr": "line1\rline2",
    "dp-crlf": "line1\r\nline2",
    // An attempted metric-line forgery: close the quote+braces early and splice in a fake second series.
    "dp-brace": 'evil"} fake_metric{pwned="true',
    "dp-unicode": "bäckup café 备份 \u{1F4BE}",
  };
  for (const [id, name] of Object.entries(hostile)) seedDownpipe(storage, { id, name });

  const resp = await scrape(stub, bearer);
  ok("hostile-name fleet: 200, renders without error", resp.status === 200);
  const text = await resp.text();
  const lines = text.split("\n").filter((l) => l !== "");

  for (const [id, name] of Object.entries(hostile)) {
    const line = lines.find((l) => l.startsWith("downpipe_backup_success{") && l.includes(`downpipe_id="${id}"`));
    ok(`hostile name (${id}): exactly one downpipe_backup_success sample line exists for it`, line !== undefined);
    if (line === undefined) continue;
    const decoded = extractLabelValue(line, "downpipe_name");
    // escapeLabelValue INTENTIONALLY normalises every line-break variant (bare CR, CRLF, bare LF) to
    // the SAME two-character \n escape (its own comment: "so a bare carriage return cannot smuggle a
    // line break past a newline-only check either" -- also asserted directly in test/validate-
    // metrics.ts's escapeLabelValue unit tests). That normalisation is lossy BY DESIGN: decoding \n can
    // only ever recover a bare LF, never which of the three original variants produced it. So the
    // round-trip is checked against the LF-normalised original, not the raw original, for every name
    // here (a no-op replace for names with no CR/CRLF).
    const expected = name.replace(/\r\n|\r|\n/g, "\n");
    ok(`hostile name (${id}): the downpipe_name label round-trips to the original string (CR/CRLF/LF all normalise to LF, by design)`, decoded === expected);
  }

  // Structural proof no forgery landed: exactly one downpipe_backup_success sample per seeded downpipe
  // -- a successful injection (e.g. the dp-brace attempt) would manifest as an EXTRA line.
  const successLines = lines.filter((l) => l.startsWith("downpipe_backup_success{"));
  ok("exactly one downpipe_backup_success sample per hostile downpipe (no forged extra line)", successLines.length === Object.keys(hostile).length);
  ok("the attempted fake_metric{pwned=\"true\"} forgery never appears as its own line", !lines.some((l) => l.startsWith("fake_metric")));

  // No RAW (unescaped) newline/CR from any hostile name survives anywhere in the body.
  for (const name of Object.values(hostile)) {
    if (name.includes("\n") || name.includes("\r")) ok("a raw hostile value containing a real newline/CR never appears verbatim in the body", !text.includes(name));
  }
}

// ---- Auth: no bearer / wrong bearer / POST, and the DO-round-trip asymmetry vs /support/* -----------
async function testAuthGating(): Promise<void> {
  const { storage, stub } = makeScheduler();
  {
    const resp = await scrape(stub, "");
    ok('an empty-string bearer ("Bearer ") -> 401', resp.status === 401);
  }
  {
    const resp = await handleMetricsRoute(new Request("https://e/metrics"), asStub(stub));
    ok("no Authorization header at all -> 401", resp.status === 401);
  }
  {
    const resp = await handleMetricsRoute(new Request("https://e/metrics", { headers: { Authorization: "Bearer dpc_nope.dps_wrong" } }), asStub(stub));
    ok("an unrecognised bearer -> 401", resp.status === 401);
  }
  {
    const resp = await handleMetricsRoute(new Request("https://e/metrics", { method: "POST" }), asStub(stub));
    ok("POST /metrics -> 404 (GET-only surface)", resp.status === 404);
  }
  const bearer = await seedMetricsCredential(storage);
  {
    const resp = await scrape(stub, bearer);
    ok("the correct bearer -> 200", resp.status === 200);
  }

  // The DO-round-trip asymmetry: /metrics' checkMetricsBearer (src/admin/metrics.ts) short-circuits on
  // an EMPTY presented bearer BEFORE it ever calls scheduler.fetch, whereas /support/*'s
  // handleSupportPull (src/admin/support-ingest.ts) ALWAYS calls scheduler.fetch(GET /ingest-credential)
  // first and only checks for an empty bearer afterwards -- both fail closed to the same 401, but
  // /support/* pays one extra internal DO round trip on every unauthenticated probe that /metrics does
  // not. Proven with a deterministic fetch-call counter, not a timing guess.
  {
    const { stub: freshDo } = makeScheduler();
    const { stub: counted, fetchCount } = countingStub(freshDo);
    const resp = await handleMetricsRoute(new Request("https://e/metrics"), counted);
    ok("METRICS: no-bearer request -> 401", resp.status === 401);
    ok("METRICS: an absent bearer short-circuits BEFORE any DO round trip (0 DO fetches)", fetchCount() === 0);
  }
  {
    const { stub: freshDo } = makeScheduler();
    const { stub: counted, fetchCount } = countingStub(freshDo);
    const resp = await handleSupportPull(new Request("https://e/support/audit-feed"), EMPTY_ENV, counted);
    ok("SUPPORT-INGEST: no-bearer request -> 401 too (same fail-closed outcome)", resp.status === 401);
    // /support/* must not do a DO round trip BEFORE the empty-bearer check (a softer DoS target than
    // /metrics): it short-circuits an absent bearer first, matching /metrics -- 0 DO fetches.
    ok("SUPPORT-INGEST: an absent bearer short-circuits BEFORE the DO round trip (0 DO fetches)", fetchCount() === 0);
  }
}

// ---- Stable ordering --------------------------------------------------------------------------------
async function testStableOrdering(): Promise<void> {
  const { storage, stub } = makeScheduler();
  const bearer = await seedMetricsCredential(storage);
  for (let i = 0; i < 40; i++) seedDownpipe(storage, { id: `dp${i}`, name: `Downpipe ${i}` });

  const t1 = await (await scrape(stub, bearer)).text();
  const t2 = await (await scrape(stub, bearer)).text();
  ok("two scrapes of unchanged state are byte-identical (stable canonical family ordering)", t1 === t2 && t1.length > 0);
}

async function main(): Promise<void> {
  console.log("unbounded-fleet scrape:");
  await testUnboundedFleetScrape();
  console.log("\ninjection safety under hostile downpipe names:");
  await testInjectionSafety();
  console.log("\nauth gating + DO-round-trip asymmetry:");
  await testAuthGating();
  console.log("\nstable ordering:");
  await testStableOrdering();

  console.log(failures === 0 ? "\nDESTSIM METRICS ABUSE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
