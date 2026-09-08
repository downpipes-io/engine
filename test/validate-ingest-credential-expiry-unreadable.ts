// THE BEARER THAT COULD NEVER EXPIRE, AND THE FOUR READERS THAT AGREED WITH IT.
//
// WHAT THIS PINS. A stored ingest grant's expiry was read by four sites with one idiom,
// `Date.now() > Date.parse(grant.expiresAt)`, and Date.parse answers NaN for anything it cannot read. Every
// comparison with NaN is false, so an unparseable expiresAt read as NOT EXPIRED at all four at once:
//   1. classifyIngestCredentialCheck (the GATE for /support/diagnostics, /support/audit-feed and /metrics --
//      the credential family presented by an UNAUTHENTICATED caller from the public internet) authenticated;
//   2. redactGrant (the console's supportability view) reported `expired: false`;
//   3. fetchAuditFeedState (the support pack's SIEM-feed block) wrote `expired: false`;
//   4. fetchMetricsFeed (the pack's scrape block) wrote `expired: false`.
// A credential that can never expire and no surface anywhere that disagrees, against a mint comment that
// promises the longest-lived scope is "still expiring and re-mintable, never permanent".
//
// Section W drives the ONLY two writers of the stored record --
// mintIngestCredential over hostile TTLs (including the JSON literals that parse to +/-Infinity, which is the
// one route a caller controls) and the DO's own record-pull read-modify-write -- and measures that neither can
// produce an unparseable value. The producer is a corrupted write, a half-flushed page or a hand-edited
// record.
//
// THE RIG IS THE REAL PATH: handleSupportPull and the two pack gatherers against a REAL SchedulerDO
// (src/sched/scheduler-do.ts) over MockStorage, with counters read back through fetchAdminCounters -- the
// projection the SUPPORT PACK itself takes. No hand-rolled double reads any number.
//
// THREE STATES, NEVER TWO. The gate's third state is its own closed outcome and a REFUSAL, because collapsing
// "unreadable" into either "expired" or "live" is how the same idiom went wrong to begin with; sections F.S2
// and F.S3 drive both collapses and require them to fail.
//
// Run: node test/validate-ingest-credential-expiry-unreadable.ts

import { readFileSync } from "node:fs";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { ADMIN_COUNTER_NAMES, METRICS_SCRAPE_OUTCOMES } from "../src/admin/diag-records.ts";
import {
  classifyIngestCredentialCheck,
  handleSupportPull,
  ingestPullRefusalCounter,
  INGEST_TTL_CAPS_SECONDS,
  mintIngestCredential,
  redactGrant,
  resetAuthFailureThrottle,
  type IngestCheckOutcome,
  type IngestGrant,
} from "../src/admin/support-ingest.ts";
import { handleMetricsRoute } from "../src/admin/metrics.ts";
import { fetchAuditFeedState, fetchMetricsFeed } from "../src/admin/support-sections-audit.ts";
import { fetchAdminCounters, fetchMetricsHealth } from "../src/admin/support-sections-diag.ts";
import { grantExpiryState } from "../src/admin/support-shared.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const EMPTY_ENV = {} as unknown as Env;
const HOUR = 3_600_000;
const UNREADABLE_COUNTER = "ingest-pull-refused-credential-expiry-unreadable";

// asStub adapts a real SchedulerDO to the DurableObjectStub shape: the platform bridges a stub's TWO-ARGUMENT
// fetch(url, init) into the ONE-ARGUMENT Request SchedulerDO.fetch takes. THIS IS A MEASURED KNOWN POSITIVE.
// Without it every DO fetch throws "Invalid URL" INSIDE the route, the 500 body parses to an object with no
// `grant`, and handleSupportPull reads that as `no-grant` and answers a plausible 401 for every dose while
// measuring nothing at all -- the exact way a broken rig can look like it works. Section A
// proves the bridge before any zero below is trusted.
function asStub(dobj: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(input as string, init)),
  } as unknown as DurableObjectStub;
}

function makeScheduler(): { storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: asStub(new SchedulerDO(state)) };
}

/** settle drains the fire-and-forget counter writes handleSupportPull issues with `void`. */
async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0));
}

/** at builds an expiresAt offset from now, so the dose is injected rather than waited for. */
function at(offsetMs: number): string {
  return new Date(Date.now() + offsetMs).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

function pull(bearer: string): Request {
  return new Request("https://engine.example/support/audit-feed", { headers: { Authorization: `Bearer ${bearer}` } });
}

/** withExpiry clones a grant with a planted expiresAt; `undefined` plants an ABSENT field (a corrupt record). */
function withExpiry(base: IngestGrant, value: string | undefined): IngestGrant {
  // The local type makes expiresAt OPTIONAL rather than intersecting an optional onto a required member:
  // `IngestGrant & { expiresAt?: string }` keeps the required member required, so `delete` was a type error
  // (TS2790) and the absent-field plant this function exists to build could not be expressed in its own terms.
  const g: Omit<IngestGrant, "expiresAt"> & { expiresAt?: string } = { ...base };
  if (value === undefined) delete g.expiresAt;
  else g.expiresAt = value;
  return g as IngestGrant;
}

/** THE PRE TREE: the exact expression the four sites carried before this change, quoted once. */
function preExpired(expiresAt: unknown): boolean {
  return Date.now() > Date.parse(expiresAt as string);
}

async function driveSeeded(grant: IngestGrant, bearer: string): Promise<{ counters: Record<string, { count: number; lastAt?: string }>; status: number }> {
  const { storage, stub } = makeScheduler();
  await storage.put("ingestcred:audit-feed", grant);
  resetAuthFailureThrottle();
  const resp = await handleSupportPull(pull(bearer), EMPTY_ENV, stub);
  await settle();
  return { counters: await fetchAdminCounters(stub), status: resp.status };
}

async function packBlocks(grant: IngestGrant): Promise<{ feed: Record<string, unknown>; metrics: Record<string, unknown> }> {
  const { storage, stub } = makeScheduler();
  await storage.put("ingestcred:audit-feed", grant);
  await storage.put("ingestcred:metrics", grant);
  return { feed: await fetchAuditFeedState(stub), metrics: await fetchMetricsFeed(stub) };
}

async function main(): Promise<void> {
  const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
  const bearer = `${minted.clientId}.${minted.secret}`;

  // ------------------------------------------------------------------------------------------------------
  // A. KNOWN POSITIVES FIRST: prove the rig reaches the code before trusting any zero it reports.
  // ------------------------------------------------------------------------------------------------------
  console.log("A -- known positives (the rig reaches the code, both trees)");
  {
    const good = await driveSeeded(minted.grant, bearer);
    ok("A1 a VALID bearer on a live grant is ADMITTED (200), so the rig reaches past the gate", good.status === 200);
    ok("A1 and books NO refusal at all (the keys are ABSENT, not zero)", Object.keys(good.counters).filter((k) => k.startsWith("ingest-pull-refused-")).length === 0);
    // THE INSTRUMENT CONTROL for every section below: the ORDINARY expiry class, which booked correctly before
    // this change and must book correctly after it, on the same rig in the same session. If this is missing,
    // every absence below is a dead ledger rather than a suppressed booking.
    const lapsed = await driveSeeded(withExpiry(minted.grant, at(-HOUR)), bearer);
    ok("A2 INSTRUMENT CONTROL: an ORDINARY expired grant still refuses 401", lapsed.status === 401);
    ok("A2 INSTRUMENT CONTROL: and still books ingest-pull-refused-credential-expired exactly 1", lapsed.counters["ingest-pull-refused-credential-expired"]?.count === 1);
    ok("A2 INSTRUMENT CONTROL: the generic ingest-pull-auth-failed rides beside it, unchanged", lapsed.counters["ingest-pull-auth-failed"]?.count === 1);
    const blocks = await packBlocks(minted.grant);
    ok("A3 the PACK gatherers reach the same seeded grant (configured, not an empty block)", blocks.feed.configured === true && blocks.metrics.configured === true);
    ok("A3 and read a live grant as NOT expired", blocks.feed.expired === false && blocks.metrics.expired === false);
  }

  // ------------------------------------------------------------------------------------------------------
  // W. THE WRITER TRACE. Question one, measured rather than argued: can a PRODUCT writer put an unparseable
  //    value in this field at all? There are exactly two writers of `ingestcred:<scope>` -- the mint (via the
  //    DO's /ingest-credential/set) and the DO's own record-pull read-modify-write.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nW -- the writer trace: no product writer can produce an unparseable expiresAt");
  {
    // ttlSeconds is the ONE part of the mint a caller controls (POST /support/credentials), and it arrives
    // through JSON.parse. NaN and Infinity are not JSON literals, but an overflowing numeric literal IS:
    // JSON.parse("1e400") yields Infinity, and `typeof Infinity === "number"` passes the router's own guard.
    const overflow = JSON.parse('{"ttlSeconds":1e400}') as { ttlSeconds: number };
    const underflow = JSON.parse('{"ttlSeconds":-1e400}') as { ttlSeconds: number };
    ok("W0 KNOWN POSITIVE: a JSON numeric literal really can overflow to Infinity and pass `typeof === number`", overflow.ttlSeconds === Number.POSITIVE_INFINITY && typeof overflow.ttlSeconds === "number");
    const doses: Array<{ label: string; ttl: number | undefined }> = [
      { label: "absent (the default)", ttl: undefined },
      { label: "0", ttl: 0 },
      { label: "-1", ttl: -1 },
      { label: "1e400 -> +Infinity", ttl: overflow.ttlSeconds },
      { label: "-1e400 -> -Infinity", ttl: underflow.ttlSeconds },
      { label: "fractional 0.5", ttl: 0.5 },
      { label: "Number.MAX_SAFE_INTEGER", ttl: Number.MAX_SAFE_INTEGER },
      { label: "1e21 (past the ISO year range on its own)", ttl: 1e21 },
      { label: "the scope cap exactly", ttl: INGEST_TTL_CAPS_SECONDS["audit-feed"].max },
    ];
    for (const d of doses) {
      const m = await mintIngestCredential("audit-feed", null, d.ttl);
      const state = grantExpiryState(m.grant.expiresAt);
      ok(`W1 mint ttl=${d.label}: the minted expiresAt PARSES (the writer cannot produce the corrupt state)`, state.readable);
      ok(`W1 mint ttl=${d.label}: and is clamped inside the scope cap, so no dose escapes the ladder`, Date.parse(m.grant.expiresAt) - Date.now() <= INGEST_TTL_CAPS_SECONDS["audit-feed"].max * 1000 + 5_000);
    }
    // The SECOND writer: the DO's record-pull is a read-modify-write over the same key. If it re-wrote the
    // record from a partial shape it would DELETE expiresAt, which is one of the corrupt states section B
    // drives -- so this is a real candidate producer, not a formality.
    const { storage, stub } = makeScheduler();
    await storage.put("ingestcred:audit-feed", minted.grant);
    for (let i = 0; i < 3; i++) {
      const r = await stub.fetch("https://do/ingest-credential/record-pull", { method: "POST", body: JSON.stringify({ scope: "audit-feed", at: at(0) }) });
      if (r.status !== 200) throw new Error(`record-pull answered ${r.status}`);
    }
    const after = (await storage.get("ingestcred:audit-feed")) as IngestGrant;
    ok("W2 KNOWN POSITIVE: the record-pull writer really did run and mutate the record (3 pulls are on it)", after.pulls.length === 3);
    ok("W2 and expiresAt survives it BYTE-IDENTICAL (the RMW preserves the field it does not own)", after.expiresAt === minted.grant.expiresAt);
    ok("W2 so the stored record still parses after the only other writer touched it", grantExpiryState(after.expiresAt).readable);
    // The whole-file census behind the two writers above: no OTHER site writes the key at all.
    const routing = readFileSync(new URL("../src/sched/scheduler-do-routing.ts", import.meta.url), "utf8");
    const writeSites = (routing.match(/storage\.put\(`ingestcred:/g) ?? []).length;
    const anyOtherFile = ["../src/admin/support-ingest.ts", "../src/admin/router-status.ts", "../src/sched/scheduler-do-base.ts"].filter((f) =>
      readFileSync(new URL(f, import.meta.url), "utf8").includes("storage.put(`ingestcred:"),
    );
    ok("W3 the ingest-credential key has exactly TWO writers, both in the DO routing mixin", writeSites === 2);
    ok("W3 and no admin route, restore path or migration writes it directly", anyOtherFile.length === 0);
  }

  // ------------------------------------------------------------------------------------------------------
  // B. DOSE-RESPONSE OVER THE VALUE CLASSES, AT ALL FOUR READERS, PRE AND POST, IN ONE SESSION.
  //    The four boundary answers this campaign has each had as a separate defect are asserted APART:
  //    ABSENT (the key is not there), ZERO/false (a value that reads as healthy), INVERTED and DISCARDED.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nB -- dose-response: well-formed, boundary-adjacent, malformed, absent, empty-string");
  type Dose = { label: string; value: string | undefined; readable: boolean; expired: boolean };
  const doses: Dose[] = [
    { label: "+24h (well-formed, live)", value: at(24 * HOUR), readable: true, expired: false },
    { label: "+1s (boundary-adjacent, live)", value: at(1_000), readable: true, expired: false },
    { label: "-1s (boundary-adjacent, lapsed)", value: at(-1_000), readable: true, expired: true },
    { label: "-24h (well-formed, lapsed)", value: at(-24 * HOUR), readable: true, expired: true },
    { label: "malformed text", value: "not-a-date", readable: false, expired: false },
    { label: "malformed ISO-shaped", value: "2026-13-45T99:99:99Z", readable: false, expired: false },
    { label: "truncated ISO (no time part)", value: "2026-08-12T", readable: false, expired: false },
    { label: "empty string", value: "", readable: false, expired: false },
    { label: "absent field", value: undefined, readable: false, expired: false },
    // MEASURED, NOT ASSUMED, AND IT CORRECTED THIS PASS'S FIRST DOSE SET. Date.parse is LENIENT where the ISO
    // grammar is not: "2026-08-" resolves to local midnight and "0" to 31 December 1999, so a
    // TRUNCATED stored expiry does not produce the corrupt state at all -- it produces a silently DIFFERENT,
    // past date, which reads as expired and therefore fails CLOSED. Only a wholly unparseable value reaches
    // the fail-open state this validator exists for, and these two doses hold that line rather than assuming
    // "malformed implies NaN". Both are stable instants: they are in the past and stay there.
    { label: "lenient partial date (parses to 2026-08-01 local)", value: "2026-08-", readable: true, expired: true },
    { label: "lenient bare zero (parses to 1999-12-31 local)", value: "0", readable: true, expired: true },
  ];
  for (const d of doses) {
    const g = withExpiry(minted.grant, d.value);
    // 1. THE GATE.
    const outcome = await classifyIngestCredentialCheck(bearer, g);
    const wantOutcome: IngestCheckOutcome = !d.readable ? "credential-expiry-unreadable" : d.expired ? "credential-expired" : "ok";
    ok(`B ${d.label}: the GATE answers ${wantOutcome}`, outcome === wantOutcome);
    // 2. THE CONSOLE VIEW.
    const view = redactGrant(g) as { expired: boolean; expiryUnreadable?: boolean };
    ok(`B ${d.label}: the VIEW's coarse boolean says ${!d.readable || d.expired ? "unusable" : "usable"}`, view.expired === (!d.readable || d.expired));
    ok(`B ${d.label}: the VIEW's expiryUnreadable is ${d.readable ? "ABSENT (not false)" : "true"}`, d.readable ? view.expiryUnreadable === undefined : view.expiryUnreadable === true);
    // 3 + 4. BOTH PACK BLOCKS.
    const blocks = await packBlocks(g);
    for (const [name, block] of [
      ["auditFeed", blocks.feed],
      ["metricsFeed", blocks.metrics],
    ] as const) {
      ok(`B ${d.label}: the PACK ${name} block says expired=${!d.readable || d.expired}`, block.expired === (!d.readable || d.expired));
      ok(`B ${d.label}: the PACK ${name} block's expiryUnreadable is ${d.readable ? "ABSENT" : "true"}`, d.readable ? block.expiryUnreadable === undefined : block.expiryUnreadable === true);
    }
    // THE PRE TREE, on the same dose in the same session. On every unreadable dose it answered NOT EXPIRED --
    // and that is the defect, stated as a measurement rather than as prose.
    ok(`B ${d.label}: PRE (the removed expression) answered expired=${preExpired(d.value)}`, preExpired(d.value) === (d.readable && d.expired));
    if (!d.readable) {
      ok(`B ${d.label}: PRE therefore read a CORRUPT grant as LIVE, and POST does not`, preExpired(d.value) === false && view.expired === true);
    }
    // The refusal booking, through the real pull path and the pack's own counter projection.
    const drive = await driveSeeded(g, bearer);
    const booked = drive.counters[UNREADABLE_COUNTER]?.count;
    ok(`B ${d.label}: the unreadable-class counter is ${d.readable ? "ABSENT" : "1"}`, d.readable ? booked === undefined : booked === 1);
    ok(`B ${d.label}: the pull is ${!d.readable || d.expired ? "401" : "200"}`, drive.status === (!d.readable || d.expired ? 401 : 200));
    if (!d.readable) {
      ok(`B ${d.label}: and the EXPIRED class is NOT booked beside it (the two classes do not blend)`, drive.counters["ingest-pull-refused-credential-expired"] === undefined);
    }
  }

  // ------------------------------------------------------------------------------------------------------
  // C. THE OLD IDIOM IS GONE FROM THE FOUR SITES. A repair that left one reader on the raw comparison would
  //    put the gate and a surface back on two different edges, which is the disagreement this pins against.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nC -- the four readers share ONE expression");
  {
    const files = ["../src/admin/support-ingest.ts", "../src/admin/support-sections-audit.ts", "../src/admin/support-shared.ts"];
    // CODE ONLY. The census must not count a comment (such as one in support-shared.ts) that quotes the removed
    // idiom verbatim for documentation's sake. A scanner
    // that reads commentary as code fires in the direction that
    // manufactures a defect rather than hiding one. Comments are stripped before the match, and the known
    // positive below proves the stripped text is still real source rather than an empty string.
    const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
    let rawComparisons = 0;
    let sharedCalls = 0;
    let strippedBytes = 0;
    for (const f of files) {
      const src = stripComments(readFileSync(new URL(f, import.meta.url), "utf8"));
      strippedBytes += src.length;
      rawComparisons += (src.match(/Date\.now\(\) > Date\.parse\(/g) ?? []).length;
      sharedCalls += (src.match(/grantExpiryState\(/g) ?? []).length;
    }
    ok("C KNOWN POSITIVE: the census instrument finds the shared reader, so a zero above is a real zero", sharedCalls >= 4);
    ok("C KNOWN POSITIVE: comment-stripping left real source behind rather than emptying the files", strippedBytes > 20_000);
    ok("C CONTROL: the un-stripped text DOES contain the quoted idiom, so the stripper is what made the zero", /Date\.now\(\) > Date\.parse\(/.test(readFileSync(new URL("../src/admin/support-shared.ts", import.meta.url), "utf8")));
    ok("C no site still carries the NaN-blind `Date.now() > Date.parse(` comparison", rawComparisons === 0);
    // The helper itself is the single edge, and it is TOTAL: every input lands in exactly one of three states.
    for (const v of [at(HOUR), at(-HOUR), "not-a-date", "", undefined, null, 42, {}]) {
      const s = grantExpiryState(v);
      ok(`C grantExpiryState(${JSON.stringify(v)}) returns a complete verdict, never undefined`, typeof s.readable === "boolean" && typeof s.expired === "boolean");
      ok(`C ... and never reports an unreadable value as expired (the third state is not collapsed)`, s.readable || s.expired === false);
    }
    ok("C the injected clock is honoured, so the edge is testable rather than wall-clock-bound", grantExpiryState(at(0), Date.now() + HOUR).expired && !grantExpiryState(at(0), Date.now() - HOUR).expired);
  }

  // ------------------------------------------------------------------------------------------------------
  // D. THE SENTINEL THAT MUST BE REACHED. An assertion that only counts absences holds over a blank page:
  //    two refusals of the SAME class must ARRIVE AT 2 through the pack's own projection.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nD -- the sentinel that must be REACHED, not an absence");
  {
    const corrupt = withExpiry(minted.grant, "not-a-date");
    const { storage, stub } = makeScheduler();
    await storage.put("ingestcred:audit-feed", corrupt);
    for (let i = 0; i < 2; i++) {
      resetAuthFailureThrottle(); // two distinct throttle windows, by design one booking each
      await handleSupportPull(pull(bearer), EMPTY_ENV, stub);
    }
    await settle();
    const c = await fetchAdminCounters(stub);
    ok("D two unreadable-expiry refusals ARRIVE AT 2 through the pack projection", c[UNREADABLE_COUNTER]?.count === 2);
    ok("D the generic ingest-pull-auth-failed arrives at 2 beside it (the two move together)", c["ingest-pull-auth-failed"]?.count === 2);
    ok("D the counter carries a lastAt, so 'since when' is answerable", typeof c[UNREADABLE_COUNTER]?.lastAt === "string");
    // THROTTLE PARITY: the branch is reachable by any unauthenticated caller, so the added name must not have
    // turned the observer into a write amplifier for the storm it observes.
    const { storage: s2, stub: st2 } = makeScheduler();
    await s2.put("ingestcred:audit-feed", corrupt);
    resetAuthFailureThrottle();
    for (let i = 0; i < 50; i++) await handleSupportPull(pull(bearer), EMPTY_ENV, st2);
    await settle();
    const c2 = await fetchAdminCounters(st2);
    ok("D 50 refusals inside ONE window book ONE discriminating event (the throttle is intact)", c2[UNREADABLE_COUNTER]?.count === 1);
    ok("D and ONE generic event (the write rate is byte-for-byte what it was)", c2["ingest-pull-auth-failed"]?.count === 1);
    // The pack block is a REACHED POSITIVE too: expiryUnreadable is a value that must be present, not a gap.
    const blocks = await packBlocks(corrupt);
    ok("D the pack's auditFeed block carries expiryUnreadable:true AS A VALUE", blocks.feed.expiryUnreadable === true && blocks.feed.configured === true);
    ok("D the pack's metricsFeed block carries it too (both blocks, one edge)", blocks.metrics.expiryUnreadable === true);
    // REDACTION: the corrupt timestamp TEXT never becomes a counter key, and the new field carries no text.
    ok("D no counter KEY carries the corrupt timestamp, the bearer or the clientId", Object.keys(c).every((k) => !k.includes("not-a-date") && !k.includes(minted.clientId) && !k.includes("dps_")));
    ok("D every projected counter key is a member of the CLOSED admin vocabulary", Object.keys(c).every((k) => (ADMIN_COUNTER_NAMES as readonly string[]).includes(k)));
    ok("D expiryUnreadable is a BOOLEAN, so the unparseable text cannot ride out on it", typeof blocks.feed.expiryUnreadable === "boolean");
  }

  // ------------------------------------------------------------------------------------------------------
  // E. THE CLOSED VOCABULARIES. A new outcome that booked nothing, or that no scrape record could carry,
  //    would be the fifteenth defect one member later: a class decided and discarded.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nE -- the closed vocabularies carry the new class");
  {
    const key = ingestPullRefusalCounter("credential-expiry-unreadable");
    ok("E the new outcome maps to a counter name at all (it is not dropped by the map)", key === UNREADABLE_COUNTER);
    ok("E and that name is a member of the CLOSED admin-counter vocabulary", (ADMIN_COUNTER_NAMES as readonly string[]).includes(UNREADABLE_COUNTER));
    ok("E the /metrics scrape record can carry it too (the SAME classifier feeds MetricsScrapeOutcome)", (METRICS_SCRAPE_OUTCOMES as readonly string[]).includes("credential-expiry-unreadable"));
    const all: IngestCheckOutcome[] = ["ok", "no-grant", "credential-expired", "credential-expiry-unreadable", "bearer-malformed", "client-id-mismatch", "secret-mismatch"];
    const names = all.filter((o) => o !== "ok").map((o) => ingestPullRefusalCounter(o));
    ok("E the map is TOTAL over the union and every class is DISTINCT (six names, no blend)", names.length === 6 && new Set(names).size === 6 && names.every((n) => n !== null));
    ok("E ok still books NOTHING (a successful pull is not a refusal)", ingestPullRefusalCounter("ok") === null);
  }

  // ------------------------------------------------------------------------------------------------------
  // F. TWO-SIDED. Each suppression is a WRONG treatment driven on the real subjects; the count of checks that
  //    fail in each direction is printed, and the INSTRUMENT CONTROL must PASS inside every one of them, so a
  //    failure is attributable to the treatment rather than to a dead rig.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nF -- two-sided: the suppressed directions, with the instrument control passing in each");
  {
    type Verdict = { gate: IngestCheckOutcome; expired: boolean; unreadable: boolean };
    type Sup = { name: string; apply: (v: string | undefined) => Verdict };
    const truth = (v: string | undefined): Verdict => {
      const s = grantExpiryState(v);
      return { gate: !s.readable ? "credential-expiry-unreadable" : s.expired ? "credential-expired" : "ok", expired: !s.readable || s.expired, unreadable: !s.readable };
    };
    const sups: Sup[] = [
      // S1 THE UNREPAIRED TREE: the NaN-blind comparison at every site, exactly as it stood before this change.
      { name: "S1 unrepaired (the raw Date.parse comparison)", apply: (v) => ({ gate: preExpired(v) ? "credential-expired" : "ok", expired: preExpired(v), unreadable: false }) },
      // S2 COLLAPSE INTO EXPIRED: NaN-safe, but the third state is thrown into the first, which loses the "your
      //    stored record is corrupt" ticket.
      { name: "S2 collapse unreadable INTO expired", apply: (v) => ({ gate: truth(v).expired ? "credential-expired" : "ok", expired: truth(v).expired, unreadable: false }) },
      // S3 COLLAPSE INTO LIVE: the original defect, restated as a deliberate choice.
      { name: "S3 collapse unreadable INTO live", apply: (v) => ({ gate: grantExpiryState(v).expired ? "credential-expired" : "ok", expired: grantExpiryState(v).expired, unreadable: false }) },
      // S4 OVER-FIX: a HEALTHY grant refused as unreadable. This needs live subjects in the loop to be seen at
      //    all, or an over-fix direction can fail 0 of 5 and read as green.
      { name: "S4 over-fix (a live grant refused as unreadable)", apply: () => ({ gate: "credential-expiry-unreadable", expired: true, unreadable: true }) },
      // S5 INVERTED SURFACE: the class is decided and the surface still says the credential is fine.
      { name: "S5 inverted surface (unreadable, but expired:false)", apply: (v) => ({ ...truth(v), expired: truth(v).unreadable ? false : truth(v).expired }) },
    ];
    for (const s of sups) {
      let sFail = 0;
      let controlOk = 0;
      for (const d of doses) {
        const want = truth(d.value);
        const got = s.apply(d.value);
        const held = got.gate === want.gate && got.expired === want.expired && got.unreadable === want.unreadable;
        if (!held) sFail++;
        // THE INSTRUMENT CONTROL, re-run inside every suppressed direction, on the REAL code rather than the
        // suppression: the ordinary two states still classify correctly, so a failure above is the treatment.
        const real = await classifyIngestCredentialCheck(bearer, withExpiry(minted.grant, d.value));
        if (real === want.gate) controlOk++;
      }
      ok(`F ${s.name}: FAILS the three-state check (${sFail} of ${doses.length})`, sFail > 0);
      ok(`F ${s.name}: INSTRUMENT CONTROL still passes in the suppressed direction (${controlOk} of ${doses.length})`, controlOk === doses.length);
    }
  }

  // ------------------------------------------------------------------------------------------------------
  // G. THE THIRD AUDIENCE: /metrics. The SAME classifier gates the Prometheus scrape, and its outcome is
  //    written to the metrics-health record -- but fetchMetricsHealth only projects lastOutcome when the
  //    value is a member of METRICS_SCRAPE_OUTCOME_SET, so a class the vocabulary does not carry is DROPPED
  //    from the pack in silence. This is where that kind of gap would recur.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nG -- the /metrics scrape half, through its own pack projection");
  {
    const metricsMint = await mintIngestCredential("metrics", "owner@example.test", 3600);
    const metricsBearer = `${metricsMint.clientId}.${metricsMint.secret}`;
    const drive = async (grant: IngestGrant): Promise<{ status: number; health: Record<string, unknown> }> => {
      const { storage, stub } = makeScheduler();
      await storage.put("ingestcred:metrics", grant);
      const resp = await handleMetricsRoute(new Request("https://engine.example/metrics", { headers: { authorization: `Bearer ${metricsBearer}` } }), stub);
      await settle();
      return { status: resp.status, health: await fetchMetricsHealth(stub) };
    };
    // KNOWN POSITIVE: a live grant scrapes, so a refusal below is the dose rather than a dead route.
    const live = await drive(metricsMint.grant);
    ok("G1 KNOWN POSITIVE: a live metrics grant SCRAPES (200), so the route is reached", live.status === 200);
    const lapsed = await drive(withExpiry(metricsMint.grant, at(-HOUR)));
    ok("G2 INSTRUMENT CONTROL: an ordinary expired metrics grant is refused and records credential-expired", lapsed.status === 401 && lapsed.health.lastOutcome === "credential-expired");
    const corrupt = await drive(withExpiry(metricsMint.grant, "not-a-date"));
    ok("G3 an UNREADABLE expiry refuses the scrape 401 (before this it rendered the whole fleet, for ever)", corrupt.status === 401);
    ok("G3 and the pack's own projection carries the class REACHED, not dropped as out-of-vocabulary", corrupt.health.lastOutcome === "credential-expiry-unreadable");
  }

  console.log(failures === 0 ? "\nINGEST CREDENTIAL EXPIRY-UNREADABLE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
