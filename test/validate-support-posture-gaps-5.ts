// POSTURE (ENGINE half): two support-pack projections, each proven through its real entry point. A recorder,
// a caller and a projection can each exist and work in isolation while the evidence still cannot answer the
// support ticket, because two states the projection exists to separate can still produce a BYTE-IDENTICAL row.
//
// EVERY ASSERTION HERE DRIVES A REAL ENTRY POINT. Nothing posts a hand-made record into a recorder and then
// asserts it came back: that proves the ring can carry a class, not that the product can put it there. The
// discovery-health case is driven through GET /admin/sources/discover on a REAL Durable Object with a faked
// Cloudflare API, and the row is read back through the REAL pack projector. The replication case is driven
// through the REAL downpipes[] projector with the real config and the real replication map.
//
// Run: node test/validate-support-posture-gaps-5.ts

import { handleAdmin } from "../src/admin/router.ts";
import { makeScheduler, makeSigner, TEAM, AUD } from "./validate-rbac-harness.ts";
import { DISCOVERY_KEY } from "../src/sched/scheduler-do-records.ts";
import { fetchDiscoveryHealth } from "../src/admin/support-sections-config.ts";
import { projectDownpipeRow, type SupportDownpipeState } from "../src/admin/support-sections-downpipes.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ACCT = (n: number): string => `${n}`.padStart(2, "0").repeat(16); // 32-char hex-ish account id
const OWNER = "owner-g5@acme.example";

// ---------------------------------------------------------------------------------------------------------
// A FAKE CLOUDFLARE API. deniedD1 names the accounts whose D1 listing answers 403 (the scope-starved token);
// every other listing answers 200 with one resource, so those products classify `ok`. emptyR2 names the
// accounts whose R2 listing answers 200 with NO buckets (the honestly-empty account).
// ---------------------------------------------------------------------------------------------------------
function fakeCloudflare(opts: { deniedD1?: ReadonlySet<string>; emptyR2?: ReadonlySet<string> } = {}): () => void {
  const real = globalThis.fetch;
  const denied = opts.deniedD1 ?? new Set<string>();
  const emptyR2 = opts.emptyR2 ?? new Set<string>();
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    // Only the Cloudflare API is faked. Everything else (the Access JWKS fetch the router's own authn makes)
    // passes through untouched, so the route is driven through its REAL authentication.
    if (url.host !== "api.cloudflare.com") return real(input as RequestInfo, init);
    const p = url.pathname;
    const acct = /\/accounts\/([^/]+)\//.exec(p)?.[1] ?? "";
    const json = (result: unknown, status = 200): Response => new Response(JSON.stringify({ result, success: true }), { status, headers: { "content-type": "application/json" } });
    if (p.includes("/d1/database")) {
      // 403: the token cannot read D1 in THIS account. cfApi turns a non-ok into `HTTP 403`, listD1 fails open
      // and pushes "d1: HTTP 403", and classifyDiscoveryError reads that to select (d1, denied).
      if (denied.has(acct)) return new Response("no", { status: 403 });
      return json([{ uuid: "db-1", name: "app" }]);
    }
    if (p.includes("/r2/buckets")) return json({ buckets: emptyR2.has(acct) ? [] : [{ name: "bucket-1" }] });
    if (p.includes("/storage/kv/namespaces")) return json([{ id: "ns-1", title: "kv" }]);
    if (p.includes("/secrets_store/stores")) return json([{ id: "st-1", name: "store" }]);
    if (p.includes("/zones")) return json([{ id: "z-1", name: "acme.example" }]);
    return json([]);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = real;
  };
}

// discoverOnce boots a REAL scheduler DO, seeds the owner's discovery config (token + the selected accounts),
// drives GET /admin/sources/discover through the REAL admin router, and returns the discoveryHealth section as
// the REAL pack projector builds it. No record is hand-posted anywhere.
// ONE signer for the whole run. The router caches the Access JWKS per URL after the first verification, so a
// second keypair would leave every later token unverifiable against the cached first one.
const signer = await makeSigner();

async function discoverOnce(accounts: readonly string[], cf: { deniedD1?: ReadonlySet<string>; emptyR2?: ReadonlySet<string> }): Promise<Record<string, unknown>> {
  const s = makeScheduler();
  const env = { ...s.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN: "bg-g5" } as unknown as Env;
  const call = async (method: "GET" | "POST", path: string): Promise<Response> =>
    handleAdmin(new Request(`https://engine.example${path}`, { method, headers: { "cf-access-jwt-assertion": await signer.tokenFor(OWNER) } }), env);
  await call("GET", "/admin/whoami"); // bootstrap the first Access caller as Owner
  await s.storage.put(DISCOVERY_KEY, {
    token: "cfat_g5_token_1234567890",
    setAt: 1,
    setBy: OWNER,
    accountsSeen: accounts.map((id) => ({ id, name: id })),
    selected: [...accounts],
    engineAccountId: accounts[0],
  });
  const restore = fakeCloudflare(cf);
  try {
    const r = await call("GET", "/admin/sources/discover");
    if (!r.ok) throw new Error(`discover returned ${r.status}`);
  } finally {
    restore();
  }
  return fetchDiscoveryHealth(s.stub);
}

type Tally = { withData?: number; empty?: number; degraded?: number };
const tallyOf = (h: Record<string, unknown>, product: string): Tally =>
  ((h.accountsByProduct as Record<string, Tally> | undefined)?.[product] ?? {});

// ---------------------------------------------------------------------------------------------------------
// "half our accounts show no resources" -- a ticket clause, and the state a folded per-product verdict
// destroys.
// ---------------------------------------------------------------------------------------------------------
async function g286(): Promise<void> {
  console.log("\na TOTAL product blackout and ONE scope-starved account are different rows:");

  const ten = Array.from({ length: 6 }, (_, i) => ACCT(i)); // MAX_DISCOVERY_ACCOUNTS is 8: six accounts, uncapped

  // STATE A: the token can read D1 in NO account. Every one of the ten 403s.
  const allDenied = await discoverOnce(ten, { deniedD1: new Set(ten) });
  // STATE B: the token can read D1 in NINE accounts and is refused in ONE (a membership-scoped account).
  const oneDenied = await discoverOnce(ten, { deniedD1: new Set([ACCT(3)]) });

  // The folded verdict is IDENTICAL in both: these two states produce byte-identical rows under a folded
  // per-product verdict alone, which is why the fold alone can never separate them.
  const lastA = allDenied.lastOutcome as Record<string, string>;
  const lastB = oneDenied.lastOutcome as Record<string, string>;
  ok("both states still fold to the SAME worst per-product verdict (denied), as they must", lastA.d1 === "denied" && lastB.d1 === "denied");
  ok("and to the SAME accountsScanned (6), so nothing in the folded verdict alone separates them", allDenied.accountsScanned === 6 && oneDenied.accountsScanned === 6);

  // ...and the per-account tally DOES separate them. This is the discrimination the gap asked for.
  ok("STATE A: EVERY account is degraded on d1 (a total blackout)", tallyOf(allDenied, "d1").degraded === 6 && tallyOf(allDenied, "d1").withData === 0);
  ok("STATE B: ONE account is degraded on d1 and the rest list it fine", tallyOf(oneDenied, "d1").degraded === 1 && tallyOf(oneDenied, "d1").withData === 5);
  ok("THE ROWS ARE DIFFERENT (the two states can never coalesce)", JSON.stringify(tallyOf(allDenied, "d1")) !== JSON.stringify(tallyOf(oneDenied, "d1")));
  ok("accountsDegraded counts the ACCOUNTS, not the requests: 6 vs 1", allDenied.accountsDegraded === 6 && oneDenied.accountsDegraded === 1);

  // A healthy scan must not cry wolf: nothing is degraded, and the tally says every account had data.
  const clean = await discoverOnce(ten, {});
  ok("NOISE: a healthy multi-account scan reports ZERO degraded accounts", clean.accountsDegraded === 0 && tallyOf(clean, "d1").degraded === 0);
  ok("NOISE: and every account is counted as having data (no fabricated emptiness)", tallyOf(clean, "d1").withData === 6);

  // ---- the SECOND defect: an empty account must not MASK a populated one ----
  console.log("\none empty account does not assert 'no R2 anywhere':");
  const oneEmptyR2 = await discoverOnce(ten, { emptyR2: new Set([ACCT(4)]) });
  const allEmptyR2 = await discoverOnce(ten, { emptyR2: new Set(ten) });
  ok("five populated accounts and ONE empty one report r2 = ok, NOT empty (the false row is gone)", (oneEmptyR2.lastOutcome as Record<string, string>).r2 === "ok");
  ok("...while a genuinely empty estate still reports r2 = empty (the honest absence survives)", (allEmptyR2.lastOutcome as Record<string, string>).r2 === "empty");
  ok("and the tally says HOW MANY were empty: 1 of 6 vs 6 of 6", tallyOf(oneEmptyR2, "r2").empty === 1 && tallyOf(oneEmptyR2, "r2").withData === 5 && tallyOf(allEmptyR2, "r2").empty === 6);

  // ---- REDACTION: the account ids are the sentinel. Not one may appear anywhere in the projected section. ----
  const text = JSON.stringify(allDenied) + JSON.stringify(oneDenied) + JSON.stringify(clean);
  ok("REDACTION: no account id rides into the pack section (counts by closed class only)", !ten.some((a) => text.includes(a)));
  ok("REDACTION: no Cloudflare message, token or bucket name rides", !text.includes("HTTP 403") && !text.includes("cfat_") && !text.includes("bucket-1"));
}

// ---------------------------------------------------------------------------------------------------------
// A destination that has NEVER replicated, versus one the downpipe was never configured to use. Row
// absence is only readable against the INTENDED FAN-OUT, so the fan-out belongs in the pack.
// ---------------------------------------------------------------------------------------------------------
function g299(): void {
  console.log("\n'never reported' and 'never configured' are different rows:");

  // The real projector, over the real config shape and the real replication map fetchReplication builds.
  const project = (destinationIds: string[], replicated: string[]): Record<string, unknown> => {
    const rows = replicated.map((id) => ({ id, ok: true, holdsRunId: "01RUN" }));
    const dp = { config: { id: "P", name: "P", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds } } as unknown as SupportDownpipeState;
    return projectDownpipeRow(dp, {
      replication: rows.length > 0 ? { P: rows } : {},
      destIdSet: new Set(["D1", "D2", "D3"]),
      sealErrors: {},
      freshnessIndex: new Map(),
      // No cap refused anything in this scenario, so the row must carry no freshness caveat.
      freshnessTruncation: { named: new Set<string>(), incomplete: false },
      refusalIndex: new Map(),
    });
  };
  const repl = (row: Record<string, unknown>): Record<string, unknown> => (row.replication ?? {}) as Record<string, unknown>;

  // STATE B: catching up. P fans out to D1 and D2; BOTH have reported; D2 is behind.
  const catchingUp = project(["D1", "D2"], ["D1", "D2"]);
  // STATE A: THE ESCALATE STATE. P is configured to fan out to D2 and D2 HAS NEVER REPORTED. That copy of the
  // backup does not exist and has not since the day it was configured.
  const neverReported = project(["D1", "D2"], ["D1"]);
  // STATE C: LEGITIMATE. P was never configured to fan out to D2 at all; D2 is in the fleet roster because some
  // OTHER downpipe uses it. Nothing is wrong and nothing may fire.
  const notConfigured = project(["D1"], ["D1"]);

  ok("STATE A names the destination that has NEVER replicated", (repl(neverReported).neverReportedIds as string[])?.[0] === "D2" && repl(neverReported).neverReportedCount === 1);
  ok("STATE C (never configured for D2) names NOTHING: no neverReported key at all", repl(notConfigured).neverReportedIds === undefined && repl(notConfigured).neverReportedCount === undefined);
  ok("A vs C ARE DIFFERENT ROWS (never-reported and never-configured do not collapse into the same absence)", JSON.stringify(repl(neverReported)) !== JSON.stringify(repl(notConfigured)));
  ok("STATE B (both reported, one behind) also names nothing as never-reported", repl(catchingUp).neverReportedIds === undefined);
  ok("A vs B are different rows", JSON.stringify(repl(neverReported)) !== JSON.stringify(repl(catchingUp)));

  // The INTENDED FAN-OUT is what makes row absence mean anything, and it was in no section of the pack.
  ok("the row carries the intended fan-out, so absence is readable at all", JSON.stringify(repl(neverReported).configuredIds) === JSON.stringify(["D1", "D2"]));

  // THE WORST CASE: a naive `rows.length > 0` guard would drop the replication key entirely for a downpipe on
  // which NO destination has ever reported, reading exactly like a downpipe with no run yet.
  const nothingEverReported = project(["D1", "D2"], []);
  ok("a downpipe where NOTHING has ever replicated still carries a replication block", repl(nothingEverReported).neverReportedCount === 2);
  ok("...and it is distinct from a downpipe with no configured fan-out at all (honest absence)", (project([], []).replication) === undefined);

  // THE ROW THAT LIES, AND IT IS THE ONE SUPPORT WOULD ESCALATE ON. The /replication read is a DO round trip
  // and it can throw. Degrading that fault to an EMPTY MAP would have projectReplication read it as "no
  // destination has ever reported" -- so one transient blip would make the pack assert, of every configured
  // destination on every downpipe in the fleet, that it holds no copy of any backup: a read fault ("the
  // heartbeats could not be read") would read as "that copy does not exist". fetchReplication returns NULL on
  // a fault instead, and the projector makes no never-reported claim on it.
  const unreadable = ((): Record<string, unknown> => {
    const dp = { config: { id: "P", name: "P", source: { type: "kv", binding: "KV", namespaceId: "ns" }, destinationIds: ["D1", "D2"] } } as unknown as SupportDownpipeState;
    return projectDownpipeRow(dp, { replication: null, destIdSet: new Set(["D1", "D2"]), sealErrors: {}, freshnessIndex: new Map(), freshnessTruncation: { named: new Set<string>(), incomplete: false }, refusalIndex: new Map() });
  })();
  ok("an UNREADABLE heartbeat store makes NO never-reported claim", repl(unreadable).neverReportedIds === undefined && repl(unreadable).neverReportedCount === undefined);
  ok("...and says so, so the absence is readable as a read fault rather than as a clean fleet", repl(unreadable).heartbeatsUnreadable === true);
  ok("...while still carrying the intended fan-out, which comes off the config and is always readable", JSON.stringify(repl(unreadable).configuredIds) === JSON.stringify(["D1", "D2"]));
  ok("AN UNREADABLE READ IS NOT THE SAME ROW AS 'nothing has ever replicated'", JSON.stringify(repl(unreadable)) !== JSON.stringify(repl(nothingEverReported)));

  // NOISE: a healthy read is untouched. heartbeatsUnreadable never appears on a fleet whose heartbeats were read.
  ok("a readable store never carries heartbeatsUnreadable", repl(catchingUp).heartbeatsUnreadable === undefined && repl(neverReported).heartbeatsUnreadable === undefined);

  // NOISE: a default-destination downpipe names no destination, so it can never be reported as never-reporting.
  ok("NOISE: a downpipe on the DEFAULT destination fires nothing (it named no fan-out to fail)", (project([], []).replication) === undefined);
}

async function main(): Promise<void> {
  await g286();
  g299();
  console.log(failures === 0 ? "\nPOSTURE GROUP 1 (ENGINE) PASS" : `\nPOSTURE GROUP 1 (ENGINE): ${failures} FAILED`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

await main();
