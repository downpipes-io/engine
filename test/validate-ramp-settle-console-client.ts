// Proves the console client reaches the engine's ramp-settle route end to end: the REAL console client -> the
// REAL engine route -> the counter read back out of the PACK'S OWN adminCounters projector.
//
// A customer running a gradual ramp needs a control that can finish it. The console's update client exposes
// settleRampUpdate for exactly this; the plain settleUpdate REFUSES a ramp-shaped (percentage-carrying)
// pending, so a ramp can only be settled through the dedicated ramp-settle route. This file proves two things:
//
//   1. THE ROUTE IS REACHABLE FROM THE PRODUCT. Section 1 drives the REAL, SHIPPED console client function
//      (settleRampUpdate, imported from the console worktree, not a re-implementation of it) over a fetch that
//      dispatches into the REAL, SHIPPED engine router (handleAdmin -> handleRampSettle) against a real
//      SchedulerDO. Nothing between the two is faked: the URL, the method, the body, the deploy-token posture
//      and the response parsing are all the console's own code, and the gate, the guards, the superseded check,
//      the health gate and the state machine are all the engine's own.
//
//   2. `update-settle-inconclusive` HAS A REACHABLE PRODUCER. handleRampSettle is its ONLY producer (the plain
//      settle does not bump it, because settle firing the stuck-ramp signal is not itself informative); the
//      counter must move on a real console attempt so support reads as "how hard has the operator been trying
//      to settle this stuck ramp" are meaningful -- a two-day-old armed ramp beside `update-settle-inconclusive:
//      0` would otherwise invite the wrong inference: nobody tried. Section 2 reads the counter through
//      fetchAdminCounters, which is the function support.ts calls to BUILD the pack's adminCounters section, so
//      what is asserted here is what a customer's pack actually carries.
//
// Section 3 is the sibling-site discipline: the SAME pending, driven through the OTHER console client (the
// plain settleUpdate), must be REFUSED by the engine. The two settle routes are mutually exclusive and each
// refuses the other's shape; making the ramp reachable while leaving the plain settle able to act on a ramp's
// pending would be the same defect, mirrored.
//
// No network, no deploy, no Cloudflare account: the DO answers from in-memory storage and the CF API is stubbed.
// Run: node test/validate-ramp-settle-console-client.ts

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { handleAdmin } from "../src/admin/router.ts";
import { fetchAdminCounters } from "../src/admin/support-sections-diag.ts";
import { SchedulerDO } from "../src/index.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// ---- Locate the CONSOLE, exactly the way the console's own drift gate locates the engine: an explicit
// override, then the unified worktree, then the merged repo. The worktree wins while a build is in flight,
// because it IS the console that will ship. This FAILS rather than skips when the console cannot be found: a
// gate that quietly opts out when it cannot check reads as a pass, which is the failure it exists to prevent.
const HERE = dirname(fileURLToPath(import.meta.url));
const CONSOLE_CLIENT = "src/lib/api/client-update.ts";
const CONSOLE_ROOT = [
  process.env.DOWNPIPES_CONSOLE,
  resolve(HERE, "../../support-unified-console"),
  resolve(HERE, "../../console"),
  resolve(HERE, "../../../console"),
]
  .filter((c): c is string => typeof c === "string")
  .find((c) => existsSync(resolve(c, CONSOLE_CLIENT)));
if (CONSOLE_ROOT === undefined) {
  console.error("RAMP-SETTLE E2E: FAIL -- cannot locate the console, so the real client cannot be driven.");
  console.error("  Set DOWNPIPES_CONSOLE=/path/to/console, or check the console out beside this repo.");
  process.exit(1);
}
console.log(`  (driving the real console client from ${CONSOLE_ROOT})`);

// WHICH CONSOLE TREE, and REFUSE when it is not the sibling's main.
//
// The line above already prints WHERE the console came from, and that is the half of the problem this
// workspace keeps getting wrong: a path is not a version. Two runs of this file, an hour apart, print the
// identical path and drive two different clients, and only one of them is the client that ships.
//
// This drive is a gating claim about the shipping pair rather than a demonstration whose result stays true
// of the tree it ran against. Its one seam is globalThis.fetch: everything the CONSOLE builds is what the
// engine parses. Run against a console the workspace left behind, a green says the engine answers a request
// shape the console has stopped sending, which is the exact false green a settle-path regression hides in.
reportSiblings([{ name: "console", path: CONSOLE_ROOT }], { gate: "ramp-settle-console-client" });
requireFreshSiblings([{ name: "console", path: CONSOLE_ROOT }], {
  gate: "ramp-settle-console-client",
  consequence: "the drive would exercise an older console client than the one that ships",
  exit: (code: number) => {
    verdictSkipped(`REFUSED, exit ${code}: the console checkout beside this engine is behind its own origin/main, so nothing was concluded`);
    process.exit(code);
  },
});

// The REAL, SHIPPED console modules. Imported dynamically (a computed path) so this validator can reach across
// the repo boundary without the engine's own typecheck taking a dependency on the console's tree.
const consoleUpdate = (await import(resolve(CONSOLE_ROOT, CONSOLE_CLIENT))) as {
  settleRampUpdate: (t: unknown, token: string) => Promise<{ outcome: string; toVersion: string; fromVersion: string }>;
  settleUpdate: (t: unknown, token: string) => Promise<{ outcome: string }>;
};
const { Transport } = (await import(resolve(CONSOLE_ROOT, "src/lib/api/client-transport.ts"))) as {
  Transport: new (base: string, token?: string) => unknown;
};

const ADMIN_TOKEN = "ramp-settle-e2e-admin-token";
const DEPLOY_TOKEN = "cf_deploy_token_0123456789abcdef"; // passes the engine's validateDeployToken shape
const ENGINE_BASE = "https://engine.example";
const ACCOUNT = "acct-e2e";
const RAMPED = "v-ramped"; // the Cloudflare version id the ramp promoted (pending.toVersion)
const PRIOR = "v-prior"; // the version still serving the majority slice

const storage = new MockStorage();
const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
const stub = {
  fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    return dobj.fetch(new Request(url, init));
  },
} as unknown as DurableObjectStub;
const namespace = {
  idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
  get: (_id: DurableObjectId) => stub,
} as unknown as DurableObjectNamespace;
const env = { SCHEDULER: namespace, ADMIN_TOKEN, CF_ACCOUNT_ID: ACCOUNT, WORKER_NAME: "downpipe-engine" } as unknown as Env;

// ---- THE ONE SEAM. globalThis.fetch is what the console's engineFetch calls, and it is pointed straight at
// the engine's own handleAdmin. Everything the console builds (URL, method, headers, body) is what the engine
// parses; everything the engine answers is what the console's own parser reads. The CF API arms below are the
// only stubs, and they model the state a live ramp is actually in: a SPLIT (the ramped version at 40%, the
// prior at 60%), which is precisely why a settle dispatch can fail to land on the ramped slice.
const engineCalls: string[] = [];
const deployCalls: string[] = [];
const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
  const method = init?.method ?? "GET";
  if (url.startsWith(ENGINE_BASE)) {
    engineCalls.push(`${method} ${new URL(url).pathname}`);
    // The console sends no Authorization header (it rides the Access cookie in production); the harness adds
    // the ADMIN_TOKEN break-glass bearer, which the engine resolves to owner, so the route BODY is exercised
    // rather than the gate. Every other byte of the request is the console's.
    const headers = new Headers(init?.headers as HeadersInit | undefined);
    headers.set("authorization", `Bearer ${ADMIN_TOKEN}`);
    return handleAdmin(new Request(url, { ...init, headers }), env);
  }
  // CF: list deployments -> a REAL two-version split. liveSingleVersion() returns null on this, which is what
  // an in-flight ramp looks like, so the superseded guard correctly does NOT fire and the settle proceeds.
  if (method === "GET" && /\/workers\/scripts\/[^/]+\/deployments$/.test(url)) {
    return new Response(JSON.stringify({ success: true, result: { deployments: [{ id: "d-1", versions: [{ version_id: PRIOR, percentage: 60 }, { version_id: RAMPED, percentage: 40 }] }] } }), { status: 200 });
  }
  // CF: create a deployment (a rollback would land here). Counted so "nothing was changed" can be PROVEN.
  if (method === "POST" && /\/workers\/scripts\/[^/]+\/deployments$/.test(url)) {
    deployCalls.push(url);
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }
  throw new TypeError(`unexpected outbound fetch: ${method} ${url}`);
}) as typeof globalThis.fetch;

// RAMP_RECOMMENDED is the ramp's recommendedVersion, and it MUST NOT equal the running ENGINE_VERSION.
// The whole first section below asserts an `inconclusive` settle, and inconclusive is the honest verdict
// precisely because this dispatch's ENGINE_VERSION is not the ramp's recommendedVersion, so the engine
// cannot prove it ran the ramped version's own code. Make the two equal and the settle concludes instead,
// which is a different scenario wearing this one's assertions. A hard-coded constant that silently collides
// with a future release version would break this file in the cross-repo chain, the one place it runs, so
// the guard below asserts the inequality rather than leaving it as a comment. 0.4.0 matches the fixture
// version the other two update-route suites use.
// Held in a widened-type local, the same idiom validate-version-constants-parity.ts uses: compared as
// two string literals, tsc narrows both and folds the comparison away as "no overlap" at compile time,
// which is a check that cannot fail at run time.
const RAMP_RECOMMENDED: string = "0.4.0";
const runningVersion: string = ENGINE_VERSION;
ok(`the ramp's recommendedVersion (${RAMP_RECOMMENDED}) is NOT the running ENGINE_VERSION (${runningVersion}), which is what makes an inconclusive settle the honest verdict`, RAMP_RECOMMENDED !== runningVersion);

// seedRampPending arms the DO with a RAMP-SHAPED pending: `percentage` is the field the ramp start writes and
// the atomic apply never does, and its presence is the whole discriminator.
async function seedRampPending(): Promise<void> {
  await stub.fetch("https://do/update-pending", {
    method: "POST",
    body: JSON.stringify({ fromVersion: PRIOR, toVersion: RAMPED, recommendedVersion: RAMP_RECOMMENDED, percentage: 40, promotedAt: Date.now(), promotedBy: "owner@acme.example" }),
  });
}
const t = new Transport(ENGINE_BASE);

// =====================================================================================================
// 1. THE ROUTE IS REACHABLE FROM THE PRODUCT. The real console client, the real engine route.
// =====================================================================================================
console.log("\n-- the real console ramp-settle client, driven through the real engine route --");
await seedRampPending();

// The status the console's pending card actually reads. The discriminator must survive the wire: if
// `percentage` is not on GET /admin/update/status, the card cannot route and the hole is still open.
{
  const statusResp = await handleAdmin(new Request(`${ENGINE_BASE}/admin/update/status`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
  const rec = (await statusResp.json()) as { pending: { percentage?: number; toVersion?: string } | null };
  ok("GET /admin/update/status carries the ramp discriminator (`percentage`) to the console", rec.pending?.percentage === 40);
  ok("...on the pending the console is about to settle", rec.pending?.toVersion === RAMPED);
}

const before = deployCalls.length;
const r1 = await consoleUpdate.settleRampUpdate(t, DEPLOY_TOKEN);
ok("the console client reached POST /admin/update/ramp/settle (the route nothing called)", engineCalls.includes("POST /admin/update/ramp/settle"));
ok("the console client did NOT reach the plain settle", !engineCalls.includes("POST /admin/update/settle"));
ok("the engine answered the ramp settle 200 with a structured outcome", typeof r1.outcome === "string");
// The settle ran against a still-splitting ramp on a dispatch whose ENGINE_VERSION is not the ramp's
// recommendedVersion, so the engine cannot prove it ran the ramped version's own code: INCONCLUSIVE is the
// honest verdict, and it is the one that leaves the pending armed.
ok("the outcome is `inconclusive` (this dispatch did not land on the ramped slice)", r1.outcome === "inconclusive");
ok("...and it is the RAMP's pending it answered about", r1.toVersion === RAMPED && r1.fromVersion === PRIOR);
ok("an inconclusive settle DEPLOYS NOTHING (nothing was changed, and it can be proven)", deployCalls.length === before);
{
  const statusResp = await handleAdmin(new Request(`${ENGINE_BASE}/admin/update/status`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
  const rec = (await statusResp.json()) as { pending: { toVersion?: string } | null };
  ok("...and the pending stays ARMED, so the operator can simply press the button again", rec.pending?.toVersion === RAMPED);
}

// =====================================================================================================
// 2. THE COUNTER HAS A REACHABLE PRODUCER, READ OUT OF THE PACK'S OWN PROJECTOR.
//
// fetchAdminCounters is the exact function support.ts calls to build the bundle's adminCounters section, so
// this is not a proxy for what a customer's pack would say -- it is what a customer's pack would say.
// =====================================================================================================
console.log("\n-- update-settle-inconclusive: read out of the pack's own adminCounters projector --");
{
  const counters = (await fetchAdminCounters(stub)) as Record<string, { count: number; lastAt?: string }>;
  const c = counters["update-settle-inconclusive"];
  ok("the pack's adminCounters section CARRIES update-settle-inconclusive", c !== undefined);
  ok("the counter moved: a real console click, through the real route, moved it by exactly one", c?.count === 1);
  ok("it carries a lastAt, so 'when did they last try' is answerable", typeof c?.lastAt === "string");
}

// THE COUNTER COUNTS THE OPERATOR TRYING. Three more clicks (which is what the console's retry ladder does on
// an inconclusive verdict, and what an operator does overnight) must show up as three more, so forty overnight
// attempts and zero attempts never produce a byte-identical pack.
for (let i = 0; i < 3; i++) await consoleUpdate.settleRampUpdate(t, DEPLOY_TOKEN);
{
  const counters = (await fetchAdminCounters(stub)) as Record<string, { count: number }>;
  ok("four real console attempts read as four, not as zero", counters["update-settle-inconclusive"]?.count === 4);
  ok("'we tried to settle the ramp all night' is distinguishable from 'nobody touched it'", (counters["update-settle-inconclusive"]?.count ?? 0) > 0);
}

// NO-CUSTODY: the counter is a NAME and an INT, and the pack section it lands in holds nothing else. Prove it
// carries no free text, no version id, no token, no email -- the whole projected row, field by field.
{
  const counters = (await fetchAdminCounters(stub)) as Record<string, Record<string, unknown>>;
  const row = counters["update-settle-inconclusive"] ?? {};
  const keys = Object.keys(row).sort();
  ok("no-custody: the projected row is a count + a timestamp and nothing else", keys.join(",") === "count,lastAt");
  ok("no-custody: the count is an integer", Number.isInteger(row.count));
  const serialised = JSON.stringify(counters);
  ok("no-custody: the deploy token is nowhere in the projected section", !serialised.includes(DEPLOY_TOKEN));
  ok("no-custody: no version id, account id or email leaked into it", !serialised.includes(RAMPED) && !serialised.includes(ACCOUNT) && !serialised.includes("@"));
}

// =====================================================================================================
// 3. THE SIBLING SITE. The SAME ramp-shaped pending, driven through the OTHER console client.
//
// The two settle routes are mutually exclusive and each refuses the other's shape. Making the ramp reachable
// while leaving the plain settle able to act on a ramp's pending would be the same defect, mirrored.
// =====================================================================================================
console.log("\n-- the sibling site: the plain settle client against the same ramp-shaped pending --");
{
  const deploysBefore = deployCalls.length;
  let threw: string | null = null;
  try {
    await consoleUpdate.settleUpdate(t, DEPLOY_TOKEN);
  } catch (err) {
    threw = err instanceof Error ? err.message : String(err);
  }
  ok("the plain settle client REFUSES to settle a ramp's pending (the engine rejects it)", threw !== null);
  ok("...and says which call to make instead", threw !== null && /ramp settle call instead/.test(threw));
  ok("...changing nothing (no deploy)", deployCalls.length === deploysBefore);
  const statusResp = await handleAdmin(new Request(`${ENGINE_BASE}/admin/update/status`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } }), env);
  const rec = (await statusResp.json()) as { pending: { toVersion?: string } | null };
  ok("...and leaving the ramp's pending exactly where it was", rec.pending?.toVersion === RAMPED);
}
// The refused plain settle bumps update-settle-REFUSED, never update-settle-INCONCLUSIVE: the two counters
// mean opposite things (a guard turned the attempt away, versus the settle ran and could not decide) and the
// whole value of the inconclusive counter is that it fires on one branch and no other.
{
  const counters = (await fetchAdminCounters(stub)) as Record<string, { count: number }>;
  ok("the refused plain settle bumped update-settle-refused", (counters["update-settle-refused"]?.count ?? 0) >= 1);
  ok("...and did NOT contaminate update-settle-inconclusive (still exactly the four real attempts)", counters["update-settle-inconclusive"]?.count === 4);
  ok("...and the ramp-shaped guard class is on the record too", (counters["update-refused-ramp-shaped"]?.count ?? 0) >= 1);
}

globalThis.fetch = realFetch;
console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILED`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
