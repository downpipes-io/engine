// The per-credential 429 on GET /support/audit-feed, and the
// structured JSON error bodies the 401/503 paths on /support/* now carry (see support-ingest.ts,
// ingestPullRateLimited/INGEST_PULL_RATE_LIMIT_MAX_PER_WINDOW, and the five call sites converted from
// bare text: the empty-bearer 401, the refused-credential 401, the grant-unreadable 503, and the two
// audit-export-failed 503s).
//
// THE RIG. Section A drives handleSupportPull against a REAL SchedulerDO (src/sched/scheduler-do.ts)
// over MockStorage, the same rig test/validate-ingest-pull-refusal-class.ts and
// test/validate-destsim-auditfeed-abuse.ts use, so the 429 is proven against the DO's own rateCheck,
// never a hand-rolled double of it. The rate-limit WINDOW is not waited out: the DO's own storage
// key (RATE_LIMIT_PREFIX + "ingest:<clientId>") is seeded directly at (or just under) the cap, the
// same dose-injection technique test/validate-ingest-pull-refusal-class.ts uses for grant expiry, so
// the test proves the boundary without 120 real round trips or a real 60-second wait.
//
// Section D drives the JSON-body conversions with small hand-rolled stubs (matching
// test/validate-destsim-cursor.ts's schedulerFor and test/validate-support.ts's throwingStub
// patterns), because those paths need the DO to answer specific ways (a thrown grant lookup, a
// non-ok export response, a thrown export) that are cheaper to fake directly than to provoke on a
// real DO.
//
// Run: node test/validate-ingest-pull-rate-limit.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { handleSupportPull, mintIngestCredential, type IngestGrant } from "../src/admin/support-ingest.ts";
import { fetchAdminCounters } from "../src/admin/support-sections-diag.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const EMPTY_ENV = {} as unknown as Env;

// The engine-side cap this file pins (support-ingest.ts's INGEST_PULL_RATE_LIMIT_MAX_PER_WINDOW,
// private to that module): 120 successful audit-feed pulls per clientId per 60-second window,
// matching the admin front door's own budget in shape (router-core.ts, RATE_LIMIT_MAX_PER_WINDOW).
const CAP = 120;

// asStub adapts a real SchedulerDO to the DurableObjectStub shape handleSupportPull expects (the same
// helper test/validate-ingest-pull-refusal-class.ts and test/validate-destsim-auditfeed-abuse.ts use).
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

async function settle(): Promise<void> {
  for (let i = 0; i < 8; i++) await new Promise((r) => setTimeout(r, 0));
}

function pull(scope: "audit-feed" | "diagnostics", bearer: string | null): Request {
  return new Request(`https://engine.example/support/${scope}`, bearer === null ? {} : { headers: { Authorization: `Bearer ${bearer}` } });
}

async function counters(stub: DurableObjectStub): Promise<Record<string, { count: number; lastAt?: string }>> {
  return fetchAdminCounters(stub);
}

async function main(): Promise<void> {
  // ------------------------------------------------------------------------------------------------------
  // A. THE 429 SHAPE, seeded at the boundary on a REAL SchedulerDO.
  // ------------------------------------------------------------------------------------------------------
  console.log("A -- the 429 shape at the per-credential cap boundary");
  {
    const { storage, stub } = makeScheduler();
    const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
    await storage.put("ingestcred:audit-feed", minted.grant);
    const bearer = `${minted.clientId}.${minted.secret}`;

    // Seed the DO's own rate-limit bucket already AT the cap (a fresh window opened "now"), so the very
    // next pull is the one that tips it over -- the real boundary, not a fabricated response.
    await storage.put(`ratelimit:ingest:${minted.clientId}`, { windowStart: Date.now(), count: CAP });

    const resp = await handleSupportPull(pull("audit-feed", bearer), EMPTY_ENV, stub);
    ok("A the boundary-tipping pull is refused 429", resp.status === 429);
    ok("A the body is application/problem+json", resp.headers.get("content-type") === "application/problem+json");

    const body = (await resp.json()) as { type?: string; title?: string; status?: number; error?: string };
    ok("A RFC 9457: type is the rate-limited urn", body.type === "urn:downpipe:error:rate-limited");
    ok("A RFC 9457: title is Rate limited", body.title === "Rate limited");
    ok("A RFC 9457: status echoes 429", body.status === 429);
    ok('A the legacy error field is the published wire contract "rate limited"', body.error === "rate limited");

    const retryAfter = Number(resp.headers.get("retry-after"));
    ok("A Retry-After is present and a whole number of seconds", Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 60);

    const rl = resp.headers.get("ratelimit");
    ok("A the advisory RateLimit header carries the ceiling that actually refused (120)", rl?.includes(`limit=${CAP}`) === true && rl.includes("remaining=0"));
    const rlPolicy = resp.headers.get("ratelimit-policy");
    ok("A the advisory RateLimit-Policy header states the 120-per-60s policy", rlPolicy === `${CAP};w=60`);

    await settle();
    const c = await counters(stub);
    ok("A the new ingest-pull-rate-limited counter books exactly 1", c["ingest-pull-rate-limited"]?.count === 1);
    ok("A the generic ingest-pull-auth-failed counter is NOT touched (this is not an auth refusal)", c["ingest-pull-auth-failed"] === undefined);

    // A refused (over-budget) pull must never look, to the customer, like a served one: the pull trail
    // (grant.pulls) is checked BEFORE the trail write, so a 429 leaves it untouched.
    const after = (await (await stub.fetch("https://do/ingest-credential?scope=audit-feed")).json()) as { grant: IngestGrant };
    ok("A a rate-limited pull is NOT recorded on the customer-visible pull trail", after.grant.pulls.length === 0);
  }

  // ------------------------------------------------------------------------------------------------------
  // B. JUST UNDER THE CAP: the pull is served normally, and nothing rate-limit-shaped books.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nB -- one pull under the cap is served normally");
  {
    const { storage, stub } = makeScheduler();
    const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
    await storage.put("ingestcred:audit-feed", minted.grant);
    const bearer = `${minted.clientId}.${minted.secret}`;
    await storage.put(`ratelimit:ingest:${minted.clientId}`, { windowStart: Date.now(), count: CAP - 1 });

    const resp = await handleSupportPull(pull("audit-feed", bearer), EMPTY_ENV, stub);
    ok("B a pull that lands exactly on the cap (not over it) is served, 200", resp.status === 200);
    await settle();
    const c = await counters(stub);
    ok("B the rate-limited counter is ABSENT, not zero (nothing was refused)", c["ingest-pull-rate-limited"] === undefined);
    const after = (await (await stub.fetch("https://do/ingest-credential?scope=audit-feed")).json()) as { grant: IngestGrant };
    ok("B a served pull IS recorded on the trail", after.grant.pulls.length === 1);
  }

  // ------------------------------------------------------------------------------------------------------
  // C. SCOPE: the diagnostics leg is deliberately NOT budget-capped (a vendor's manual pull cannot
  //    realistically hit a per-window cap the way a scheduled SIEM poller can). Proven by saturating the
  //    SAME clientId's bucket and showing a diagnostics pull is unaffected.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nC -- the diagnostics leg is not subject to the audit-feed budget");
  {
    const { storage, stub } = makeScheduler();
    const minted = await mintIngestCredential("diagnostics", "owner@example.test", 3600);
    await storage.put("ingestcred:diagnostics", minted.grant);
    const bearer = `${minted.clientId}.${minted.secret}`;
    // Saturate what WOULD be this clientId's ingest-pull bucket, exactly as section A's boundary case did.
    await storage.put(`ratelimit:ingest:${minted.clientId}`, { windowStart: Date.now(), count: CAP });

    const resp = await handleSupportPull(pull("diagnostics", bearer), EMPTY_ENV, stub);
    ok("C a diagnostics pull is served even with a saturated ingest bucket for the same clientId", resp.status === 200);
    await settle();
    const c = await counters(stub);
    ok("C no rate-limited refusal is booked for the diagnostics leg", c["ingest-pull-rate-limited"] === undefined);
  }

  // ------------------------------------------------------------------------------------------------------
  // D. STRUCTURED JSON ERROR BODIES on the five 401/503 call sites converted here.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nD -- the 401/503 bodies are now JSON, carrying an error field");
  async function assertJsonError(resp: Response, status: number, error: string, label: string): Promise<void> {
    ok(`D ${label}: status ${status}`, resp.status === status);
    ok(`D ${label}: content-type is application/json`, resp.headers.get("content-type") === "application/json");
    const body = (await resp.json()) as { error?: string };
    ok(`D ${label}: body carries error="${error}"`, body.error === error);
  }

  // D1: an empty bearer -> 401 (the pre-DO short-circuit).
  {
    const { stub } = makeScheduler();
    const resp = await handleSupportPull(pull("audit-feed", null), EMPTY_ENV, stub);
    await assertJsonError(resp, 401, "unauthorised", "empty bearer");
  }

  // D2: the grant lookup THROWS -> 503 (grant-unreadable, fail-closed).
  {
    const throwingStub = {
      fetch: async (input: RequestInfo | URL): Promise<Response> => {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/ingest-credential") throw new Error("DO unavailable");
        return new Response(JSON.stringify({}));
      },
    } as unknown as DurableObjectStub;
    const resp = await handleSupportPull(pull("audit-feed", "dpc_x.dps_y"), EMPTY_ENV, throwingStub);
    await assertJsonError(resp, 503, "unavailable", "grant lookup throws");
  }

  // D3: a wrong secret -> 401 (the refused-credential path).
  {
    const { storage, stub } = makeScheduler();
    const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
    await storage.put("ingestcred:audit-feed", minted.grant);
    const resp = await handleSupportPull(pull("audit-feed", `${minted.clientId}.dps_wrong`), EMPTY_ENV, stub);
    await assertJsonError(resp, 401, "unauthorised", "wrong secret");
  }

  // D4: the audit export DO answers non-ok -> 503.
  {
    const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
    const grant = minted.grant;
    const stub = {
      fetch: async (input: RequestInfo | URL): Promise<Response> => {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/ingest-credential") return new Response(JSON.stringify({ grant }), { headers: { "content-type": "application/json" } });
        if (u.pathname === "/ingest-credential/record-pull") return new Response("{}");
        if (u.pathname === "/rate-check") return new Response(JSON.stringify({ allowed: true, retryAfterMs: 0 }));
        if (u.pathname === "/audit/export") return new Response("", { status: 500 });
        return new Response("{}");
      },
    } as unknown as DurableObjectStub;
    const resp = await handleSupportPull(pull("audit-feed", `${grant.clientId}.${minted.secret}`), EMPTY_ENV, stub);
    await assertJsonError(resp, 503, "unavailable", "export answers non-ok");
  }

  // D5: the audit export DO fetch THROWS -> 503.
  {
    const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
    const grant = minted.grant;
    const stub = {
      fetch: async (input: RequestInfo | URL): Promise<Response> => {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/ingest-credential") return new Response(JSON.stringify({ grant }), { headers: { "content-type": "application/json" } });
        if (u.pathname === "/ingest-credential/record-pull") return new Response("{}");
        if (u.pathname === "/rate-check") return new Response(JSON.stringify({ allowed: true, retryAfterMs: 0 }));
        if (u.pathname === "/audit/export") throw new Error("DO unavailable");
        return new Response("{}");
      },
    } as unknown as DurableObjectStub;
    const resp = await handleSupportPull(pull("audit-feed", `${grant.clientId}.${minted.secret}`), EMPTY_ENV, stub);
    await assertJsonError(resp, 503, "unavailable", "export fetch throws");
  }

  // ------------------------------------------------------------------------------------------------------
  // E. FAIL OPEN: an unreadable /rate-check verdict (malformed body, or a thrown fetch) must never turn
  //    an engine-side limiter fault into a collector-visible outage -- the same posture router-core.ts's
  //    rateLimited uses for the admin caller limiter.
  // ------------------------------------------------------------------------------------------------------
  console.log("\nE -- fail open when the limiter itself cannot answer");
  {
    const minted = await mintIngestCredential("audit-feed", "owner@example.test", 3600);
    const grant = minted.grant;
    const malformedStub = {
      fetch: async (input: RequestInfo | URL): Promise<Response> => {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/ingest-credential") return new Response(JSON.stringify({ grant }), { headers: { "content-type": "application/json" } });
        if (u.pathname === "/rate-check") return new Response("{}"); // no `allowed` field at all
        if (u.pathname === "/audit/export") return new Response(JSON.stringify({ events: [], headSeq: 0, headHash: "sha384:0" }), { headers: { "content-type": "application/json" } });
        return new Response("{}");
      },
    } as unknown as DurableObjectStub;
    const resp1 = await handleSupportPull(pull("audit-feed", `${grant.clientId}.${minted.secret}`), EMPTY_ENV, malformedStub);
    ok("E a malformed rate-check verdict admits the pull (200), not a 429", resp1.status === 200);

    const throwingRateCheckStub = {
      fetch: async (input: RequestInfo | URL): Promise<Response> => {
        const u = new URL(input instanceof Request ? input.url : String(input));
        if (u.pathname === "/ingest-credential") return new Response(JSON.stringify({ grant }), { headers: { "content-type": "application/json" } });
        if (u.pathname === "/rate-check") throw new Error("DO unavailable");
        if (u.pathname === "/audit/export") return new Response(JSON.stringify({ events: [], headSeq: 0, headHash: "sha384:0" }), { headers: { "content-type": "application/json" } });
        return new Response("{}");
      },
    } as unknown as DurableObjectStub;
    const resp2 = await handleSupportPull(pull("audit-feed", `${grant.clientId}.${minted.secret}`), EMPTY_ENV, throwingRateCheckStub);
    ok("E a thrown rate-check admits the pull (200), not a 429", resp2.status === 200);
  }

  console.log(failures === 0 ? "\nINGEST PULL RATE LIMIT + JSON ERROR BODIES PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
