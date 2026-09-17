// destsim STORM test: drives the REAL Worker entrypoint (src/index.ts) inside a REAL workerd isolate
// (vitest-pool-workers, mirroring test/vitest/worker-entry.test.ts's SELF.fetch pattern) against the
// SIEM audit-feed pull (/support/audit-feed) and the Prometheus scrape (/metrics) CONCURRENTLY, to
// prove the two pull surfaces this destsim build hardens do not crash or tear under parallel access
// against the REAL SchedulerDO (SQLite-backed workerd storage, not MockStorage) -- the one thing the
// Node validators (test/validate-destsim-auditfeed-abuse.ts, test/validate-destsim-metrics-abuse.ts)
// cannot reach, since they run entirely in Node against MockStorage.
//
// Setup seeds credentials/downpipes/audit events DIRECTLY on the singleton scheduler DO
// (env.SCHEDULER.idFromName("account-scheduler"), the SAME resolution schedulerStub() uses,
// src/admin/router-helpers.ts) via its internal routes -- exactly the technique the Node validators'
// fetchDO/asStub helpers use against their MockStorage-backed doubles, here against the REAL DO
// instead. Everything (seed + storm) lives in ONE test so nothing depends on vitest-pool-workers'
// per-test storage isolation semantics either way.
//
// Run: npm run test:vitest (test/vitest/**/*.test.ts, vitest.config.ts)

import { SELF, env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { encodeCaller, type Caller } from "../../src/admin/identity.ts";
import { mintIngestCredential } from "../../src/admin/support-ingest.ts";
import type { AuditDraft } from "../../src/admin/audit.ts";

const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
const OWNER_HEADER = encodeCaller(OWNER_CALLER);

function schedulerStub(): DurableObjectStub {
  const id = env.SCHEDULER.idFromName("account-scheduler");
  return env.SCHEDULER.get(id);
}

// doFetch is the internal-RPC helper (mirrors test/validate-metrics.ts's fetchDO, against the REAL DO
// instead of a MockStorage-backed one): builds the scheduler.internal Request the DO's route() expects.
async function doFetch(path: string, opts?: { method?: string; body?: unknown; caller?: string }): Promise<Response> {
  const headers: Record<string, string> = {
    ...(opts?.body !== undefined ? { "content-type": "application/json" } : {}),
    ...(opts?.caller !== undefined ? { "x-downpipe-caller": opts.caller } : {}),
  };
  return schedulerStub().fetch(`https://scheduler.internal${path}`, {
    method: opts?.method ?? "GET",
    headers,
    ...(opts?.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  });
}

describe("destsim pull-consumer storm (real workerd + real SchedulerDO)", () => {
  it("concurrent /metrics scrapes and /support/audit-feed pulls survive parallel access with stable results", async () => {
    // ---- seed: a small fleet, a modest audit chain, and both ingest credentials ----
    for (let i = 0; i < 3; i++) {
      const resp = await doFetch("/downpipes", {
        method: "POST",
        caller: OWNER_HEADER,
        body: { id: `storm-dp${i}`, name: `Storm ${i}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_storm${i}`, include: [], exclude: [] } },
      });
      expect(resp.status).toBe(200);
    }

    const draft: AuditDraft = { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "role-change", outcome: "success", target: { kind: "access-policy" } };
    for (let i = 0; i < 20; i++) {
      const resp = await doFetch("/audit", { method: "POST", body: draft });
      expect(resp.status).toBe(200);
    }

    const metrics = await mintIngestCredential("metrics", "owner@example.com.au", undefined);
    const metricsSet = await doFetch("/ingest-credential/set", { method: "POST", caller: OWNER_HEADER, body: { scope: "metrics", grant: metrics.grant } });
    expect(metricsSet.status).toBe(200);
    const metricsBearer = `${metrics.clientId}.${metrics.secret}`;

    const feed = await mintIngestCredential("audit-feed", "owner@example.com.au", undefined);
    const feedSet = await doFetch("/ingest-credential/set", { method: "POST", caller: OWNER_HEADER, body: { scope: "audit-feed", grant: feed.grant } });
    expect(feedSet.status).toBe(200);
    const auditFeedBearer = `${feed.clientId}.${feed.secret}`;

    // ---- storm: fire 8 concurrent scrapes + 8 concurrent pulls (varying limits) through the REAL
    // Worker entrypoint (SELF.fetch), genuinely overlapping (a single Promise.all, not sequential
    // awaits) ----
    const scrapes = Array.from({ length: 8 }, () => SELF.fetch("https://engine.test/metrics", { headers: { Authorization: `Bearer ${metricsBearer}` } }));
    const pulls = Array.from({ length: 8 }, (_, i) => SELF.fetch(`https://engine.test/support/audit-feed?afterSeq=0&limit=${5 + i}`, { headers: { Authorization: `Bearer ${auditFeedBearer}` } }));
    const results = await Promise.all([...scrapes, ...pulls]);

    // No crash: every one of the 16 concurrent requests resolved to a clean 200 (no throw, no 5xx).
    for (const r of results) expect(r.status).toBe(200);

    const scrapeResults = results.slice(0, 8);
    const pullResults = results.slice(8);

    // Every scrape parses as Prometheus exposition carrying the canonical families, and (unchanged
    // state, genuinely concurrent reads) every scrape body is byte-identical.
    const scrapeTexts = await Promise.all(scrapeResults.map((r) => r.text()));
    for (const t of scrapeTexts) {
      expect(t).toContain("# TYPE downpipe_backup_success gauge");
      expect(t).toContain('downpipe_id="storm-dp0"');
    }
    expect(scrapeTexts.every((t) => t === scrapeTexts[0])).toBe(true);

    // Every pull parses as a valid feed envelope: ascending contiguous seqs, none <= its own afterSeq.
    interface FeedEnvelope {
      afterSeq: number;
      count: number;
      events: Array<{ seq: number }>;
    }
    const pullBodies = (await Promise.all(pullResults.map((r) => r.json()))) as FeedEnvelope[];
    for (const b of pullBodies) {
      expect(b.events.length).toBe(b.count);
      expect(b.events.every((e) => e.seq > b.afterSeq)).toBe(true);
      expect(b.events.every((e, i) => i === 0 || e.seq === b.events[i - 1]!.seq + 1)).toBe(true);
    }

    // ---- two IDENTICAL-parameter pulls, fired concurrently (not sequentially): byte-identical bodies,
    // proving no torn/interleaved read under concurrent access to the same window ----
    const [a, b] = await Promise.all([
      SELF.fetch("https://engine.test/support/audit-feed?afterSeq=0&limit=1000", { headers: { Authorization: `Bearer ${auditFeedBearer}` } }),
      SELF.fetch("https://engine.test/support/audit-feed?afterSeq=0&limit=1000", { headers: { Authorization: `Bearer ${auditFeedBearer}` } }),
    ]);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    const [ta, tb] = await Promise.all([a.text(), b.text()]);
    expect(ta).toBe(tb);
  });
});
