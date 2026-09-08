// flushDigests delivery-path cases of the validate-worker suite (split out of test/validate-worker.ts):
// the cron's digest flush (digest-due -> per-channel deliver ->
// /notify/record -> /notify/digest-sent), proving clear-on-attempt on failure, record/clear on
// success, and the empty-batch no-op. Only the customer webhook POST uses global fetch, stubbed
// per-case; no real network, no deploy.

import { flushDigests } from "../src/index.ts";
import type { DigestBatch, DigestSummary, NotifyChannel } from "../src/notify.ts";
import { ok, makeEnv, makeSchedulerStub, type RecordedCall } from "./validate-worker-helpers.ts";

export async function run(): Promise<void> {
  // -----------------------------------------------------------------------------------------
  // flushDigests DELIVERY PATH (contract section 2). The cron's digest flush
  //     (digest-due -> per-channel deliver -> /notify/record -> /notify/digest-sent) was untested.
  //     We drive the exported flushDigests with an in-memory scheduler stub that returns ONE due
  //     batch and a live enabled channel, and assert BOTH documented outcomes:
  //
  //   (a) FAILED delivery is CLEAR-ON-ATTEMPT (documented at-most-once): when deliverToChannel
  //       returns { ok:false } (we make the customer webhook POST fail by stubbing global fetch to
  //       reject), the batch's pending entries are STILL cleared via /notify/digest-sent carrying the
  //       batch's exact seqs, and a history row is recorded with delivered:false (the failure stays
  //       observable). This bounds the pending store so a permanently-unreachable channel cannot
  //       accumulate digest entries forever.
  //
  //   (b) SUCCESS delivery records and clears the RIGHT seqs: when the POST returns 2xx, /notify/record
  //       carries delivered:true and the channel id/kind, and /notify/digest-sent carries exactly the
  //       batch's seqs.
  //
  // The DO routes go through the injected scheduler stub (never global fetch); ONLY the customer
  // webhook POST inside deliverPayload uses global fetch, which we stub per-case and restore in a
  // finally so no other test is affected and NO real network call is made.
  // -----------------------------------------------------------------------------------------
  {
    // A redaction-safe summary for one batch of two success occurrences across two downpipes.
    const summary: DigestSummary = {
      total: 2,
      byEvent: { "backup-success": 2 },
      downpipeNames: ["Prod KV", "Prod R2"],
      accountLevelCount: 0,
      fromAt: "2026-06-09T00:00:00.000Z",
      toAt: "2026-06-09T00:05:00.000Z",
    };
    const SEQS = [11, 12];
    const batch: DigestBatch = {
      channelId: "ch-digest-1",
      channelKind: "webhook",
      period: "daily",
      summary,
      detail: "Digest: 2 updates (2 backup-success) across Prod KV, Prod R2",
      seqs: SEQS,
    };
    const channel: NotifyChannel = {
      id: "ch-digest-1",
      kind: "webhook",
      name: "SIEM digest",
      url: "https://siem.example.com/digest",
      enabled: true,
      createdAt: "2026-01-01T00:00:00.000Z",
    };

    // Build a scheduler stub that answers the flush's DO routes and records every call. digest-due
    // returns the one batch; /notify/channel returns the live channel; /notify/record and
    // /notify/digest-sent just succeed. The customer webhook POST does NOT come here (it uses global
    // fetch); any unexpected DO route is surfaced as a 500 so a future round-trip cannot pass silently.
    function makeDigestScheduler(): { stub: DurableObjectStub; calls: RecordedCall[] } {
      const calls: RecordedCall[] = [];
      const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
        const path = new URL(url).pathname;
        let body: unknown = undefined;
        if (typeof init?.body === "string") {
          try { body = JSON.parse(init.body); } catch { body = init.body; }
        }
        calls.push({ path, body });
        if (path === "/notify/digest-due") return new Response(JSON.stringify({ batches: [batch] }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/channel") return new Response(JSON.stringify({ channel }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/record") return new Response(JSON.stringify({ recorded: 1 }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/digest-sent") return new Response(JSON.stringify({ cleared: (body as { ids?: unknown[] })?.ids?.length ?? 0 }), { headers: { "content-type": "application/json" } });
        return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
      });
      return { stub, calls };
    }

    // (a) FAILED delivery (deliverToChannel -> { ok:false }) still clears the batch (clear-on-attempt).
    {
      const { stub, calls } = makeDigestScheduler();
      const env = makeEnv(stub);
      const origFetch = globalThis.fetch;
      // Stub global fetch so the customer webhook POST (the ONLY global-fetch use on this path) fails;
      // deliverPayload swallows the throw into { ok:false }. We assert the stub is hit ONLY for the
      // customer url (the DO routes never reach global fetch).
      let webhookHits = 0;
      let nonWebhookHit = false;
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        if (u === channel.url) { webhookHits++; throw new Error("simulated webhook outage"); }
        nonWebhookHit = true;
        throw new Error(`unexpected global fetch to ${u}`);
      }) as typeof fetch;

      let threw = false;
      try {
        await flushDigests(env, stub);
      } catch {
        threw = true;
      } finally {
        globalThis.fetch = origFetch;
      }

      ok("flushDigests does NOT throw on a failed delivery (fail-open)", !threw);
      ok("the customer webhook POST was attempted via global fetch", webhookHits === 1);
      ok("global fetch was used ONLY for the customer webhook (DO routes use the stub)", !nonWebhookHit);
      // A history row IS recorded even for the failed delivery, with delivered:false (observable).
      const recordCall = calls.find((c) => c.path === "/notify/record");
      ok("a /notify/record was posted for the failed delivery", recordCall !== undefined);
      const recBody = recordCall?.body as { records?: Array<{ channelId?: string; channelKind?: string; delivered?: boolean }> } | undefined;
      ok("the recorded delivery is delivered:false (failure stays observable)", recBody?.records?.[0]?.delivered === false);
      ok("the recorded row carries the channel id/kind", recBody?.records?.[0]?.channelId === channel.id && recBody?.records?.[0]?.channelKind === "webhook");
      // CLEAR-ON-ATTEMPT: the pending entries are STILL cleared despite the failed send.
      const sentCall = calls.find((c) => c.path === "/notify/digest-sent");
      ok("/notify/digest-sent WAS posted despite the failed delivery (clear-on-attempt)", sentCall !== undefined);
      const sentIds = (sentCall?.body as { ids?: number[] } | undefined)?.ids ?? [];
      ok("digest-sent clears EXACTLY the batch's seqs", sentIds.length === SEQS.length && SEQS.every((s) => sentIds.includes(s)));
    }

    // (b) SUCCESS delivery records delivered:true and clears the same seqs.
    {
      const { stub, calls } = makeDigestScheduler();
      const env = makeEnv(stub);
      const origFetch = globalThis.fetch;
      let webhookHits = 0;
      globalThis.fetch = (async (input: RequestInfo | URL) => {
        const u = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
        if (u === channel.url) { webhookHits++; return new Response("{}", { status: 200, headers: { "content-type": "application/json" } }); }
        throw new Error(`unexpected global fetch to ${u}`);
      }) as typeof fetch;

      let threw = false;
      try {
        await flushDigests(env, stub);
      } catch {
        threw = true;
      } finally {
        globalThis.fetch = origFetch;
      }

      ok("flushDigests does NOT throw on a successful delivery", !threw);
      ok("the customer webhook POST was made once (2xx)", webhookHits === 1);
      const recordCall = calls.find((c) => c.path === "/notify/record");
      const recBody = recordCall?.body as { emission?: { event?: string; severity?: string }; records?: Array<{ channelId?: string; channelKind?: string; delivered?: boolean }> } | undefined;
      ok("/notify/record posted with delivered:true", recBody?.records?.[0]?.delivered === true);
      ok("the recorded emission is the info-severity digest roll-up", recBody?.emission?.severity === "info");
      ok("the recorded row carries the channel id/kind", recBody?.records?.[0]?.channelId === channel.id && recBody?.records?.[0]?.channelKind === "webhook");
      const sentCall = calls.find((c) => c.path === "/notify/digest-sent");
      const sentIds = (sentCall?.body as { ids?: number[] } | undefined)?.ids ?? [];
      ok("digest-sent clears EXACTLY the batch's seqs", sentIds.length === SEQS.length && SEQS.every((s) => sentIds.includes(s)));
      // The flush passed nowMs to digest-due (the DO has no wall clock).
      const dueCall = calls.find((c) => c.path === "/notify/digest-due");
      ok("digest-due was called with a finite nowMs (DO has no wall clock)", typeof (dueCall?.body as { nowMs?: unknown } | undefined)?.nowMs === "number");
    }

    // (c) EMPTY batches: a near no-op flush makes NO delivery, NO record, NO digest-sent round-trip.
    {
      const calls: RecordedCall[] = [];
      const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
        const path = new URL(url).pathname;
        let body: unknown = undefined;
        if (typeof init?.body === "string") { try { body = JSON.parse(init.body); } catch { body = init.body; } }
        calls.push({ path, body });
        if (path === "/notify/digest-due") return new Response(JSON.stringify({ batches: [] }), { headers: { "content-type": "application/json" } });
        return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
      });
      const env = makeEnv(stub);
      const origFetch = globalThis.fetch;
      let anyFetch = false;
      globalThis.fetch = (async () => { anyFetch = true; throw new Error("no network on an empty flush"); }) as typeof fetch;
      try {
        await flushDigests(env, stub);
      } finally {
        globalThis.fetch = origFetch;
      }
      const paths = calls.map((c) => c.path);
      ok("only /notify/digest-due is called (no delivery, no record, no clear)", paths.length === 1 && paths[0] === "/notify/digest-due");
      ok("no global fetch (no customer POST) on an empty flush", !anyFetch);
    }

    // (d) the channel that deferred this batch's entries no longer exists (/notify/channel returns
    // { channel: null }). This must still record delivered:false, code "no-transport" (the same closed
    // reason the live Slack/webhook adapters use for "no url configured"), and still clear the pending
    // seqs (a permanently gone channel must not accumulate deferrals forever), so the digest never
    // vanishes with no honest trace of the outcome.
    {
      const calls: RecordedCall[] = [];
      const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
        const path = new URL(url).pathname;
        let body: unknown = undefined;
        if (typeof init?.body === "string") {
          try { body = JSON.parse(init.body); } catch { body = init.body; }
        }
        calls.push({ path, body });
        if (path === "/notify/digest-due") return new Response(JSON.stringify({ batches: [batch] }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/channel") return new Response(JSON.stringify({ channel: null }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/record") return new Response(JSON.stringify({ recorded: 1 }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/digest-sent") return new Response(JSON.stringify({ cleared: (body as { ids?: unknown[] })?.ids?.length ?? 0 }), { headers: { "content-type": "application/json" } });
        return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
      });
      const env = makeEnv(stub);
      const origFetch = globalThis.fetch;
      let anyFetch = false;
      globalThis.fetch = (async () => { anyFetch = true; throw new Error("no customer POST for a channel that no longer exists"); }) as typeof fetch;

      let threw = false;
      try {
        await flushDigests(env, stub);
      } catch {
        threw = true;
      } finally {
        globalThis.fetch = origFetch;
      }

      ok("flushDigests does NOT throw when the channel is gone (fail-open)", !threw);
      ok("NO customer POST is attempted (there is no channel to send to)", !anyFetch);
      const recordCall = calls.find((c) => c.path === "/notify/record");
      ok("a /notify/record IS posted even though the channel is gone (B3 fix; previously nothing was)", recordCall !== undefined);
      const recBody = recordCall?.body as { records?: Array<{ channelId?: string; channelKind?: string; delivered?: boolean; code?: string }> } | undefined;
      ok("the recorded outcome is delivered:false", recBody?.records?.[0]?.delivered === false);
      ok('the recorded outcome carries code "no-transport" (never a bare, unexplained failure)', recBody?.records?.[0]?.code === "no-transport");
      ok("the recorded row carries the BATCH's own channel id/kind (the channel record itself is gone)", recBody?.records?.[0]?.channelId === batch.channelId && recBody?.records?.[0]?.channelKind === batch.channelKind);
      // The pending entries are STILL cleared (a permanently gone channel cannot accumulate forever).
      const sentCall = calls.find((c) => c.path === "/notify/digest-sent");
      ok("/notify/digest-sent WAS posted despite the missing channel (bounds the pending store)", sentCall !== undefined);
      const sentIds = (sentCall?.body as { ids?: number[] } | undefined)?.ids ?? [];
      ok("digest-sent clears EXACTLY the batch's seqs", sentIds.length === SEQS.length && SEQS.every((s) => sentIds.includes(s)));
    }

    // (e) the sibling branch: the channel still exists but is DISABLED. Same undeliverable outcome as a
    // deleted channel (both are the one `!channel?.enabled` condition in deliverDigestBatch).
    {
      const disabledChannel: NotifyChannel = { ...channel, enabled: false };
      const calls: RecordedCall[] = [];
      const stub = makeSchedulerStub(async (url: string, init?: RequestInit) => {
        const path = new URL(url).pathname;
        let body: unknown = undefined;
        if (typeof init?.body === "string") {
          try { body = JSON.parse(init.body); } catch { body = init.body; }
        }
        calls.push({ path, body });
        if (path === "/notify/digest-due") return new Response(JSON.stringify({ batches: [batch] }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/channel") return new Response(JSON.stringify({ channel: disabledChannel }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/record") return new Response(JSON.stringify({ recorded: 1 }), { headers: { "content-type": "application/json" } });
        if (path === "/notify/digest-sent") return new Response(JSON.stringify({ cleared: (body as { ids?: unknown[] })?.ids?.length ?? 0 }), { headers: { "content-type": "application/json" } });
        return new Response(JSON.stringify({ unexpected: path }), { status: 500, headers: { "content-type": "application/json" } });
      });
      const env = makeEnv(stub);
      const origFetch = globalThis.fetch;
      let anyFetch = false;
      globalThis.fetch = (async () => { anyFetch = true; throw new Error("no customer POST for a disabled channel"); }) as typeof fetch;

      try {
        await flushDigests(env, stub);
      } finally {
        globalThis.fetch = origFetch;
      }

      ok("NO customer POST is attempted (the channel is disabled)", !anyFetch);
      const recordCall = calls.find((c) => c.path === "/notify/record");
      ok("a /notify/record IS posted for the disabled channel (B3 fix)", recordCall !== undefined);
      const recBody = recordCall?.body as { records?: Array<{ delivered?: boolean; code?: string }> } | undefined;
      ok("the recorded outcome is delivered:false", recBody?.records?.[0]?.delivered === false);
      ok('the recorded outcome carries code "no-transport"', recBody?.records?.[0]?.code === "no-transport");
      const sentCall = calls.find((c) => c.path === "/notify/digest-sent");
      ok("/notify/digest-sent still clears the batch's seqs despite the disabled channel", sentCall !== undefined);
    }
  }
}
