// Pins Splunk HEC ACCEPTANCE handling on the SIEM audit-log push sender, and the cursor behaviour behind it.
//
// WHAT THIS PINS. Splunk's HTTP Event Collector states its own status in the response BODY, not in the HTTP
// status: the documented envelope is {"text":"...","code":N} and code 0 is the only value that means the batch
// was taken. Before this fix deliverSiemPush did `void resp.body?.cancel()` on every response and returned
// ok:true for any 2xx, so a 200 carrying a NON-ZERO code was recorded as a clean delivery and the cursor
// advanced PAST audit events HEC had positively refused. Those events are never re-sent: silent, permanent
// audit-log loss on the one feed a compliance record depends on. The same cancel also discarded the payload
// that says WHICH refusal a non-2xx was, so every HEC 400 collapsed to http-bad-request.
//
// This validator asserts four things:
//   1. a HEC error payload behind a 2xx is now VISIBLE (a closed hec-declined-* class), not discarded;
//   2. it holds the cursor, so those events are RE-SENT rather than skipped (the at-least-once half);
//   3. the happy path is byte-identical (code 0 sets no class, and an UNREADABLE answer never manufactures a
//      failure -- it rides as an ok:true caveat, the same shape OTLP finding F1 settled on);
//   4. no OTHER format's result changed at all, because the body is only read where the contract is known.
//
// WHAT IT DOES NOT CLAIM. Acceptance is not indexing. A HEC that answers code 0 and then drops the events to a
// deleted index, a discarding routing transform, or a blocked indexer queue has still accepted, and nothing
// here can see that. Confirming an event was indexed needs HEC's own indexer acknowledgement (a request
// channel plus an ack poll), which is deliberately not built. This file pins the boundary of what the
// drain can honestly say.
//
// PRECEDENT: the OTLP push sender had the same class of bug (a 200 read as full success while
// partial_success said otherwise), fixed the same way in notify/otlp-push-sender.ts and pinned by
// test/validate-destsim-otlp-partial.ts.
//
// Run: node test/validate-hec-acceptance.ts

import { fetchSiemPush } from "../src/admin/support-sections-push.ts";
import { deliverSiemPush, HEC_BODY_CLASSES } from "../src/notify/siem-push-sender.ts";
import { deliverResolvedPush, runSiemPushPass, type ResolvedPushConfig } from "../src/cron/siem-push-pass.ts";
import type { AuditEvent } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { startEmulator } from "./destsim/server.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log((cond ? "  ok   " : "  FAIL ") + label);
  if (!cond) failures++;
}

// A PUBLIC-looking endpoint, because deliverSiemPush re-screens the host at send time and REFUSES loopback by
// design (there is no internal-sink override on a push destination). That is why destsim's live server cannot
// be reached through the sender, and why this file stubs fetch -- the same reason and the same shape as
// test/validate-destsim-otlp-partial.ts. The BYTES the stub returns are taken from destsim below, so the
// fixture is the emulator's real wire output rather than a hand-written guess.
const PUBLIC_HEC_URL = "https://splunk.example-stack.test/services/collector";

const HEC_BODY = "application/json";

async function withStubbedFetch(responder: () => Response, body: () => Promise<void>): Promise<void> {
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async () => responder()) as typeof fetch;
  try {
    await body();
  } finally {
    globalThis.fetch = realFetch;
  }
}

// hec sends one batch to the stubbed sink with the HEC envelope reading ON (what cfg.format "splunk-hec" does).
async function hec(status: number, body: string, init?: ResponseInit): Promise<{ ok: boolean; status?: number; code?: string }> {
  let out: { ok: boolean; status?: number; code?: string } = { ok: false };
  await withStubbedFetch(
    () => new Response(body, { status, ...init }),
    async () => {
      const r = await deliverSiemPush(PUBLIC_HEC_URL, '{"event":{}}', HEC_BODY, "Authorization", "Splunk tok", { hecEnvelope: true });
      out = { ok: r.ok, ...(r.status !== undefined ? { status: r.status } : {}), ...(r.code !== undefined ? { code: r.code } : {}) };
    },
  );
  return out;
}

// plain sends the same batch with the envelope reading OFF (every non-splunk-hec format).
async function plain(status: number, body: string): Promise<{ ok: boolean; status?: number; code?: string }> {
  let out: { ok: boolean; status?: number; code?: string } = { ok: false };
  await withStubbedFetch(
    () => new Response(body, { status }),
    async () => {
      const r = await deliverSiemPush(PUBLIC_HEC_URL, '{"event":{}}', HEC_BODY, "Authorization", "tok");
      out = { ok: r.ok, ...(r.status !== undefined ? { status: r.status } : {}), ...(r.code !== undefined ? { code: r.code } : {}) };
    },
  );
  return out;
}

function fakeEvent(seq: number): AuditEvent {
  return {
    seq,
    ts: new Date(1_700_000_000_000 + seq * 1000).toISOString(),
    actorSubject: "https://acct.cloudflareaccess.com|sub-of-owner@example.com",
    actorEmail: "owner@example.com",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "dest-config-set",
    outcome: "success",
    target: { kind: "access-policy" },
    prevHash: `sha384:${"a".repeat(96)}`,
    hash: `sha384:${"b".repeat(96)}`,
  } as AuditEvent;
}

async function main(): Promise<void> {
  // ---- 0. Ground the fixture in destsim, so the "200 with a HEC error payload" shape is the emulator's own
  //         wire output and not something invented here. destsim's status fault serves it under content-type
  //         text/plain, which is itself worth having: the reader must classify by CONTENT, never by the
  //         response's content-type (destsim's wrong-content-type fault exists because a real endpoint can
  //         serve its ack under a type nobody expects).
  console.log("\ndestsim grounding: a 200 carrying a HEC error payload is a real wire response");
  let declinedIndexBody = "";
  {
    const em = await startEmulator({ format: "splunk-hec" });
    try {
      em.setFault({ kind: "status", code: 200, body: JSON.stringify({ text: "Incorrect index", code: 7 }) });
      const resp = await fetch(`${em.url}`, { method: "POST", headers: { "content-type": HEC_BODY }, body: '{"time":1,"source":"downpipes","sourcetype":"downpipe:audit","event":{}}' });
      declinedIndexBody = await resp.text();
      ok("destsim can answer 200 while its body declares a non-zero HEC code", resp.status === 200);
      ok(`destsim's body declares code 7 (got ${JSON.stringify(declinedIndexBody)})`, (JSON.parse(declinedIndexBody) as { code?: unknown }).code === 7);
      ok("destsim serves that ack under a content-type that is NOT application/json, so the reader cannot key off it", (resp.headers.get("content-type") ?? "").includes("application/json") === false);
    } finally {
      await em.close();
    }
  }

  // ---- 1. THE DEFECT. A 2xx whose body declares a non-zero code used to return ok:true and advance the
  //         cursor. It must now be visible AND must fail, so the cursor holds and the events are re-sent.
  console.log("\nTHE DEFECT: a HEC error payload behind a 2xx is visible, and holds the cursor");
  {
    const r = await hec(200, declinedIndexBody);
    ok("200 + code 7 (incorrect index): the payload is VISIBLE as hec-declined-index, not discarded", r.code === "hec-declined-index");
    ok("200 + code 7: ok:false, so the cursor holds and those audit events are re-sent (was ok:true)", r.ok === false);
    ok("200 + code 7: the real HTTP status is still reported (200), so the trail does not lie about the wire", r.status === 200);
  }

  // ---- 2. Every documented refusal class, grouped by the operator action rather than by the raw number. A
  //         future code Splunk adds must fall to the residual, never out of the vocabulary into a success.
  console.log("\nevery non-zero code is a refusal, grouped by the operator action");
  {
    const cases: Array<[number, string, string]> = [
      [7, "Incorrect index", "hec-declined-index"],
      [1, "Token disabled", "hec-declined-token"],
      [2, "Token is required", "hec-declined-token"],
      [3, "Invalid authorization", "hec-declined-token"],
      [4, "Invalid token", "hec-declined-token"],
      [16, "Query string authorization is not enabled", "hec-declined-token"],
      [5, "No data", "hec-declined-format"],
      [6, "Invalid data format", "hec-declined-format"],
      [12, "Event field is required", "hec-declined-format"],
      [13, "Event field cannot be blank", "hec-declined-format"],
      [10, "Data channel is missing", "hec-declined-channel"],
      [11, "Invalid data channel", "hec-declined-channel"],
      [14, "ACK is disabled", "hec-declined-channel"],
      [9, "Server is busy", "hec-declined-busy"],
      [8, "Internal server error", "hec-declined-other"],
      [999, "a code Splunk has not shipped yet", "hec-declined-other"],
    ];
    for (const [code, text, want] of cases) {
      const r = await hec(200, JSON.stringify({ text, code }));
      ok(`200 + code ${code} -> ok:false, ${want}`, r.ok === false && r.code === want);
    }
    ok("every class the sender can emit is inside the closed HEC_BODY_CLASSES allow-list", cases.every(([, , want]) => HEC_BODY_CLASSES.has(want)));
  }

  // ---- 3. THE HAPPY PATH IS UNCHANGED. code 0 sets no class at all, so a healthy drain's trail stays quiet.
  console.log("\nthe happy path is byte-identical: code 0 sets no class");
  {
    const r = await hec(200, JSON.stringify({ text: "Success", code: 0 }));
    ok('200 + {"text":"Success","code":0}: ok:true, status 200, and NO code rides', r.ok === true && r.status === 200 && r.code === undefined);
    const r2 = await hec(201, JSON.stringify({ text: "Success", code: 0 }));
    ok("any other 2xx + code 0 is likewise clean", r2.ok === true && r2.code === undefined);
  }

  // ---- 4. AN UNREADABLE ANSWER MUST NEVER MANUFACTURE A FAILURE. It is a caveat on an ok:true row, not a
  //         refusal: inventing a failure from silence would retry-storm a healthy sink. This is the exact
  //         asymmetry F1 settled for OTLP, kept identical here.
  console.log("\nan answer we could not read is a caveat on success, never a manufactured failure");
  {
    const absent = await hec(200, "");
    ok("200 + empty body: ok:TRUE with hec-body-absent (accepted, but we could not confirm)", absent.ok === true && absent.code === "hec-body-absent");
    const html = await hec(200, "<html>not json</html>", { headers: { "content-type": "text/html" } });
    ok("200 + non-JSON body: ok:TRUE with hec-body-unparseable", html.ok === true && html.code === "hec-body-unparseable");
    const noCode = await hec(200, JSON.stringify({ text: "Success" }));
    ok('200 + {"text":"Success"} with NO code: unparseable, never coerced to 0', noCode.ok === true && noCode.code === "hec-body-unparseable");
    const stringCode = await hec(200, JSON.stringify({ text: "Success", code: "0" }));
    ok('200 + a STRING code "0": unparseable, never coerced to 0 (the anti-coercion rule)', stringCode.ok === true && stringCode.code === "hec-body-unparseable");
    const nullCode = await hec(200, JSON.stringify({ text: "Success", code: null }));
    ok("200 + a null code: unparseable, never coerced to 0", nullCode.ok === true && nullCode.code === "hec-body-unparseable");
    const nanCode = await hec(200, '{"text":"Success","code":1e999}');
    ok("200 + a non-finite code: unparseable, never coerced", nanCode.ok === true && nanCode.code === "hec-body-unparseable");
    const truncated = await hec(200, '{"text":"Success","code":0');
    ok("200 + a truncated JSON body: unparseable, no throw", truncated.ok === true && truncated.code === "hec-body-unparseable");
    // The bounded read is a REAL bound on bytes taken off the socket, so a refusal past the cap is not
    // reached. That is a deliberate limit, and pinning it means nobody later reads an oversized body as clean.
    const oversized = await hec(200, `{"text":"pad","code":7,"pad":"${"x".repeat(20000)}"}`);
    ok("200 + a body past the 16 KiB read cap: ok:TRUE with hec-body-oversized (the cap bounds the READ)", oversized.ok === true && oversized.code === "hec-body-oversized");
  }

  // ---- 5. A NON-2XX. The payload now names WHICH refusal it was, but a body we could not read must not
  //         displace the HTTP classification (that would be a strictly weaker fact).
  console.log("\na non-2xx: the payload sharpens the reason, but never weakens it");
  {
    const sharpened = await hec(400, JSON.stringify({ text: "Incorrect index", code: 7 }));
    ok("400 + code 7: hec-declined-index, not the collapsed http-bad-request", sharpened.ok === false && sharpened.code === "hec-declined-index");
    const ackOff = await hec(400, JSON.stringify({ text: "ACK is disabled", code: 14 }));
    ok("400 + code 14: hec-declined-channel (a different operator action from a refused index)", ackOff.ok === false && ackOff.code === "hec-declined-channel");
    const empty400 = await hec(400, "");
    ok("400 + empty body: still http-bad-request (a read class never displaces the status)", empty400.ok === false && empty400.code === "http-bad-request");
    const rate = await hec(429, "slow down");
    ok("429: still http-rate-limited (unchanged)", rate.ok === false && rate.code === "http-rate-limited");
    const gone = await hec(410, "");
    ok("410: still http-gone (unchanged)", gone.ok === false && gone.code === "http-gone");
  }

  // ---- 6. NO OTHER SINK CHANGED. The body is read only where the contract is known, so a generic endpoint
  //         whose `code` field means something else entirely cannot have a failure invented for it.
  console.log("\nevery other format is byte-identical: the body is only read where the contract is known");
  {
    const p = await plain(200, JSON.stringify({ text: "Incorrect index", code: 7 }));
    ok("envelope reading OFF: a 200 declaring code 7 is still ok:true with NO code (unchanged)", p.ok === true && p.status === 200 && p.code === undefined);
    const p2 = await plain(200, JSON.stringify({ code: 200, msg: "ok" }));
    ok("envelope reading OFF: a vendor that answers {code:200} on success is untouched", p2.ok === true && p2.code === undefined);
    const p3 = await plain(200, "");
    ok("envelope reading OFF: an empty 200 carries no class at all (a healthy trail stays quiet)", p3.ok === true && p3.code === undefined);
    const p4 = await plain(503, "nope");
    ok("envelope reading OFF: a 503 is still http-5xx", p4.ok === false && p4.code === "http-5xx");
  }

  // ---- 7. THE CURSOR. Drive the REAL DO: a refusal behind a 200 must leave the cursor exactly where it was.
  console.log("\nthe DO cursor holds on a refusal behind a 200, and advances on a clean accept");
  {
    const storage = new MockStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const OWNER_CALLER = { method: "token" as const, email: null, subject: null, groups: [] };
    await dobj.setSiemPushDestination(
      { endpoint: PUBLIC_HEC_URL, format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: "Splunk tok", enabled: true },
      OWNER_CALLER,
    );
    const gen = (await dobj.getSiemPushRecordRaw())?.gen ?? "";
    ok("the cursor starts at 0", (await dobj.getSiemPushView()).lastPushedSeq === 0);
    await dobj.recordSiemPushOutcome({ ok: false, httpStatus: 200, reason: "hec-declined-index", count: 3, fromSeq: 0, toSeq: 3, gen });
    const held = await dobj.getSiemPushView();
    ok("a 200 that HEC refused leaves the cursor at 0, so seq 1-3 are re-exported next tick", held.lastPushedSeq === 0);
    ok("the trail row says ok:false and names the refusal", held.trail[held.trail.length - 1]?.ok === false && held.trail[held.trail.length - 1]?.reason === "hec-declined-index");
    ok("the trail row still carries the real wire status (200), so the row is not a lie", held.trail[held.trail.length - 1]?.httpStatus === 200);
    await dobj.recordSiemPushOutcome({ ok: true, httpStatus: 200, count: 3, fromSeq: 0, toSeq: 3, gen });
    ok("a clean accept then advances the cursor to 3 (the happy path is unchanged)", (await dobj.getSiemPushView()).lastPushedSeq === 3);
  }

  // ---- 8. THE DRAIN END TO END. The same events must actually be asked for again on the next tick. This is
  //         the "events are not dropped" proof: not just that the cursor held, but that the drain re-reads it.
  console.log("\nthe drain re-sends the SAME events on the next tick (events are not dropped)");
  {
    interface FakeState {
      record: { endpoint: string; format: string; authHeaderName: string; authHeaderValue: unknown; enabled: boolean; gen: string } | null;
      lastPushedSeq: number;
      events: AuditEvent[];
      recorded: Array<{ ok: boolean; httpStatus?: number; reason?: string; count: number; fromSeq: number; toSeq: number }>;
      exportedAfterSeq: number[];
    }
    type Sched = Parameters<typeof runSiemPushPass>[1];
    function fakeScheduler(state: FakeState): Sched {
      return {
        fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
          const url = new URL(typeof input === "string" ? input : input.toString());
          const json = (v: unknown): Response => new Response(JSON.stringify(v), { status: 200 });
          if (url.pathname === "/push-config") return json({ record: state.record });
          if (url.pathname === "/push") return json({ present: state.record !== null, lastPushedSeq: state.lastPushedSeq, trail: [] });
          if (url.pathname === "/audit/export") {
            const afterSeq = Number(url.searchParams.get("afterSeq") ?? "0");
            state.exportedAfterSeq.push(afterSeq);
            const matching = state.events.filter((e) => e.seq > afterSeq);
            return json({ events: matching, headSeq: state.events.length, headHash: "sha384:head" });
          }
          if (url.pathname === "/push-record") {
            const rec = JSON.parse(String(init?.body ?? "{}")) as FakeState["recorded"][number];
            state.recorded.push(rec);
            // Model the DO's own rule: the cursor moves only on ok:true.
            if (rec.ok === true && typeof rec.toSeq === "number") state.lastPushedSeq = Math.max(state.lastPushedSeq, rec.toSeq);
            return json({ ok: true });
          }
          throw new Error(`unexpected DO fetch in test: ${url.pathname}`);
        },
      } as unknown as Sched;
    }
    const env = { CONFIG_WRAP_KEY: undefined } as unknown as Env;
    const state: FakeState = {
      record: { endpoint: PUBLIC_HEC_URL, format: "splunk-hec", authHeaderName: "Authorization", authHeaderValue: "Splunk tok", enabled: true, gen: "gen-hec" },
      lastPushedSeq: 0,
      events: [fakeEvent(1), fakeEvent(2), fakeEvent(3)],
      recorded: [],
      exportedAfterSeq: [],
    };
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({ text: "Incorrect index", code: 7 }), { status: 200 })) as typeof fetch;
    try {
      ok("tick 1: a refusal behind a 200 still COMPLETES the pass (a customer-sink refusal is not a pass fault)", (await runSiemPushPass(env, fakeScheduler(state))) === true);
      ok("tick 1: recorded ok:false with the refusal named", state.recorded[0]?.ok === false && state.recorded[0]?.reason === "hec-declined-index");
      ok("tick 1: the cursor did not move", state.lastPushedSeq === 0);
      await runSiemPushPass(env, fakeScheduler(state));
      ok("tick 2 asked for the SAME events again (afterSeq 0 twice), so nothing was dropped", state.exportedAfterSeq.length === 2 && state.exportedAfterSeq[0] === 0 && state.exportedAfterSeq[1] === 0);
      ok("tick 2 re-sent the same span (fromSeq 0, toSeq 3)", state.recorded[1]?.fromSeq === 0 && state.recorded[1]?.toSeq === 3 && state.recorded[1]?.count === 3);
      // Now the sink recovers. The same events must land and the cursor must finally advance.
      globalThis.fetch = (async () => new Response(JSON.stringify({ text: "Success", code: 0 }), { status: 200 })) as typeof fetch;
      await runSiemPushPass(env, fakeScheduler(state));
      ok("tick 3, the sink recovered: ok:true with NO reason, and the cursor advances to 3", state.recorded[2]?.ok === true && state.recorded[2]?.reason === undefined && state.lastPushedSeq === 3);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // ---- 9. The sink dispatch honours the format gate: only splunk-hec turns the reading on. Driven through
  //         deliverResolvedPush (the shared dispatch the drain AND the admin test-send both use), so the test
  //         send reports the same refusal the drain would -- which is what the docs claim it does.
  console.log("\ndeliverResolvedPush gates the reading on the format, for the drain and the test-send alike");
  {
    const base = { endpoint: PUBLIC_HEC_URL, authHeaderName: "Authorization", authHeaderValue: "Splunk tok", enabled: true, gen: "g", sink: "http" as const, authInUrl: false };
    const meta = { afterSeq: 0, nextAfterSeq: 1, headSeq: 1, headHash: "h" };
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({ text: "Incorrect index", code: 7 }), { status: 200 })) as typeof fetch;
    try {
      const hecCfg = { ...base, format: "splunk-hec" } as unknown as ResolvedPushConfig;
      const rHec = await deliverResolvedPush(hecCfg, [fakeEvent(1)], meta);
      ok("format splunk-hec: the refusal reaches the sink-agnostic result as ok:false + the reason", rHec.ok === false && rHec.reason === "hec-declined-index");
      const ndCfg = { ...base, format: "ndjson" } as unknown as ResolvedPushConfig;
      const rNd = await deliverResolvedPush(ndCfg, [fakeEvent(1)], meta);
      ok("format ndjson against the SAME response: ok:true with no reason (unchanged)", rNd.ok === true && rNd.reason === undefined);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  // ---- 10. THE PACK. A reason the support pack's closed allow-list has not learned collapses to the
  //          unknown-code placeholder, so the row reaches support with no cause at all. A new
  //          vocabulary that is not added to PUSH_REASON_SET is therefore invisible EXACTLY when it matters.
  console.log("\nthe support pack projects the new reasons rather than collapsing them to unknown-code");
  {
    const trail = [
      { at: "2026-07-30T00:00:00.000Z", ok: false, httpStatus: 200, reason: "hec-declined-index", count: 3, fromSeq: 0, toSeq: 3 },
      { at: "2026-07-30T00:15:00.000Z", ok: true, httpStatus: 200, reason: "hec-body-unparseable", count: 1, fromSeq: 3, toSeq: 4 },
    ];
    const stub = {
      fetch: async (): Promise<Response> =>
        new Response(JSON.stringify({ present: true, enabled: true, format: "splunk-hec", sink: "http", lastPushedSeq: 3, headSeq: 4, trail }), { status: 200 }),
    } as unknown as DurableObjectStub;
    const section = (await fetchSiemPush(stub)) as { trail?: Array<{ reason?: string; ok?: boolean }>; unknownReasonCount?: number };
    ok("the pack carries hec-declined-index verbatim (not unknown-code)", section.trail?.[0]?.reason === "hec-declined-index");
    ok("the pack carries the ok:true caveat hec-body-unparseable too, so accepted-but-unconfirmed is visible", section.trail?.[1]?.reason === "hec-body-unparseable" && section.trail?.[1]?.ok === true);
    ok("no drift is reported, because both reasons are inside the closed allow-list", section.unknownReasonCount === undefined);
    // The negative control: a reason NOT in the vocabulary still collapses, so this assertion is really
    // checking membership rather than passing on any string at all.
    const rogue = { fetch: async (): Promise<Response> => new Response(JSON.stringify({ present: true, enabled: true, lastPushedSeq: 0, headSeq: 1, trail: [{ at: "2026-07-30T00:00:00.000Z", ok: false, reason: "hec-declined-invented" }] }), { status: 200 }) } as unknown as DurableObjectStub;
    const rogueSection = (await fetchSiemPush(rogue)) as { trail?: Array<{ reason?: string }>; unknownReasonCount?: number };
    ok("a reason outside the vocabulary still collapses to unknown-code and is counted as drift", rogueSection.trail?.[0]?.reason === "unknown-code" && rogueSection.unknownReasonCount === 1);
  }

  console.log(failures === 0 ? "\nHEC ACCEPTANCE PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
