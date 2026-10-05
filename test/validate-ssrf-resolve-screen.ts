// validate-ssrf-resolve-screen: the send-time RESOLVE half of the SSRF screen, which is the half that sees
// what a hostname actually points at.
//
// WHY THIS FILE EXISTS. The published ASVS self-assessment carried a section-4 finding, "SSRF via DNS
// rebinding (V1.3.6 / V13.2.4, medium)": isAllowedWebhookUrl validates the literal hostname at store time,
// so an attacker with the notify.config capability registers a name that resolves somewhere public at store
// time and repoints it at RFC1918 or 169.254.169.254 before the send. screenSinkHost's own comment recorded
// the same residual, returning the verdict "hostname" for exactly this case and naming it the rebind gap.
//
// The literal screen cannot close this, by construction: a name that resolves to cloud metadata is spelled
// like any other name. screenResolvedSinkHost resolves the name over DoH at send time and judges the
// ADDRESSES, and deliverPayload refuses on "resolved-internal".
//
// WHAT THIS DOES NOT CLAIM, asserted here rather than left to prose. Workers offers no way to pin a resolved
// address for the fetch that follows, so fetch resolves the name again itself and a racing attacker who can
// flip a record between the two lookups is not stopped. The exposure moves from "store a name, repoint it,
// wait" to "win that race". The test below asserts the residual exists rather than pretending otherwise, so
// nobody later reads this file as proof the target is un-rebindable.
//
// EVERY REFUSAL HERE CARRIES A CONTROL. A screen that refuses everything is not a screen, so each refusal is
// paired with a delivery that must still succeed, and the DoH transport is stubbed on both sides so the two
// differ only in what the resolver answered.

import {
  deliverPayload,
  screenResolvedSinkHost,
  screenSinkHost,
  DELIVERY_FAIL_CODES,
  RESOLVED_SINK_VERDICTS,
} from "../src/notify/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ---- fixtures -------------------------------------------------------------------------------------------

const SINK = "https://alerts.example.com/hook";

// INTERNAL_ANSWERS spans the classifier's arms rather than repeating one address: cloud metadata, RFC1918,
// loopback, IPv6 unique-local and IPv6 loopback.
const INTERNAL_ANSWERS = ["169.254.169.254", "10.0.0.5", "127.0.0.1", "192.168.1.10"];
const INTERNAL_V6_ANSWERS = ["fd00::1", "::1", "fe80::1"];

/**
 * A stubbed DoH + delivery transport. `answers` is what the resolver returns for the sink name; every other
 * request is the webhook POST itself, which is counted so a refusal can be shown to have happened BEFORE the
 * request rather than instead of reading its response.
 */
function stubFetch(answers: { a?: string[]; aaaa?: string[]; fail?: boolean; empty?: boolean }) {
  const state = { dohCalls: 0, postCalls: 0, dohUrls: [] as string[] };
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.startsWith("https://cloudflare-dns.com/")) {
      state.dohCalls++;
      state.dohUrls.push(url);
      if (answers.fail) throw new Error("resolver unreachable");
      const type = new URL(url).searchParams.get("type");
      const list = answers.empty ? [] : type === "AAAA" ? (answers.aaaa ?? []) : (answers.a ?? []);
      const Answer = list.map((data) => ({ type: type === "AAAA" ? 28 : 1, data }));
      return new Response(JSON.stringify({ Status: 0, Answer }), {
        status: 200,
        headers: { "content-type": "application/dns-json" },
      });
    }
    state.postCalls++;
    return new Response("{}", { status: 200 });
  }) as unknown as typeof fetch;
  return { impl, state };
}

// ---- the gap this closes --------------------------------------------------------------------------------

async function theRebindCase(): Promise<void> {
  console.log("\nthe rebind case: a public-looking NAME that resolves into private space");

  // THE OLD BEHAVIOUR, asserted so this file cannot pass vacuously. The literal screen returns "hostname"
  // for the rebinding sink, which is the verdict deliverPayload used to carry straight through to the POST.
  // If this ever stops being "hostname", the finding has changed shape and the rest of this file is grading
  // something else.
  ok(
    'the LITERAL screen alone still returns "hostname" for the rebinding sink, which is what used to deliver',
    screenSinkHost(SINK) === "hostname",
  );

  for (const addr of INTERNAL_ANSWERS) {
    const { impl, state } = stubFetch({ a: [addr] });
    const r = await deliverPayload(SINK, { hello: "world" }, false, undefined, impl);
    ok(`a name resolving to ${addr} is REFUSED`, r.ok === false && r.code === "internal-sink-resolved");
    ok(`  ...and no POST was issued to it (${state.postCalls} sent)`, state.postCalls === 0);
    ok("  ...and the resolved verdict is recorded on the result", r.resolvedScreen === "resolved-internal");
  }

  for (const addr of INTERNAL_V6_ANSWERS) {
    const { impl, state } = stubFetch({ aaaa: [addr] });
    const r = await deliverPayload(SINK, {}, false, undefined, impl);
    ok(`a name resolving to IPv6 ${addr} is REFUSED`, r.ok === false && r.code === "internal-sink-resolved");
    ok(`  ...and no POST was issued to it (${state.postCalls} sent)`, state.postCalls === 0);
  }

  // A name whose A record is public and whose AAAA record is internal is internal. This is why both types
  // are asked: screening only A would pass this.
  {
    const { impl, state } = stubFetch({ a: ["93.184.216.34"], aaaa: ["fd00::1"] });
    const r = await deliverPayload(SINK, {}, false, undefined, impl);
    ok("a public A with an internal AAAA is REFUSED (both record types are screened)", r.ok === false && r.code === "internal-sink-resolved");
    ok("  ...and no POST was issued", state.postCalls === 0);
  }
}

// ---- the controls ---------------------------------------------------------------------------------------

async function theControls(): Promise<void> {
  console.log("\ncontrols: the screen must still deliver everything it is not there to stop");

  {
    const { impl, state } = stubFetch({ a: ["93.184.216.34"], aaaa: ["2606:2800:220:1:248:1893:25c8:1946"] });
    const r = await deliverPayload(SINK, {}, false, undefined, impl);
    ok("CONTROL: a name resolving to public space is DELIVERED", r.ok === true && r.status === 200);
    ok("  ...the POST really was issued", state.postCalls === 1);
    ok("  ...and the verdict says the resolve ran and passed", r.resolvedScreen === "resolved-public");
  }

  // FAIL-OPEN ON NO ANSWER is deliberate: refusing every webhook during a resolver blip would be an outage
  // of the customer's own alerting that we built ourselves. The abstention must be RECORDED, not swallowed,
  // which is the difference between a documented limit and a silent one.
  {
    const { impl, state } = stubFetch({ fail: true });
    const r = await deliverPayload(SINK, {}, false, undefined, impl);
    ok("an unreachable resolver does NOT block delivery (fail-open on no answer)", r.ok === true);
    ok("  ...the POST was issued", state.postCalls === 1);
    ok('  ...and the abstention is recorded as "resolve-unavailable" rather than passing silently', r.resolvedScreen === "resolve-unavailable");
  }
  {
    const { impl } = stubFetch({ empty: true });
    const r = await deliverPayload(SINK, {}, false, undefined, impl);
    ok("a resolver answering NO addresses is an abstention, not a pass", r.ok === true && r.resolvedScreen === "resolve-unavailable");
  }

  // The explicit per-channel opt-in must not pay for a lookup at all: an operator who has declared their
  // sink internal has already answered this question.
  {
    const { impl, state } = stubFetch({ a: ["10.0.0.5"] });
    const r = await deliverPayload(SINK, {}, true, undefined, impl);
    ok("the internal-sink opt-in still delivers", r.ok === true);
    ok("  ...and issues NO resolve at all (the operator already answered)", state.dohCalls === 0);
  }

  // A public IP LITERAL is un-rebindable, so paying for a lookup would be waste.
  {
    const { impl, state } = stubFetch({ a: ["93.184.216.34"] });
    const r = await deliverPayload("https://93.184.216.34/hook", {}, false, undefined, impl);
    ok("a public IP literal is delivered with NO resolve (nothing to rebind)", r.ok === true && state.dohCalls === 0);
  }

  // An internal LITERAL must still be caught by the cheap screen, with its own distinct code, so a reviewer
  // can tell a sink that was always internal from one that was repointed after it was stored.
  {
    const { impl, state } = stubFetch({});
    const r = await deliverPayload("https://169.254.169.254/hook", {}, false, undefined, impl);
    ok("an internal LITERAL keeps its own distinct code", r.ok === false && r.code === "internal-sink-blocked");
    ok("  ...and costs no resolve", state.dohCalls === 0);
  }
}

// ---- the resolver itself --------------------------------------------------------------------------------

async function theResolver(): Promise<void> {
  console.log("\nthe resolver this screen asks");

  const { impl, state } = stubFetch({ a: ["93.184.216.34"] });
  await screenResolvedSinkHost("alerts.example.com", impl);
  ok("the resolver is asked for BOTH A and AAAA", state.dohCalls === 2);
  ok(
    "the resolver endpoint is FIXED and never customer-supplied, so this lookup cannot become the SSRF it prevents",
    state.dohUrls.every((u) => u.startsWith("https://cloudflare-dns.com/dns-query?")),
  );
  ok(
    "the queried name is the sink's, urlencoded",
    state.dohUrls.every((u) => new URL(u).searchParams.get("name") === "alerts.example.com"),
  );

  // The obfuscated spellings the literal screen canonicalises must not reappear through the resolve path:
  // a resolver ANSWER is an address, and an internal one is internal however it is written.
  for (const [answer, why] of [
    ["::ffff:169.254.169.254", "IPv4-mapped IPv6 cloud metadata"],
    ["::ffff:10.0.0.5", "IPv4-mapped IPv6 RFC1918"],
  ] as [string, string][]) {
    const s = stubFetch({ aaaa: [answer] });
    const v = await screenResolvedSinkHost("alerts.example.com", s.impl);
    ok(`a resolver answer of ${answer} (${why}) is classified internal`, v.verdict === "resolved-internal");
  }
}

// ---- the vocabulary and the stated residual ---------------------------------------------------------------

async function theContract(): Promise<void> {
  console.log("\nthe closed vocabulary, and the residual this does NOT close");

  ok('"internal-sink-resolved" is a member of the CLOSED delivery-failure vocabulary', DELIVERY_FAIL_CODES.has("internal-sink-resolved"));

  // THE VERDICT REACHES THE ADAPTER'S RESULT. deliverPayload computing a verdict is not enough: the adapters
  // used to return {ok, code, sinkScreen} and drop it, so the abstention the threat model says is recorded
  // was recorded nowhere. Driven through the real webhook adapter, the ChannelDeliveryResult must carry it.
  {
    const { deliver } = await import("../src/notify/channels/webhook.ts");
    const { impl } = stubFetch({ fail: true });
    const realFetch = globalThis.fetch; globalThis.fetch = impl;
    try {
      const r = await deliver({ id: "c1", kind: "webhook", name: "w", url: SINK, enabled: true, createdAt: "2026-09-11T00:00:00.000Z" } as never, { event: "backup-failure", severity: "critical", downpipeId: "d", detail: "x", ts: "2026-09-11T00:00:00.000Z" } as never);
      ok("the webhook adapter's ChannelDeliveryResult carries the resolve verdict (an abstention is not dropped one frame up)", (r as { resolvedScreen?: string }).resolvedScreen === "resolve-unavailable");
    } finally { globalThis.fetch = realFetch; }
  }
  ok('it is DISTINCT from "internal-sink-blocked", so the two causes never collapse', DELIVERY_FAIL_CODES.has("internal-sink-blocked"));
  for (const v of ["resolved-public", "resolved-internal", "resolve-unavailable"]) {
    ok(`"${v}" is a member of the closed resolved-verdict vocabulary`, RESOLVED_SINK_VERDICTS.has(v));
  }

  // THE RESIDUAL, asserted rather than described. The screen reads the resolver's answer; the POST that
  // follows resolves the name AGAIN, through the runtime, and nothing carries our answer across. A resolver
  // that returns public to us and internal to the runtime is therefore not stopped. Demonstrated by making
  // the two lookups disagree: the screen passes and the POST is issued, which is exactly the race.
  {
    let doh = 0;
    const impl = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("https://cloudflare-dns.com/")) {
        doh++;
        return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }), { status: 200 });
      }
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;
    const r = await deliverPayload(SINK, {}, false, undefined, impl);
    ok(
      "STATED RESIDUAL: a record that answers public to the screen still reaches the POST, because the fetch resolves independently",
      r.ok === true && r.resolvedScreen === "resolved-public" && doh === 2,
    );
  }
}

// ---- the three bespoke senders ------------------------------------------------------------------------
// SIEM HTTP push, OTLP push and JSM each carry their own sender rather than deliverPayload, and each had only
// the literal screen: the challenger on V1.3.6 showed the rebinding residual was "narrowed to a race" for
// four channels and not at all for these three. Same decision, same helper, proven on each.

async function theBespokeSenders(): Promise<void> {
  console.log("\nthe bespoke senders (SIEM push, OTLP push, JSM) refuse a name that resolves internal");
  const { deliverSiemPush } = await import("../src/notify/siem-push-sender.ts");
  const { deliverOtlpPush } = await import("../src/notify/otlp-push-sender.ts");
  const realFetch = globalThis.fetch;
  try {
    for (const [label, run] of [
      ["SIEM HTTP push", () => deliverSiemPush("https://siem.example.com/services/collector", "{}", "application/json", "authorization", "Splunk t")],
      ["OTLP push", () => deliverOtlpPush("https://otlp.example.com/v1/logs", "{}", "authorization", "Bearer t")],
    ] as [string, () => Promise<{ ok: boolean; code?: string }>][]) {
      const bad = stubFetch({ a: ["10.0.0.5"] }); globalThis.fetch = bad.impl;
      const r = await run();
      ok(`${label}: a name resolving to 10.0.0.5 is REFUSED with internal-sink-resolved`, r.ok === false && r.code === "internal-sink-resolved");
      ok(`${label}:   ...and no POST was issued (${bad.state.postCalls} sent)`, bad.state.postCalls === 0);
      const good = stubFetch({ a: ["93.184.216.34"] }); globalThis.fetch = good.impl;
      const r2 = await run();
      ok(`${label}: CONTROL, a public answer is DELIVERED`, r2.ok === true && good.state.postCalls === 1);
    }
  } finally { globalThis.fetch = realFetch; }
}

async function main(): Promise<void> {
  await theRebindCase();
  await theBespokeSenders();
  await theControls();
  await theResolver();
  await theContract();

  console.log(failures === 0 ? "\nSSRF RESOLVE SCREEN VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

void main();
