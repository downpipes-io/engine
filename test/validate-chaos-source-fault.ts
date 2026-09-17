// Offline validation of the in-engine source-fault injector (src/sources/chaos-fault.ts) -- the engine hook
// the chaos scripts (chaos/srcfault-run.sh) arm at deploy time. Proves, WITHOUT a deploy, that: the fault
// spec parses FAIL-SAFE (a bad var never crashes a run); an UNSET var is a byte-identical no-op (the real
// fetch/binding is returned untouched); and an ARMED fault injects at the source's OWN read boundary so the
// run surfaces the CORRECT observable outcome -- a fail-open marker / graceful degradation, NEVER a clean
// full capture under a fault (the chaos harness invariant). Covers the new-work paths: the cf-config zone
// identity read (fail-open) and a cf-config surface read (incompleteness), plus the KV vanish fault.
// Run: node test/validate-chaos-source-fault.ts

import { parseSourceFault, chaosSourceFetch, chaosKVBinding } from "../src/sources/chaos-fault.ts";
import { CloudflareConfigSource } from "../src/sources/cloudflare-config.ts";
import { KVSource } from "../src/sources/kv.ts";
import { CF_CONFIG_SURFACES, CF_CONFIG_IDENTITY_ID } from "../src/sources/cf-config-surfaces.ts";
import type { Selector, SourceRecord } from "../src/sources/types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(name: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${name}`);
  if (!cond) failures++;
}
const ALL: Selector = { include: [], exclude: [] };
const dec = (u?: Uint8Array): string => new TextDecoder().decode(u);

// A cf-config stub: /zones/<id> (the identity zone-name read) returns a zone with a name; every surface read
// returns the generic stub envelope. Not wrapped -- the chaosSourceFetch wraps THIS.
function cfStub(zoneId: string): typeof fetch {
  return (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith(`/zones/${zoneId}`)) return new Response(JSON.stringify({ success: true, result: { id: zoneId, name: "example.com" } }), { status: 200 });
    return new Response(JSON.stringify({ success: true, result: [{ stub: true }] }), { status: 200 });
  }) as typeof fetch;
}
async function collect(it: AsyncIterable<SourceRecord>): Promise<SourceRecord[]> {
  const out: SourceRecord[] = [];
  for await (const r of it) out.push(r);
  return out;
}

async function main(): Promise<void> {
  console.log("-- parseSourceFault is FAIL-SAFE (a bad var never arms a fault / crashes a run) --");
  ok("unset => null (no-op)", parseSourceFault({}) === null && parseSourceFault(undefined) === null);
  ok("blank => null", parseSourceFault({ CHAOS_SOURCE_FAULT: "   " }) === null);
  ok("malformed JSON => null", parseSourceFault({ CHAOS_SOURCE_FAULT: "{not json" }) === null);
  ok("missing required fields => null", parseSourceFault({ CHAOS_SOURCE_FAULT: '{"source":"kv"}' }) === null);
  const spec = parseSourceFault({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"api-fault","at":2,"path":"/zones/"}' });
  ok("a valid spec parses with its fields", spec?.source === "cf-config" && spec?.fault === "api-fault" && spec?.at === 2 && spec?.path === "/zones/");
  ok("a non-positive/absent `at` defaults to 1", parseSourceFault({ CHAOS_SOURCE_FAULT: '{"source":"kv","fault":"vanish-midcrawl"}' })?.at === 1);

  console.log("-- UNSET / different-source => the real fetch is returned UNTOUCHED (byte-identical no-op) --");
  const realFetch = (async () => new Response("real")) as typeof fetch;
  ok("unarmed => the same fetch reference", chaosSourceFetch({}, "cf-config", realFetch) === realFetch);
  ok("armed for a DIFFERENT source => the same fetch reference", chaosSourceFetch({ CHAOS_SOURCE_FAULT: '{"source":"kv","fault":"vanish-midcrawl"}' }, "cf-config", realFetch) === realFetch);
  ok("an unknown fault kind => the same fetch reference (fetch helper only knows api-fault/api-timeout)", chaosSourceFetch({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"cursor-expiry"}' }, "cf-config", realFetch) === realFetch);

  console.log("-- ARMED + PERMANENT: the fault is SUSTAINED for the call it lands on (a retry finds it still down) --");
  {
    // The three cf-config assertions below are DOWNSTREAM evidence of this: they went red the moment the retry
    // classifier started reading the status off the error (dest/classify.ts statusOnError), because the injected
    // 500 became retryable and the adapter's retry reached the real upstream on attempt two. The engine was
    // right; the injector faulted one call while documenting "a sustained outage". Asserted here directly, at
    // the injector's own boundary, so a regression names the cause instead of surfacing as a marker that
    // quietly stopped appearing three assertions away.
    let realCalls = 0;
    const counting = (async () => { realCalls++; return new Response("real-ok", { status: 200 }); }) as typeof fetch;
    const faulted = chaosSourceFetch({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"api-fault","at":1,"path":"/x"}' }, "cf-config", counting);
    ok("attempt 1 on the matching call faults", (await faulted("https://api/x")).status === 500);
    ok("attempt 2 on the SAME call faults too (the retry does not ride past the outage)", (await faulted("https://api/x")).status === 500);
    ok("attempt 3 as well (sustained, not a two-shot)", (await faulted("https://api/x")).status === 500);
    ok("... and NOT ONE of them reached the real upstream", realCalls === 0);
    // The pin must not walk the fault onto a neighbour: a DIFFERENT matching URL is a new matching call, and
    // `at` has already been spent, so it passes through. Without this the sustained fault would black-hole every
    // surface and the fail-open-per-surface evidence would be vacuous.
    ok("a DIFFERENT matching URL still passes through (the fault stays on the resource it landed on)", (await faulted("https://api/x2")).status === 200 && realCalls === 1);
  }

  console.log("-- ARMED: a cf-config ZONE-NAME fault => the identity STILL emits with zoneId (graceful fail-open) --");
  {
    const faulted = chaosSourceFetch({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"api-fault","at":1,"path":"/zones/z1"}' }, "cf-config", cfStub("z1"));
    const recs = await collect(new CloudflareConfigSource("tok", "acct-1", "z1", CF_CONFIG_SURFACES, faulted).crawl(ALL));
    const id = JSON.parse(dec(recs[0]?.value)) as { zoneId?: unknown; zoneName?: unknown };
    ok("the identity record is still emitted first", recs[0]?.name === CF_CONFIG_IDENTITY_ID);
    ok("it keeps the zoneId (still unambiguous under the fault)", id.zoneId === "z1");
    ok("the faulted zone-name read drops zoneName, never throws (fail-open)", id.zoneName === undefined);
    ok("the surfaces after the faulted identity read still crawl (the run continues)", recs.length === CF_CONFIG_SURFACES.length + 1);
  }

  console.log("-- ARMED: a cf-config SURFACE fault => that surface is an _unavailable MARKER (the invariant) --");
  {
    // Fault the dns surface's read (/zones/z1/dns_records); the identity + other surfaces are unaffected.
    const faulted = chaosSourceFetch({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"api-fault","at":1,"path":"/dns_records"}' }, "cf-config", cfStub("z1"));
    const recs = await collect(new CloudflareConfigSource("tok", "acct-1", "z1", CF_CONFIG_SURFACES, faulted).crawl(ALL));
    const dns = recs.find((r) => r.name === "dns");
    ok("the faulted surface is present as a marker, never silently dropped", dns !== undefined && dns.markerKind === "_unavailable");
    ok("the fault surfaces incompleteness (NOT a clean full capture) -- the harness invariant", recs.some((r) => r.markerKind === "_unavailable"));
    ok("a fault at one surface does not fail the whole crawl (fail-open per surface)", recs.length === CF_CONFIG_SURFACES.length + 1);
  }

  console.log("-- ARMED: api-timeout REJECTS the matching call (a transient network fault) => survived --");
  {
    // A single transient timeout on a surface read is the CfApi's retry path's job: the crawl must SURVIVE it
    // (either the retry recovers, or the surface is marked _unavailable) -- never crash. Fail-open either way.
    const faulted = chaosSourceFetch({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"api-timeout","at":1,"path":"/dns_records"}' }, "cf-config", cfStub("z1"));
    const recs = await collect(new CloudflareConfigSource("tok", "acct-1", "z1", CF_CONFIG_SURFACES, faulted).crawl(ALL));
    ok("an api-timeout fault never crashes the crawl (fail-open: retried or marked)", recs.length === CF_CONFIG_SURFACES.length + 1);
    const dns = recs.find((r) => r.name === "dns");
    ok("the timed-out surface is either recovered (real) or a marker, never silently dropped", dns !== undefined);
  }

  console.log("-- TRANSIENT (faultUntilMs): faults BEFORE the deadline, passes through AFTER -- injected clock, NO real timers --");
  {
    // A transient fault must recover across a retry (a new isolate). The clock is injected, so the test crosses
    // the deadline by ADVANCING a variable -- never a setTimeout / sleep. passFetch is the "real upstream": a
    // 200 the adapter reads as success, distinct from the injected 500, so we can tell fault from pass-through.
    let now = 0;
    const clock = (): number => now;
    const passFetch = (async () => new Response("real-ok", { status: 200 })) as typeof fetch;
    const armed = '{"source":"cf-config","fault":"api-fault","at":1,"faultUntilMs":1000}';
    ok("faultUntilMs parses as a number", parseSourceFault({ CHAOS_SOURCE_FAULT: armed })?.faultUntilMs === 1000);
    ok(
      "a non-number faultUntilMs is IGNORED (fail-safe -> fault stays permanent)",
      parseSourceFault({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"api-fault","faultUntilMs":"soon"}' })?.faultUntilMs === undefined,
    );

    // Before the deadline (now=0 < 1000): the matching call faults -- a 500 the adapter reads as an upstream error.
    now = 0;
    const before = chaosSourceFetch({ CHAOS_SOURCE_FAULT: armed }, "cf-config", passFetch, clock);
    ok("BEFORE the deadline the matching call faults (500)", (await before("https://api/x")).status === 500);

    // After the deadline (clock advanced to 1000, NO real timer): a FRESH isolate's injector -- its own `matched`
    // counter resets, and the same matching call now finds no fault and reaches the real upstream: park-and-resume.
    now = 1000;
    const after = chaosSourceFetch({ CHAOS_SOURCE_FAULT: armed }, "cf-config", passFetch, clock);
    const rAfter = await after("https://api/x");
    ok("AFTER the deadline (clock advanced) the SAME call passes through to success", rAfter.status === 200 && (await rAfter.text()) === "real-ok");

    // A fault with NO faultUntilMs is UNCHANGED: it faults at any clock (a permanent / sustained outage).
    now = 9_999_999;
    const perm = chaosSourceFetch({ CHAOS_SOURCE_FAULT: '{"source":"cf-config","fault":"api-fault","at":1}' }, "cf-config", passFetch, clock);
    ok("a fault with NO faultUntilMs still faults at any clock (permanent, unchanged)", (await perm("https://api/x")).status === 500);
  }

  console.log("-- ARMED: chaosKVBinding vanish-midcrawl => the at-th value get returns null (a deleted key) --");
  {
    let gets = 0;
    // A NATIVE-LIKE binding: its methods throw if called with the wrong `this`, exactly as a workerd host
    // object (a real KVNamespace) does -- an "illegal invocation". This is the regression guard for the bug a
    // LIVE run caught (the Proxy passed methods through with `this` = the Proxy, crashing the crawl at 8ms);
    // a plain-object stub could not catch it because plain methods tolerate any `this`.
    const nativeKV: Record<string, unknown> = {};
    Object.assign(nativeKV, {
      async get(this: unknown) { if (this !== nativeKV) throw new Error("illegal invocation: get called with wrong this"); gets++; return "v"; },
      // getWithMetadata models the REAL Workers KV contract (a bound value + metadata), so the injector's
      // getWithMetadata branch -- the one the vanish patch fixes -- is exercised, not just the get() side.
      async getWithMetadata(this: unknown) { if (this !== nativeKV) throw new Error("illegal invocation: getWithMetadata called with wrong this"); gets++; return { value: new TextEncoder().encode("v").buffer, metadata: { m: 1 } }; },
      async list(this: unknown) { if (this !== nativeKV) throw new Error("illegal invocation: list called with wrong this"); return { keys: [], list_complete: true }; },
    });
    const wrapped = chaosKVBinding({ CHAOS_SOURCE_FAULT: '{"source":"kv","fault":"vanish-midcrawl","at":2}' }, nativeKV as unknown as KVNamespace);
    // The PASSTHROUGH path (list is not faulted) must bind to the real binding, or a native host object throws.
    ok("a non-faulted method (list) passes through BOUND to the real binding (no illegal invocation)", Array.isArray((await wrapped.list()).keys));
    ok("get #1 returns the real value", (await wrapped.get("k1")) === "v");
    ok("get #2 (at:2) vanishes -> null (the key was deleted mid-crawl)", (await wrapped.get("k2")) === null);
    ok("get #3 returns the real value again", (await wrapped.get("k3")) === "v");
    // The bug the patch fixes lives on the getWithMetadata BRANCH: real KV getWithMetadata returns
    // {value:null, metadata:null} for a missing key, NEVER bare null (a revert to bare null would crash the
    // adapter with "cannot read properties of null"). get() returned null both before and after the patch, so
    // it cannot pin the regression. Use FRESH wrapped instances: get() and getWithMetadata() share ONE
    // per-instance getCalls counter, so calling both on `wrapped` above would shift the at:N target.
    const wmPass = chaosKVBinding({ CHAOS_SOURCE_FAULT: '{"source":"kv","fault":"vanish-midcrawl","at":2}' }, nativeKV as unknown as KVNamespace);
    const gmOk = (await wmPass.getWithMetadata("k1")) as { value: unknown; metadata: unknown };
    ok("a non-faulted getWithMetadata passes through the real KV shape (value + metadata present)", gmOk !== null && gmOk.value !== null && gmOk.metadata !== null);
    const wmFault = chaosKVBinding({ CHAOS_SOURCE_FAULT: '{"source":"kv","fault":"vanish-midcrawl","at":1}' }, nativeKV as unknown as KVNamespace);
    const gm = (await wmFault.getWithMetadata("gone")) as { value: unknown; metadata: unknown };
    ok("a faulted getWithMetadata returns the real KV shape {value:null, metadata:null}, never bare null", gm !== null && gm.value === null && gm.metadata === null);
    // cursor-expiry's passthrough must likewise bind (its faulted method is list; get is a passthrough here).
    const cur = chaosKVBinding({ CHAOS_SOURCE_FAULT: '{"source":"kv","fault":"cursor-expiry","at":99}' }, nativeKV as unknown as KVNamespace);
    ok("cursor-expiry passthrough (get) is bound to the real binding too", (await cur.get("k")) === "v");
    ok("an unarmed KV binding is returned untouched", chaosKVBinding({}, nativeKV as unknown as KVNamespace) === (nativeKV as unknown as KVNamespace));
  }

  console.log("-- ARMED: vanish-midcrawl DRIVEN THROUGH KVSource.crawl => the vanished key seals a _vanished MARKER --");
  {
    // The end-to-end path the patch actually fixes: injector -> KVSource.readRecord (prefers getWithMetadata,
    // reads r.value = null, the `v === null` guard returns null) -> yieldPage seals a _vanished marker. The
    // get()-only stub above never reaches this because readRecord takes the getWithMetadata path when present.
    const keys = [{ name: "a" }, { name: "b" }, { name: "c" }];
    const crawlKV: Record<string, unknown> = {};
    Object.assign(crawlKV, {
      // getWithMetadata MUST return an ArrayBuffer value (readRecord does `new Uint8Array(v)`); a string throws.
      // Keep the native-host-object `this`-identity guard on BOTH methods so the illegal-invocation coverage holds.
      async getWithMetadata(this: unknown) { if (this !== crawlKV) throw new Error("illegal invocation: getWithMetadata called with wrong this"); return { value: new TextEncoder().encode("v").buffer, metadata: null }; },
      async list(this: unknown) { if (this !== crawlKV) throw new Error("illegal invocation: list called with wrong this"); return { keys, list_complete: true }; },
    });
    const wrapped = chaosKVBinding({ CHAOS_SOURCE_FAULT: '{"source":"kv","fault":"vanish-midcrawl","at":2}' }, crawlKV as unknown as KVNamespace);
    const recs = await collect(new KVSource(wrapped, "ns-1").crawl(ALL));
    const vanished = recs.filter((r) => r.markerKind === "_vanished");
    ok("exactly one key vanished -> a single _vanished marker record", vanished.length === 1);
    ok("the vanished marker is the 2nd getWithMetadata call's key ('b')", vanished[0]?.name === "b");
    ok("the other two keys sealed as real records (markerKind undefined)", recs.length === 3 && recs.filter((r) => r.markerKind === undefined).length === 2);
  }

  console.log(failures === 0 ? "\nCHAOS SOURCE-FAULT PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
