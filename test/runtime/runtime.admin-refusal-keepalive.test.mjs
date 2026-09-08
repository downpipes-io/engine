// runtime.admin-refusal-keepalive.test.mjs -- does a refused admin write's RECORD survive the request?
//
// Run: node test/runtime/runtime.admin-refusal-keepalive.test.mjs
//
// WHAT THIS EXISTS TO CATCH. Fourteen admin call sites record a refusal with recordAdminRefusal. Eleven
// hand the write to fireInBackground, which calls the runtime's waitUntil; three used a bare `void` and
// returned, so the write had no keep-alive. In Node -- which is where every other validator in this repo
// runs -- a floating promise always completes, so the two shapes are INDISTINGUISHABLE and the existing
// suite passed identically before and after the fix. scripts/void-waituntil-gate.mjs says so itself: it
// can see that a call is no longer a bare void, and explicitly cannot prove the task stays alive.
//
// This test closes that gap. It runs the REAL admin router in a REAL workerd isolate (Miniflare) reached
// over a REAL socket, so the request context is genuinely torn down after each response, and it drives the
// scheduler DO subrequest a tick after the caller's own turn -- which is what a Durable Object on separate
// hardware gives you, and what a same-process loopback hides. Under that condition a bare void loses every
// record and the helper keeps every one, so the difference is observable rather than assumed.
//
// It is calibrated, not assumed: runtime.waituntil-calibration.mjs is the companion that proves this
// runtime really does abandon work not held by waitUntil (0 of 5 against 5 of 5, at every delay from 0 to
// 3000 ms). Run that first if this test ever reads clean for a reason you do not believe.
//
// CONTROLS, because the whole question is about an ABSENCE:
//   * an AWAITED record is read back in every isolate before anything else, so a zero is never read
//     over a dead reader
//   * the helper-based neighbour (downpipe-write) runs in the same window as the known positive of the
//     right kind: if IT is zero, nothing was recorded at all and the run reports could-not-check
//   * a 429 from the shared rate limiter is a refusal that never reaches the recorder, so it is
//     could-not-check, never a clean zero
//   * every surface gets a FRESH isolate, because 20 admin writes in one isolate trip that limiter
//
// Exit: 0 all four surfaces recorded their exact key; 1 a surface lost its record; 4 could-not-check.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, "admin-refusal-keepalive-worker.ts");
const OUT = join(here, ".bundle", "admin-refusal-keepalive-worker.js");
const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : d;
};
const N = Number(argOf("--n", "5"));
const JSON_OUT = argOf("--json", null);
const LABEL = argOf("--label", "admin-refusal-keepalive");
const TOKEN = "keepalive-test-token";

async function bundle() {
  mkdirSync(dirname(OUT), { recursive: true });
  const r = await build({
    entryPoints: [ENTRY],
    outfile: OUT,
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    conditions: ["workerd", "browser"],
    external: ["cloudflare:sockets", "cloudflare:workers", "cloudflare:email"],
    keepNames: true,
    legalComments: "none",
    write: true,
    logLevel: "silent",
  });
  if (r.errors.length) throw new Error(r.errors.map((e) => e.text).join("\n"));
  return OUT;
}

const say = (s) => console.log(s);
let couldNotCheck = false;

async function main() {
  const bundlePath = await bundle();
  const script = readFileSync(bundlePath, "utf8");

  const mkInstance = async () => {
    const mf = new Miniflare({
      modules: true,
      script,
      scriptPath: bundlePath,
      compatibilityDate: "2026-06-01",
      durableObjects: { SCHEDULER: { className: "SchedulerDO", useSQLite: true }, REFUSAL_SLOW: { className: "RefusalSlowDO", useSQLite: true } },
      bindings: { ADMIN_TOKEN: TOKEN, CONSOLE_ORIGIN: "https://console.test" },
      log: new Log(LogLevel.WARN),
    });
    await mf.ready;
    const hit = async (p, init) => {
      const r = await mf.dispatchFetch(`https://engine.test${p}`, init);
      return { status: r.status, text: await r.text() };
    };
    return { mf, hit };
  };
  const auth = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };
  const countOf = (o, k) => o?.[k]?.count ?? 0;

  say(`== DEFERRED-DISPATCH PRODUCT DRIVE (${LABEL}), ${N} refusals per surface, ONE FRESH ISOLATE PER SURFACE ==`);
  say("   (a fresh isolate per surface, because the per-caller rate limiter is shared and 20 writes in one");
  say("    isolate trips it to 429 -- which is a refusal that never reaches the recorder at all)");

  // The three sites under investigation, plus the helper-based neighbour as the known positive of the
  // right kind. dest-add's key depends on the refusal status, so every member of the prefix is summed.
  const SURFACES = [
    { name: "BARE   push-config  (router-push)", path: "/refusal-defer/admin/push", body: { endpoint: "not-a-url", format: "nope" }, prefix: "push-config:" },
    { name: "BARE   dest-add     (router-destinations)", path: "/refusal-defer/admin/destination", body: { config: { endpoint: "not-a-url" } }, prefix: "dest-add:" },
    { name: "BARE   otlp-config  (router-otlp-push)", path: "/refusal-defer/admin/otlp-push", body: { endpoint: "not-a-url" }, prefix: "otlp-config:" },
    { name: "HELPER downpipe-write (router-pipelines, the KNOWN POSITIVE)", path: "/refusal-defer/admin/downpipes", body: { id: "", name: "" }, prefix: "downpipe-write:" },
  ];

  const rows = [];
  let kpSeen = 0;
  for (const s of SURFACES) {
    const { mf, hit } = await mkInstance();
    // Control 0, per isolate: the reader's own known positive, an AWAITED record no teardown can take.
    await hit("/refusal/awaited");
    const kpRaw = await hit("/refusal/read");
    let kpCount = 0;
    if (kpRaw.status === 200) kpCount = countOf(JSON.parse(kpRaw.text), "update-apply:validation");
    if (kpCount === 1) kpSeen++;

    const statuses = [];
    for (let i = 0; i < N; i++) {
      const r = await hit(s.path, { method: "POST", headers: auth, body: JSON.stringify(s.body) });
      statuses.push(r.status);
    }
    await new Promise((r) => setTimeout(r, 2000));
    const aggRaw = await hit("/refusal/read");
    if (aggRaw.status !== 200) {
      say(`  ${s.name}: READER DID NOT REACH ITS ENDPOINT (${aggRaw.status}) -> COULD-NOT-CHECK`);
      couldNotCheck = true;
      await mf.dispose();
      rows.push({ name: s.name, prefix: s.prefix, statuses, keys: [], count: 0, readerReached: false, knownPositiveAwaited: kpCount });
      continue;
    }
    const agg = JSON.parse(aggRaw.text);
    const keys = Object.keys(agg).filter((k) => k.startsWith(s.prefix));
    const count = keys.reduce((a, k) => a + countOf(agg, k), 0);
    rows.push({ name: s.name, prefix: s.prefix, statuses, keys, count, readerReached: true, knownPositiveAwaited: kpCount, aggregate: agg });
    await mf.dispose();
  }

  for (const r of rows) {
    say(`  ${r.name.padEnd(58)} kp=${r.knownPositiveAwaited === 1 ? "OK" : "DEAD"} statuses=${JSON.stringify(r.statuses)} -> ${r.prefix}* = ${r.count}/${N} ${JSON.stringify(r.keys)}`);
  }

  // A drive that took a refusal on every path INCLUDING its known positive measured nothing. The 429 the
  // shared rate limiter produces is exactly such a refusal: it never reaches the recorder.
  const allStatuses = rows.flatMap((r) => r.statuses);
  if (!allStatuses.every((s) => s >= 400 && s < 500)) {
    say(`  THE DRIVE DID NOT PRODUCE 4xx REFUSALS ON EVERY PATH (${JSON.stringify(allStatuses)}) -> COULD-NOT-CHECK`);
    couldNotCheck = true;
  }
  if (allStatuses.some((s) => s === 429)) {
    say("  A 429 APPEARED: the rate limiter refused before the validator, so that surface never reached its");
    say("  recorder and its zero means nothing -> COULD-NOT-CHECK");
    couldNotCheck = true;
  }
  if (kpSeen !== SURFACES.length) {
    say(`  THE AWAITED KNOWN POSITIVE WAS READ BACK IN ONLY ${kpSeen} OF ${SURFACES.length} ISOLATES -> COULD-NOT-CHECK`);
    couldNotCheck = true;
  }
  const helperRow = rows[rows.length - 1];
  if (helperRow.count === 0) {
    say("  KNOWN POSITIVE OF THE RIGHT KIND IS ZERO: the helper path recorded nothing either, so the bare");
    say("  zeros above are worthless -> COULD-NOT-CHECK");
    couldNotCheck = true;
  }

  // THE ASSERTION, on WHAT THE RECORD CONTAINS rather than only that something was written: the exact
  // "<surface>:<reason>" key, and its count. A mutant that records the wrong surface or the wrong reason
  // still leaves a record behind, and a count-only or non-empty-aggregate check passes on it.
  const EXPECT = {
    "push-config:": "push-config:validation",
    "dest-add:": "dest-add:validation",
    "otlp-config:": "otlp-config:validation",
    "downpipe-write:": "downpipe-write:validation",
  };
  let failures = 0;
  for (const r of rows) {
    const want = EXPECT[r.prefix];
    const ok = r.count === N && r.keys.length === 1 && r.keys[0] === want;
    if (!ok) {
      failures++;
      say(`  FAIL ${r.prefix} expected ${JSON.stringify([want])} x${N}, got ${JSON.stringify(r.keys)} x${r.count}`);
      if (r.count === 0) say("       a refused admin write left NO record: the refusal is one nobody can later see");
    }
  }

  const out = { label: LABEL, n: N, rows, isolatesWithKnownPositive: kpSeen, failures, couldNotCheck };
  if (JSON_OUT) writeFileSync(JSON_OUT, `${JSON.stringify(out, null, 1)}\n`);
  say(`== ${LABEL}: ${rows.map((r) => `${r.prefix}${r.count}/${N}`).join("  ")}  failures=${failures}  couldNotCheck=${couldNotCheck} ==`);
  if (couldNotCheck) {
    say("VERDICT: COULD-NOT-CHECK (exit 4). This is NOT a pass.");
    return 4;
  }
  say(failures === 0 ? "ADMIN-REFUSAL KEEP-ALIVE PASS" : `ADMIN-REFUSAL KEEP-ALIVE FAIL (${failures} surface(s) lost their record)`);
  return failures === 0 ? 0 : 1;
}

main().then(
  (c) => process.exit(c),
  (e) => {
    console.error("DEFERDRIVE FAILED:", e);
    process.exit(1);
  },
);
