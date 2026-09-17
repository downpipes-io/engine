// runtime.dest-change-alert-keepalive.test.mjs -- do the FOUR destination-change ALERT records survive the request?
//
// Run: node test/runtime/runtime.dest-change-alert-keepalive.test.mjs [--n 3] [--calibrate] [--only <id>]
//
// WHAT THIS EXISTS TO CATCH, AND WHY IT IS A SEPARATE DRIVE. The admin-signal sweep (347696bf) drove
// twenty-six call sites through the real router and repaired twenty-seven. FOUR of the twenty-seven were
// repaired ON SHAPE and never driven: the destination-change alerts in router-destinations.ts, at
//
//   :272  POST /destination            "A backup destination was set/repointed"
//   :393  POST /destinations           "A backup destination was added or edited"
//   :406  POST /destinations/remove    "A backup destination removal was requested"
//   :416  POST /destinations/default   "The default backup destination was changed"
//
// That pass's own headline finding is the reason a shape argument does not settle them: rateLimited's
// records LOSE on a route that returns straight after admitting and KEEP on one that then does awaited
// work -- same line, two callers, opposite outcomes. So "it resembles the eleven that keep" is exactly the
// reasoning that finding undermines, and a destination repoint is an exfiltration path: the alert is the
// record that would have shown it.
//
// THE SITES ARE NOT REACHABLE THE WAY THE SWEEP'S CASES ARE. Each alert is guarded by `if (resp.ok)` on a
// DO write, and three of the four DO writes REFUSE ("no such destination") unless a destination already
// exists, while two of the four run a LIVE destination probe (HEAD/PUT/DELETE/object-lock over the network)
// before the router will store anything. So this drive adds exactly two things to the shared instrument and
// changes nothing else about it: a DO-side seed (/signal/seed-dest, which never touches the admin router, so
// the setup cannot fire one of the four alerts into the aggregate the measurement then reads) and a
// Miniflare outboundService that answers the destination probe and the webhook sink. Every recorder and
// every read-back route stays on the real DO.
//
// THE RECORD IS MEASURED IN BOTH ESTATE SHAPES, because routeEmission hands the record off at a different
// moment in each:
//   unwired  no channel matches -> `void bumpAdminCounter(alert-emit-dest-change-no-channel)` and return.
//            This is the SHORTEST path: the hand-off is the last thing before the promise the call site
//            holds resolves.
//   wired    one webhook channel + one global rule -> resolve, deliver, then
//            `void scheduler.fetch(/notify/record)`, which is the NOTIFY-HISTORY ROW: the record that
//            names the repoint, in the customer's own pack.
//
// THE ASSERTION IS ON THE EXACT KEY, never on existence and never on a count alone. Unwired: the exact
// composed counter name `alert-emit-dest-change-no-channel`, so a mutant passing a different AlertClass
// lands a record with the right count under a different name and still fails. Wired: a history row whose
// event is `dest-change` AND whose detail is the one THIS call site composes, so a mutant that fires the
// wrong route's alert, or the wrong event, leaves the right number of rows and still fails.
//
// CONTROLS, because the whole question is about an ABSENCE:
//   * per isolate, an AWAITED record into each aggregate read, taken BEFORE any drive (/signal/awaited): if it
//     is not read back the reader is dead and the zeros beside it mean nothing -> could-not-check
//   * REACHABILITY, and it is NOT the sweep's native-dispatch arm for these four. That arm works when the
//     record is written by a subrequest issued inside the caller's own turn: the loopback then holds the
//     context open by itself, so a reached site records under it whatever its keep-alive. These records are
//     written AFTER the outer response by a subrequest that does not exist yet when the caller's turn ends,
//     so nothing holds either arm open and a zero on both is what a LOST record looks like, not a missed
//     drive. Reachability here is the EMISSION-RAN evidence: the wired twin posts to the stub sink from
//     inside routeEmission, after resolve and before the record write, so N posts prove the line executed N
//     times. The native arm still runs and is still reported, because the two readings differing would
//     itself be a fact. The CONTROL case keeps the sweep's arm, since its record is the in-turn kind.
//   * the drive must answer the status the call site returns, and an UNASKED-FOR 429 (the shared per-caller
//     limiter refusing before the call site) is could-not-check, never a clean zero
//   * every case gets a FRESH isolate
//   * CALIBRATION (--calibrate) on the shared worker's own arms: the floating-promise pair MUST separate
//     (0/N bare against N/N kept) or nothing below can be trusted; the in-flight-subrequest pair is printed
//     beside it because it reads N/N on BOTH and is the blindness an earlier harness inherited.
//
// Exit: 0 every case matched its expectation; 1 a case disagreed; 4 could-not-check.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, "admin-refusal-keepalive-worker.ts");
const OUT = join(here, ".bundle", "dest-change-alert-keepalive-worker.js");
const args = process.argv.slice(2);
const argOf = (n, d) => {
  const i = args.indexOf(n);
  return i >= 0 && args[i + 1] !== undefined ? args[i + 1] : d;
};
const N = Number(argOf("--n", "3"));
const JSON_OUT = argOf("--json", null);
const ONLY = argOf("--only", null);
const CALIBRATE = args.includes("--calibrate");
const TOKEN = "signal-keepalive-test-token";
const IP = "203.0.113.7";

const say = (s) => console.log(s);
let couldNotCheck = false;

// A destination config the router's validator accepts and its live probe can verify against the stub sink.
const DEST_CONFIG = {
  endpoint: "https://s3.destchange-sink.test",
  bucket: "destchange-bucket",
  region: "auto",
  accessKeyId: "DESTCHANGETESTKEYID000000",
  secretAccessKey: "destchange-test-secret",
};

// ---------------------------------------------------------------------------------------------------------
// THE FOUR CASES. Each names ONE call site, the request that reaches it, the state it needs first, and the
// EXACT record it must leave. `expect` is what the repair at 347696bf claims: the record survives.
// ---------------------------------------------------------------------------------------------------------
const CASES = [
  // THE KNOWN POSITIVE OF THE RIGHT KIND, and it is first on purpose. noteTestOutcome at
  // router-destinations.ts:495 is a site the landed sweep DROVE and measured as KEEPS: same file, same
  // fireInBackground helper, same runtime, same deferred dispatch, same fresh isolate. If it reads LOSES
  // here then this instrument is measuring itself and every zero below is worthless.
  {
    id: "control-test-outcome-email",
    expect: "keep",
    site: "router-destinations.ts:495 POST /email/test (noteTestOutcome) -- KNOWN POSITIVE, measured KEEPS by the landed sweep",
    path: "/email/test",
    method: "POST",
    body: {},
    status: 200,
    control: true,
    agg: "testOutcomes",
    key: "email",
    seed: "none",
  },
  {
    id: "dest-change-set",
    expect: "keep",
    site: "router-destinations.ts:272 POST /destination (set/repoint)",
    path: "/destination",
    method: "POST",
    body: { config: DEST_CONFIG },
    status: 200,
    detail: "A backup destination was set/repointed.",
    seed: "none",
  },
  {
    id: "dest-change-put",
    expect: "keep",
    site: "router-destinations.ts:393 POST /destinations (add or edit)",
    path: "/destinations",
    method: "POST",
    body: { label: "destchange added", config: DEST_CONFIG },
    status: 200,
    detail: "A backup destination was added or edited.",
    seed: "none",
  },
  {
    id: "dest-change-remove",
    expect: "keep",
    site: "router-destinations.ts:406 POST /destinations/remove",
    path: "/destinations/remove",
    method: "POST",
    // One seeded destination PER DRIVE: removal is not idempotent, and a second remove of the same id is a
    // 400 that never reaches the alert line.
    seed: "per-drive",
    bodyFor: (i) => ({ id: `destchange-seed-${i}` }),
    status: 200,
    detail: "A backup destination removal was requested.",
  },
  {
    id: "dest-change-default",
    expect: "keep",
    site: "router-destinations.ts:416 POST /destinations/default",
    path: "/destinations/default",
    method: "POST",
    seed: "once",
    body: { id: "destchange-seed-0" },
    status: 200,
    detail: "The default backup destination was changed.",
  },
];

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

// THE SINK. Everything the drive sends off-worker lands here and nowhere else: the SigV4 destination probe
// (HEAD absent / PUT accepted / DELETE accepted / no object-lock configuration) and the webhook alert sink.
// It is a stub, not a fixture with opinions: it answers the four shapes probeDestination reads and counts the
// webhook posts so a wired case can say the delivery half really ran.
const sinkHits = { head: 0, put: 0, delete: 0, objectLock: 0, webhook: 0, other: [] };
const outbound = async (request) => {
  {
    const u = new URL(request.url);
    if (u.hostname === "hook.destchange-sink.test") {
      sinkHits.webhook++;
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }
    if (u.hostname === "s3.destchange-sink.test") {
      if (u.searchParams.has("object-lock")) {
        sinkHits.objectLock++;
        return new Response("", { status: 404 });
      }
      if (request.method === "HEAD") {
        sinkHits.head++;
        return new Response(null, { status: 404 });
      }
      if (request.method === "PUT") {
        sinkHits.put++;
        return new Response("", { status: 200, headers: { etag: '"destchange"' } });
      }
      if (request.method === "DELETE") {
        sinkHits.delete++;
        return new Response("", { status: 204 });
      }
    }
    sinkHits.other.push(`${request.method} ${u.host}${u.pathname}`);
    return new Response("destchange sink: unrouted", { status: 502 });
  }
};

function countOf(agg, key) {
  if (agg === null || typeof agg !== "object") return 0;
  const v = agg[key];
  if (v === undefined || v === null) return 0;
  if (typeof v === "number") return v;
  if (Array.isArray(v)) return v.length;
  if (typeof v === "object" && typeof v.count === "number") return v.count;
  return 0;
}

// historyMatches counts the notify-history rows for EXACTLY this call site: the dest-change event AND the
// detail string this one route composes. A row for another route, or another event, does not count.
function historyMatches(history, detail) {
  if (!Array.isArray(history)) return 0;
  return history.filter((h) => h !== null && typeof h === "object" && h.event === "dest-change" && h.detail === detail).length;
}

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
      outboundService: outbound,
      log: new Log(LogLevel.WARN),
    });
    await mf.ready;
    const hit = async (p, init) => {
      const r = await mf.dispatchFetch(`https://engine.test${p}`, init);
      return { status: r.status, text: await r.text() };
    };
    return { mf, hit };
  };

  // ---- CALIBRATION: prove this instrument can see the difference on a KNOWN pair --------------------------
  // The pair that matters is the FLOATING-PROMISE arm. The in-flight-subrequest arm is printed beside it
  // precisely because it reads N on BOTH holds: an outstanding subrequest keeps the context alive by itself,
  // so a harness reading only that arm cannot see this defect class at all and its zeros are worthless.
  if (CALIBRATE) {
    const { mf, hit } = await mkInstance();
    await hit("/refusal/awaited");
    const kpRaw = await hit("/refusal/read");
    const kpOk = kpRaw.status === 200 && (JSON.parse(kpRaw.text)["update-apply:validation"]?.count ?? 0) === 1;
    for (let i = 0; i < N; i++) await hit("/refusal/bare-delay?d=250");
    for (let i = 0; i < N; i++) await hit("/refusal/kept-delay?d=250");
    for (let i = 0; i < N; i++) await hit("/refusal/bare-slowdo?d=250");
    for (let i = 0; i < N; i++) await hit("/refusal/kept-slowdo?d=250");
    await new Promise((r) => setTimeout(r, 2500));
    const refRaw = await hit("/refusal/read");
    const slowRaw = await hit("/refusal/slowread");
    await mf.dispose();
    if (refRaw.status !== 200 || slowRaw.status !== 200 || !kpOk) {
      say("   THE READER DID NOT ANSWER, OR ITS AWAITED KNOWN POSITIVE WAS ABSENT -> COULD-NOT-CHECK");
      return 4;
    }
    const ref = JSON.parse(refRaw.text);
    const slow = JSON.parse(slowRaw.text);
    const bare = ref["restore-apply:validation"]?.count ?? 0;
    const kept = ref["drill:validation"]?.count ?? 0;
    say(`== CALIBRATION, ${N} each, identical work, only the hold differs ==`);
    say(`   floating promise      bare ${bare}/${N}   kept ${kept}/${N}`);
    say(`   in-flight subrequest  bare ${slow.bare}/${N}   kept ${slow.kept}/${N}   (the loopback's blind arm)`);
    if (kept !== N || bare !== 0) {
      say("   THIS HARNESS CANNOT SEE THE DEFECT CLASS (it needs kept=N and bare=0) -> COULD-NOT-CHECK");
      return 4;
    }
    say("   the instrument separates the two holds, so a zero below is a lost record and not a blind reader");
    return 0;
  }

  const auth = { authorization: `Bearer ${TOKEN}`, "content-type": "application/json" };

  // ---- THE HOLD TABLE: the LEAF drive of routeAuthChangeAlert, only the hold different ------------------
  // Not a drive over the product's own route, and labelled that way. It is what separates "the record was
  // abandoned" from "this drive never reached the line", which the native-dispatch reachability arm cannot do
  // for this record: the write that produces it is issued AFTER the outer response, so there is no
  // already-in-flight subrequest holding the context open for it on either arm.
  if (args.includes("--holds")) {
    const detail = "A backup destination was set/repointed.";
    say("== HOLD TABLE (LEAF drive of routeAuthChangeAlert; same alert, same DO, same reader, only the hold differs) ==");
    for (const wired of [false, true]) {
      for (const hold of ["bare", "waituntil", "await", "settle"]) {
        for (const defer of [true, false]) {
          const { mf, hit } = await mkInstance();
          try {
            if (wired) {
              const w = await hit("/signal/wire-alert-channel");
              if (w.status !== 200) {
                say(`  wired=${wired} hold=${hold} defer=${defer} WIRING FAILED ${w.status} -> COULD-NOT-CHECK`);
                couldNotCheck = true;
                continue;
              }
            }
            await hit("/signal/awaited");
            const kp = JSON.parse((await hit("/signal/read")).text);
            const kpOk = countOf(kp.adminCounters, "degraded-read-providers-list") >= 1;
            const before = wired ? historyMatches(kp.notifyHistory, detail) : countOf(kp.adminCounters, "alert-emit-dest-change-no-channel");
            for (let i = 0; i < N; i++) await hit(`/signal-alert-probe?hold=${hold}&defer=${defer ? "1" : "0"}`);
            await new Promise((r) => setTimeout(r, 1500));
            const after = JSON.parse((await hit("/signal/read")).text);
            const seen = (wired ? historyMatches(after.notifyHistory, detail) : countOf(after.adminCounters, "alert-emit-dest-change-no-channel")) - before;
            const other = Object.keys(after.adminCounters ?? {}).filter((k) => k.startsWith("alert-emit-"));
            say(`  ${(wired ? "wired  " : "unwired").padEnd(8)} hold=${hold.padEnd(10)} defer=${defer ? "yes" : "no "}  kp=${kpOk ? "OK" : "DEAD"}  seen=${seen}/${N}${other.length > 0 ? `   alert-emit keys: ${JSON.stringify(other)}` : ""}`);
            if (!kpOk) couldNotCheck = true;
          } finally {
            await mf.dispose();
          }
        }
      }
    }
    say(`   sink: webhook=${sinkHits.webhook} unrouted=${sinkHits.other.length}`);
    return couldNotCheck ? 4 : 0;
  }

  const rows = [];
  const emissionRan = new Map();
  const cases = ONLY === null ? CASES : CASES.filter((c) => c.id === ONLY);
  if (cases.length === 0) {
    say(`no case matched --only ${ONLY} -> COULD-NOT-CHECK`);
    return 4;
  }

  // driveOnce runs ONE arm of ONE case in its OWN isolate. wired=false is the no-channel path; wired=true
  // wires a webhook channel and a global rule first. defer=false is the REACHABILITY arm.
  const driveOnce = async (c, wired, defer) => {
    const { mf, hit } = await mkInstance();
    const webhookBefore = sinkHits.webhook;
    try {
      const setup = [];
      if (wired) {
        const w = await hit("/signal/wire-alert-channel");
        setup.push({ stage: "wire", status: w.status, body: w.text.slice(0, 200) });
        if (w.status !== 200) return { setup, setupOk: false, webhookDelta: 0 };
      }
      const seeds = c.seed === "per-drive" ? N : c.seed === "once" ? 1 : 0;
      for (let i = 0; i < seeds; i++) {
        const s = await hit(`/signal/seed-dest?id=destchange-seed-${i}`);
        setup.push({ stage: `seed-${i}`, status: s.status, body: s.text.slice(0, 200) });
        if (s.status !== 200) return { setup, setupOk: false, webhookDelta: 0 };
      }

      // Control 0: the reader's own known positive, AWAITED, taken AFTER the setup and before any drive, so
      // the `before` baseline already contains anything the setup left behind.
      await hit("/signal/awaited");
      const kpRaw = await hit("/signal/read");
      const kp = kpRaw.status === 200 ? JSON.parse(kpRaw.text) : null;
      const kpOk = kp !== null && countOf(kp.authSignals, "recovery-ratelimited") >= 1 && countOf(kp.adminCounters, "degraded-read-providers-list") >= 1 && countOf(kp.testOutcomes, "idp") >= 1;
      const measure = (snap) =>
        snap === null ? 0 : c.control === true ? countOf(snap[c.agg], c.key) : wired ? historyMatches(snap.notifyHistory, c.detail) : countOf(snap.adminCounters, "alert-emit-dest-change-no-channel");
      const before = measure(kp);

      const headers = { ...auth, "CF-Connecting-IP": IP };
      if (defer === false) headers["x-signal-defer"] = "0";
      const statuses = [];
      const bodies = [];
      for (let i = 0; i < N; i++) {
        const body = c.bodyFor ? c.bodyFor(i) : (c.body ?? {});
        const r = await hit(`/signal-defer/admin${c.path}`, { method: c.method, headers, body: JSON.stringify(body) });
        statuses.push(r.status);
        if (r.status !== c.status) bodies.push(r.text.slice(0, 240));
      }
      await new Promise((r) => setTimeout(r, 1500));
      const afterRaw = await hit("/signal/read");
      if (afterRaw.status !== 200) return { setup, setupOk: true, statuses, bodies, kpOk, readerReached: false, seen: 0, webhookDelta: sinkHits.webhook - webhookBefore };
      const after = JSON.parse(afterRaw.text);
      const seen = measure(after) - before;
      // What the aggregate ACTUALLY holds rides alongside, so a zero shows whether the key is absent or the
      // record landed under another name. EVERY alert-emit stage is listed, not only the one asserted: a
      // record that died at `resolve` instead of `no-channel` is a different fact from no record at all.
      const aggKeys = wired
        ? (Array.isArray(after.notifyHistory) ? after.notifyHistory.map((h) => `${h?.event}|${String(h?.detail).slice(0, 46)}`) : []).slice(0, 8)
        : Object.keys(after.adminCounters ?? {}).slice(0, 24);
      return { setup, setupOk: true, statuses, bodies, kpOk, readerReached: true, seen, aggKeys, webhookDelta: sinkHits.webhook - webhookBefore };
    } finally {
      await mf.dispose();
    }
  };

  for (const c of cases) {
    // The control asserts a testOutcomes key, which the channel wiring cannot affect, so it runs once.
    for (const wired of c.control === true ? [false] : [false, true]) {
      const deferred = await driveOnce(c, wired, true);
      const live = await driveOnce(c, wired, false);
      rows.push({ id: c.id, site: c.site, expect: c.expect, control: c.control === true, detail: c.detail, status: c.status, wired, ...deferred, live });
      // THE EMISSION-RAN EVIDENCE, kept per case. The wired arm posts to the stub webhook sink once per drive,
      // and that post happens INSIDE routeEmission, after resolve and before the record write. So a wired arm
      // that hit the sink N times proves the alert line executed N times, whatever the record then did. It is
      // carried onto the case's unwired rows too, because both wiring modes drive the identical route.
      if (wired) emissionRan.set(c.id, { deferred: deferred.webhookDelta ?? 0, live: live.webhookDelta ?? 0 });
    }
  }

  // ---- the controls, read off the rows ---------------------------------------------------------------
  let failures = 0;
  say(`== DESTINATION-CHANGE ALERT KEEP-ALIVE, ${N} drives per case, ONE FRESH ISOLATE PER ARM ==`);
  say(`   the key asserted: unwired = adminCounters["alert-emit-dest-change-no-channel"], wired = a notifyHistory row event=dest-change AND detail exactly the site's own`);
  for (const r of rows) {
    const label = `${r.id}/${r.wired ? "wired" : "unwired"}`;
    if (r.setupOk === false) {
      say(`  ${label.padEnd(34)} SETUP FAILED -> COULD-NOT-CHECK`);
      for (const s of r.setup) say(`       setup ${s.stage} status=${s.status} ${s.body}`);
      couldNotCheck = true;
      continue;
    }
    const kept = r.seen >= N;
    const zero = r.seen === 0;
    // REACHABILITY. For the CONTROL the native-dispatch arm is the reachability control the sweep used: the
    // record it asserts is written by a subrequest issued inside the caller's own turn, which the loopback
    // holds open by itself. For the four ALERT cases it is NOT, and that has to be said rather than assumed:
    // the record they assert is written AFTER the outer response, by a subrequest that does not exist yet when
    // the caller's turn ends, so neither arm has anything holding it open and a zero on both is the expected
    // reading of a LOST record rather than a missed drive. Their reachability is the emission-ran evidence:
    // the wired twin's N posts to the stub sink, made inside routeEmission itself.
    const ran = emissionRan.get(r.id);
    const reached = r.control === true ? (r.live.seen ?? 0) >= N : ran !== undefined && ran.deferred >= N && ran.live >= N;
    const verdict = !reached ? "NOT-REACHED" : kept ? "KEEPS" : zero ? "LOSES" : "PARTIAL";
    say(`  ${label.padEnd(34)} kp=${r.kpOk && r.live.kpOk ? "OK" : "DEAD"} st=${JSON.stringify(r.statuses)} ${verdict.padEnd(11)} seen=${r.seen}|${r.live.seen ?? 0}/${N}${ran ? `  emissionRan=${ran.deferred}|${ran.live}/${N}` : ""}`);
    if (r.bodies.length > 0) say(`       an off-status body: ${r.bodies[0]}`);
    if (!r.readerReached || !r.live.readerReached) {
      say("       THE READER DID NOT REACH ITS ENDPOINT -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!r.kpOk || !r.live.kpOk) {
      say("       THE AWAITED KNOWN POSITIVE WAS NOT READ BACK IN THIS ISOLATE: the reader is dead and this");
      say("       zero means nothing -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!r.statuses.every((s) => s === r.status)) {
      say(`       THE DRIVE DID NOT ANSWER ${r.status} ON EVERY ATTEMPT, so it did not reach the call site -> COULD-NOT-CHECK`);
      couldNotCheck = true;
    }
    if (r.status !== 429 && r.statuses.some((s) => s === 429)) {
      say("       AN UNASKED-FOR 429 APPEARED: the shared limiter refused before the call site, so this zero");
      say("       means nothing -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!reached) {
      say("       REACHABILITY NOT ESTABLISHED: the emission did not demonstrably execute (the wired twin did not");
      say("       post to the sink once per drive), so this zero is a drive that missed, not a finding -> COULD-NOT-CHECK");
      say(`       the arm held ${JSON.stringify((r.live.aggKeys ?? []).slice(0, 8))}`);
      couldNotCheck = true;
    }
    if (r.expect !== undefined) {
      const want = r.expect === "keep";
      if (want !== kept) {
        failures++;
        say(`       FAIL expected ${r.expect}, measured ${verdict}`);
        say(`       the deferred arm held ${JSON.stringify((r.aggKeys ?? []).slice(0, 8))}`);
      }
    }
  }
  say(`   sink: head=${sinkHits.head} put=${sinkHits.put} delete=${sinkHits.delete} objectLock=${sinkHits.objectLock} webhook=${sinkHits.webhook} unrouted=${sinkHits.other.length}`);
  if (sinkHits.other.length > 0) say(`   UNROUTED OUTBOUND (the stub did not answer these): ${JSON.stringify([...new Set(sinkHits.other)].slice(0, 6))}`);

  const out = { n: N, rows, failures, couldNotCheck, sinkHits };
  if (JSON_OUT) writeFileSync(JSON_OUT, `${JSON.stringify(out, null, 1)}\n`);
  if (couldNotCheck) {
    say("VERDICT: COULD-NOT-CHECK (exit 4). This is NOT a pass.");
    return 4;
  }
  say(failures === 0 ? "DEST-CHANGE ALERT KEEP-ALIVE PASS" : `DEST-CHANGE ALERT KEEP-ALIVE FAIL (${failures} arm(s))`);
  return failures === 0 ? 0 : 1;
}

main().then(
  (c) => process.exit(c),
  (e) => {
    console.error("DEST-CHANGE ALERT DRIVE FAILED:", e);
    process.exit(1);
  },
);
