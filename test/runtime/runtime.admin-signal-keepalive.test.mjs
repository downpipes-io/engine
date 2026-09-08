// runtime.admin-signal-keepalive.test.mjs -- do the OTHER fire-and-forget admin records survive the request?
//
// Run: node test/runtime/runtime.admin-signal-keepalive.test.mjs
//
// WHAT THIS EXISTS TO CATCH. runtime.admin-refusal-keepalive.test.mjs settled three bare
// `void recordAdminRefusal(...)` sites: under real workerd, with the scheduler DO subrequest dispatched a
// tick after the caller's turn, each lost EVERY record while the helper-based neighbour kept every one. That
// left the SAME SHAPE unsettled at fifty-five further call sites across ten other signals, and "the same
// shape" is not the same as "the same outcome": a site that hands the record off and then keeps working has
// a window the outstanding subrequest can land in, and a site that hands it off and returns does not.
//
// So this drives the sites rather than reasoning about them, and it drives them through the REAL admin
// router in a REAL workerd isolate (Miniflare) over a REAL socket, sharing the probe entry and the deferred
// dispatch that settled the first three (admin-refusal-keepalive-worker.ts, /signal-defer/admin).
//
// THE ONE THING THIS INSTRUMENT ADDS. Most of these signals fire only when a DO route the request depends on
// answers badly or not at all: an auth-plane edge signal is recorded precisely because the auth plane's own
// backing store failed, and a degraded-read counter is recorded because a read came back non-ok. A drive that
// cannot make a NAMED DO route misbehave never executes those lines, and would read a clean zero for a site
// it never reached. The probe entry therefore faults ONE DO pathname per case (and, on the shared /rate-check
// route, one key namespace), leaving every recorder and every read-back route on the real DO.
//
// CONTROLS, because the whole question is about an ABSENCE:
//   * per isolate, an AWAITED record into each aggregate this sweep reads, taken BEFORE any drive: if it is
//     not read back, the reader is dead and the zeros beside it mean nothing (could-not-check, exit 4)
//   * a 429 from the shared rate limiter is a refusal that never reaches the recorder, so a case whose drive
//     answered 429 without asking for one is could-not-check, never a clean zero
//   * a case that did not produce the status its call site returns did not reach that call site
//   * every case gets a FRESH isolate, because the per-caller limiter is shared and the aggregates are not
//   * CALIBRATION (--calibrate): the same recorder, the same DO route and the same storage, held three ways
//     (bare void / ctx.waitUntil / await) under this runtime. A harness that reads the same number on the
//     bare and the kept arm cannot see this defect class at all and its zeros are worthless.
//
// THE ASSERTION IS ON THE EXACT KEY, never on existence and never on a count alone: a mutant that records the
// wrong signal name still leaves a record behind, and a non-empty-aggregate check passes on it.
//
// Exit: 0 every case matched its expectation; 1 a case disagreed; 4 could-not-check.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, "admin-refusal-keepalive-worker.ts");
const OUT = join(here, ".bundle", "admin-signal-keepalive-worker.js");
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

// ---------------------------------------------------------------------------------------------------------
// THE CASES. Each names ONE call site, the request that reaches it, the DO fault that makes it fire, and the
// EXACT key its record must land under. `expect` is what the site is believed to do: "keep" (the record
// survives) or "lose" (it does not). The run reports the measurement either way; `expect` is what turns a
// measurement into a pass or a fail once a repair has been made.
// ---------------------------------------------------------------------------------------------------------
const CASES = [
  // ---- recordAuthSignalEdge: the auth-plane edge, where the record IS the evidence -----------------------
  {
    id: "admin-token-ratelimited-overcap",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:344,346 adminTokenRateLimitedViaDO (over-cap)",
    path: "/status",
    method: "GET",
    fault: { path: "/rate-check", mode: "deny", keyPrefix: "admin-token-ip:" },
    status: 429,
    agg: "authSignals",
    keys: ["admin-token-ratelimited", "admin-token-ratelimited-overcap"],
  },
  {
    id: "admin-token-ratelimited-malformed",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:344,349 adminTokenRateLimitedViaDO (answered, no verdict)",
    path: "/status",
    method: "GET",
    fault: { path: "/rate-check", mode: "noverdict", keyPrefix: "admin-token-ip:" },
    status: 429,
    agg: "authSignals",
    keys: ["admin-token-ratelimited", "admin-token-ratelimited-malformed"],
  },
  {
    id: "admin-token-ratelimited-unavailable",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:358,359 adminTokenRateLimitedViaDO (catch)",
    path: "/status",
    method: "GET",
    fault: { path: "/rate-check", mode: "throw", keyPrefix: "admin-token-ip:" },
    status: 429,
    agg: "authSignals",
    keys: ["admin-token-ratelimited", "admin-token-ratelimited-unavailable"],
  },
  {
    id: "break-glass-check-shape-invalid",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:294 breakGlassRetiredViaDO (answered, no boolean)",
    path: "/status",
    method: "GET",
    fault: { path: "/policy/break-glass-retired", mode: "noverdict" },
    status: 401,
    agg: "authSignals",
    keys: ["break-glass-check-shape-invalid"],
  },
  {
    id: "break-glass-check-unavailable",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:302 breakGlassRetiredViaDO (catch)",
    path: "/status",
    method: "GET",
    fault: { path: "/policy/break-glass-retired", mode: "throw" },
    status: 401,
    agg: "authSignals",
    keys: ["break-glass-check-unavailable"],
  },
  {
    id: "session-verify-verdict-malformed",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:235 verifyPasskeySessionViaDO (answered, no verdict)",
    path: "/status",
    method: "GET",
    cookie: true,
    fault: { path: "/passkey/session/verify", mode: "noverdict" },
    status: 401,
    agg: "authSignals",
    keys: ["session-verify-verdict-malformed"],
  },
  {
    id: "session-shape-invalid",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:239 verifyPasskeySessionViaDO (rotten accept)",
    path: "/status",
    method: "GET",
    cookie: true,
    fault: { path: "/passkey/session/verify", mode: "verified" },
    status: 401,
    agg: "authSignals",
    keys: ["session-shape-invalid"],
  },
  {
    id: "session-verify-unavailable",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-session.ts:258 verifyPasskeySessionViaDO (catch)",
    path: "/status",
    method: "GET",
    cookie: true,
    fault: { path: "/passkey/session/verify", mode: "throw" },
    status: 401,
    agg: "authSignals",
    keys: ["session-verify-unavailable"],
  },
  {
    id: "auth-limiter-verdict-malformed",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-core.ts:567 authRateLimited (answered, no verdict)",
    path: "/auth/recovery",
    method: "POST",
    body: { email: "nobody@example.test", code: "000000" },
    noAuth: true,
    fault: { path: "/rate-check", mode: "noverdict", keyPrefix: "ip:" },
    status: 429,
    agg: "authSignals",
    keys: ["auth-limiter-verdict-malformed"],
  },
  {
    id: "auth-limiter-unavailable",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-core.ts:582 authRateLimited (catch)",
    path: "/auth/recovery",
    method: "POST",
    body: { email: "nobody@example.test", code: "000000" },
    noAuth: true,
    fault: { path: "/rate-check", mode: "throw", keyPrefix: "ip:" },
    status: 429,
    agg: "authSignals",
    keys: ["auth-limiter-unavailable"],
  },
  {
    id: "limiter-verdict-malformed-answered",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-core.ts:260 rateLimited (answered, no verdict; then ADMITS and the route keeps working)",
    path: "/email/test",
    method: "POST",
    body: {},
    fault: { path: "/rate-check", mode: "noverdict", keyPrefix: "-" },
    agg: "authSignals",
    keys: ["limiter-verdict-malformed"],
  },
  {
    id: "limiter-verdict-malformed-catch",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-core.ts:279 rateLimited (catch; then ADMITS and the route keeps working)",
    path: "/email/test",
    method: "POST",
    body: {},
    fault: { path: "/rate-check", mode: "throw", keyPrefix: "-" },
    agg: "authSignals",
    keys: ["limiter-verdict-malformed"],
  },
  {
    id: "ssrf-endpoint-refused",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-destinations.ts:104 (the SSRF guard held)",
    path: "/destination",
    method: "POST",
    body: { config: { endpoint: "https://169.254.169.254/", bucket: "b", accessKeyId: "a", secretAccessKey: "s", region: "auto" } },
    status: 400,
    agg: "authSignals",
    keys: ["ssrf-endpoint-refused"],
  },
  // ---- bumpAdminCounter: the degraded-read counters -------------------------------------------------------
  {
    id: "degraded-read-dest-status",
    expect: "keep",
    signal: "bumpAdminCounter",
    site: "router-destinations.ts:224",
    path: "/destination",
    method: "GET",
    fault: { path: "/dest-status", mode: "throw" },
    status: 200,
    agg: "adminCounters",
    keys: ["degraded-read-dest-status"],
  },
  {
    id: "degraded-read-setup-state",
    expect: "keep",
    signal: "bumpAdminCounter",
    site: "router-destinations.ts:445",
    path: "/setup-state",
    method: "GET",
    fault: { path: "/dest-status", mode: "throw" },
    status: 200,
    agg: "adminCounters",
    keys: ["degraded-read-setup-state"],
  },
  {
    id: "degraded-read-status-presence",
    expect: "keep",
    signal: "bumpAdminCounter",
    site: "router-status.ts:51",
    path: "/status",
    method: "GET",
    fault: { path: "/downpipes", mode: "throw" },
    status: 200,
    agg: "adminCounters",
    keys: ["degraded-read-status-presence"],
  },
  {
    id: "degraded-read-discovery-config",
    expect: "keep",
    signal: "bumpAdminCounter",
    site: "router-discovery.ts:186",
    path: "/sources/discover",
    method: "GET",
    fault: { path: "/sources/discovery-config", mode: "throw" },
    status: 200,
    agg: "adminCounters",
    keys: ["degraded-read-discovery-config"],
  },
  // ---- noteTestOutcome: the Test button's answer ----------------------------------------------------------
  {
    id: "test-outcome-email-not-configured",
    expect: "keep",
    signal: "noteTestOutcome",
    site: "router-destinations.ts:495",
    path: "/email/test",
    method: "POST",
    body: {},
    status: 200,
    agg: "testOutcomes",
    keys: ["email"],
  },
  {
    id: "test-outcome-dest-verify",
    expect: "keep",
    signal: "noteTestOutcome",
    site: "router-destinations.ts:295 / 323",
    path: "/destination/verify",
    method: "POST",
    body: {},
    agg: "testOutcomes",
    keys: ["dest-verify"],
  },
  {
    id: "limiter-verdict-malformed-then-work",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-core.ts:260 rateLimited, on a route that then does AWAITED DO work before returning",
    path: "/downpipes",
    method: "POST",
    body: { id: "signal-probe", name: "signal probe", cadenceSeconds: 86400, enabled: false },
    fault: { path: "/rate-check", mode: "noverdict", keyPrefix: "-" },
    agg: "authSignals",
    keys: ["limiter-verdict-malformed"],
  },
  {
    id: "degraded-read-engine-account",
    expect: "keep",
    signal: "bumpAdminCounter",
    site: "router-sources.ts:133 resolveEngineAccount",
    path: "/cost/estate-size",
    method: "GET",
    fault: { path: "/sources/discovery-config", mode: "throw" },
    status: 200,
    agg: "adminCounters",
    keys: ["degraded-read-engine-account"],
  },
  {
    id: "degraded-read-lockout-preflight",
    expect: "keep",
    signal: "bumpAdminCounter",
    site: "router-ops.ts:348",
    path: "/policy/require-access",
    method: "POST",
    body: {},
    fault: { path: "/policy/lockout-preflight", mode: "throw" },
    status: 200,
    agg: "adminCounters",
    keys: ["degraded-read-lockout-preflight"],
  },
  {
    id: "discovery-token-set-refused",
    expect: "keep",
    signal: "recordDiscoveryTokenSet",
    site: "router-discovery.ts:344 (the token did not look like a Cloudflare token)",
    path: "/sources/discovery-token",
    method: "POST",
    body: { token: "not a token" },
    status: 400,
    agg: "discoveryHealth",
    keys: ["lastTokenSet outcome=refused failClass=token-invalid"],
    exact: { path: "lastTokenSet", value: { outcome: "refused", failClass: "token-invalid", accountsSeen: 0 } },
  },
  {
    id: "stepup-check-verdict-malformed",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-core.ts:499 requireStepUp (answered, no boolean) -- LEAF drive, the call site copied verbatim",
    leaf: true,
    path: "/signal-stepup?mode=noverdict",
    method: "GET",
    status: 401,
    agg: "authSignals",
    keys: ["stepup-check-verdict-malformed"],
  },
  {
    id: "stepup-check-unavailable",
    expect: "keep",
    signal: "recordAuthSignalEdge",
    site: "router-core.ts:510 requireStepUp (catch) -- LEAF drive, the call site copied verbatim",
    leaf: true,
    path: "/signal-stepup?mode=throw",
    method: "GET",
    status: 401,
    agg: "authSignals",
    keys: ["stepup-check-unavailable"],
  },
  {
    id: "test-outcome-push",
    expect: "keep",
    signal: "noteTestOutcome",
    site: "router-push.ts:304 / 308 / 320",
    path: "/push/test",
    method: "POST",
    body: {},
    agg: "testOutcomes",
    keys: ["push"],
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

// countOf reads a key's count out of whichever aggregate shape the DO returns: {k:{count:n}}, {k:n}, or
// {k:[row,...]} (the test-outcome ring). A shape it does not recognise reads 0 and is reported as such.
// atPath reads a dotted path out of a parsed aggregate, total: a missing segment reads undefined.
function atPath(obj, path) {
  let cur = obj;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = cur[seg];
  }
  return cur;
}

// matches is the EXACT-CONTENT assertion for a LAST-WRITE-WINS record (one object, overwritten each time),
// where a count says nothing. Every named field must equal the value the call site is contracted to write, so
// a mutant that records the wrong outcome or the wrong fail class fails here exactly as a wrong key would.
function matches(obj, want) {
  if (obj === null || typeof obj !== "object") return false;
  return Object.entries(want).every(([k, v]) => obj[k] === v);
}

function countOf(agg, key) {
  if (agg === null || typeof agg !== "object") return 0;
  const v = agg[key];
  if (v === undefined || v === null) return 0;
  if (typeof v === "number") return v;
  if (Array.isArray(v)) return v.length;
  if (typeof v === "object" && typeof v.count === "number") return v.count;
  return 0;
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
      log: new Log(LogLevel.WARN),
    });
    await mf.ready;
    const hit = async (p, init) => {
      const r = await mf.dispatchFetch(`https://engine.test${p}`, init);
      return { status: r.status, text: await r.text() };
    };
    return { mf, hit };
  };

  // ---- CALIBRATION: prove this instrument can see the difference on a KNOWN pair ------------------------
  // The pair is the FLOATING-PROMISE arm, not the in-flight-subrequest one. That distinction is the whole
  // reason the first harness built for this class was blind: a same-process loopback DO dispatches the
  // subrequest inside the caller's own turn, and the outstanding subrequest then keeps the context alive by
  // itself, so bare and kept both read N. This mode prints BOTH arms so the blindness is visible rather than
  // inherited, and it refuses unless the floating-promise arm separates them.
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
  const rows = [];
  const cases = ONLY === null ? CASES : CASES.filter((c) => c.id === ONLY || c.signal === ONLY);
  if (cases.length === 0) {
    say(`no case matched --only ${ONLY} -> COULD-NOT-CHECK`);
    return 4;
  }

  // driveOnce runs ONE arm of ONE case in its OWN isolate: the awaited known positive first, then N drives,
  // then the read-back. `defer` false is the REACHABILITY arm (the fault stays, the deferral goes).
  const driveOnce = async (c, defer) => {
    const { mf, hit } = await mkInstance();
    try {
      // Control 0: the reader's own known positive, AWAITED, taken before anything else in this isolate.
      await hit("/signal/awaited");
      const kpRaw = await hit("/signal/read");
      const kp = kpRaw.status === 200 ? JSON.parse(kpRaw.text) : null;
      const kpOk =
        kp !== null && countOf(kp.authSignals, "recovery-ratelimited") >= 1 && countOf(kp.adminCounters, "degraded-read-providers-list") >= 1 && countOf(kp.testOutcomes, "idp") >= 1;
      const before = kp === null || c.exact !== undefined ? {} : Object.fromEntries(c.keys.map((k) => [k, countOf(kp[c.agg], k)]));

      const headers = { ...(c.noAuth === true ? { "content-type": "application/json" } : auth), "CF-Connecting-IP": IP };
      if (c.cookie === true) headers.cookie = "__Host-downpipes_session=signal-not-a-real-session-token";
      if (defer === false) headers["x-signal-defer"] = "0";
      if (c.fault !== undefined) {
        headers["x-signal-fault-path"] = c.fault.path;
        headers["x-signal-fault-mode"] = c.fault.mode;
        if (c.fault.keyPrefix !== undefined) headers["x-signal-fault-keyprefix"] = c.fault.keyPrefix;
      }
      const statuses = [];
      const target = c.leaf === true ? `${c.path}${c.path.includes("?") ? "&" : "?"}defer=${defer === false ? "0" : "1"}` : `/signal-defer/admin${c.path}`;
      for (let i = 0; i < N; i++) {
        const r = await hit(target, {
          method: c.method,
          headers,
          ...(c.method === "GET" ? {} : { body: JSON.stringify(c.body ?? {}) }),
        });
        statuses.push(r.status);
      }
      await new Promise((r) => setTimeout(r, 1500));
      const afterRaw = await hit("/signal/read");
      if (afterRaw.status !== 200) return { statuses, kpOk, readerReached: false, seen: {} };
      const after = JSON.parse(afterRaw.text);
      const seen =
        c.exact === undefined
          ? Object.fromEntries(c.keys.map((k) => [k, countOf(after[c.agg], k) - (before[k] ?? 0)]))
          : { [c.keys[0]]: matches(atPath(after[c.agg], c.exact.path), c.exact.value) ? N : 0 };
      // The aggregate SHAPE rides alongside, so a case whose key never appears shows what the DO actually
      // stored rather than leaving a zero that could be a lost record or a mistyped key.
      const aggKeys = after[c.agg] !== null && typeof after[c.agg] === "object" ? Object.keys(after[c.agg]) : [];
      return { statuses, kpOk, readerReached: true, seen, aggKeys };
    } finally {
      await mf.dispose();
    }
  };

  for (const c of cases) {
    const deferred = await driveOnce(c, true);
    const live = await driveOnce(c, false);
    rows.push({ ...c, ...deferred, live });
  }

  // ---- the controls, read off the rows -------------------------------------------------------------------
  let failures = 0;
  say(`== SIGNAL SWEEP, ${N} drives per case, ONE FRESH ISOLATE PER CASE, deferred DO dispatch ==`);
  for (const r of rows) {
    const kept = r.keys.every((k) => (r.seen[k] ?? 0) >= N);
    const zero = r.keys.every((k) => (r.seen[k] ?? 0) === 0);
    const reached = r.keys.every((k) => (r.live.seen[k] ?? 0) >= N);
    const verdict = !reached ? "NOT-REACHED" : kept ? "KEEPS" : zero ? "LOSES" : "PARTIAL";
    const got = r.keys.map((k) => `${k}=${r.seen[k] ?? 0}|${r.live.seen[k] ?? 0}/${N}`).join(" ");
    say(`  ${r.id.padEnd(38)} kp=${r.kpOk && r.live.kpOk ? "OK" : "DEAD"} st=${JSON.stringify(r.statuses)} ${verdict.padEnd(11)} ${got}`);
    if (!r.readerReached || !r.live.readerReached) {
      say("       THE READER DID NOT REACH ITS ENDPOINT -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!r.kpOk || !r.live.kpOk) {
      say("       THE AWAITED KNOWN POSITIVE WAS NOT READ BACK IN THIS ISOLATE: the reader is dead and this");
      say("       zero means nothing -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (r.status !== undefined && !r.statuses.every((s) => s === r.status)) {
      say(`       THE DRIVE DID NOT ANSWER ${r.status} ON EVERY ATTEMPT, so it did not reach the call site -> COULD-NOT-CHECK`);
      couldNotCheck = true;
    }
    if (r.status !== 429 && r.statuses.some((s) => s === 429)) {
      say("       AN UNASKED-FOR 429 APPEARED: the shared limiter refused before the call site, so this zero");
      say("       means nothing -> COULD-NOT-CHECK");
      couldNotCheck = true;
    }
    if (!reached) {
      say("       THE REACHABILITY ARM (same fault, native dispatch) DID NOT RECORD EITHER, so this drive never");
      say("       executed the call site and its zero is not a finding -> COULD-NOT-CHECK");
      say(`       the reachability arm stored ${JSON.stringify((r.live.aggKeys ?? []).slice(0, 14))} under ${r.agg}`);
      couldNotCheck = true;
    }
    if (r.expect !== undefined) {
      const want = r.expect === "keep";
      if (want !== kept) {
        failures++;
        say(`       FAIL expected ${r.expect}, measured ${verdict}`);
      }
    }
  }

  const out = { n: N, rows: rows.map(({ aggregate, ...rest }) => rest), failures, couldNotCheck };
  if (JSON_OUT) writeFileSync(JSON_OUT, `${JSON.stringify(out, null, 1)}\n`);
  if (couldNotCheck) {
    say("VERDICT: COULD-NOT-CHECK (exit 4). This is NOT a pass.");
    return 4;
  }
  say(failures === 0 ? "ADMIN-SIGNAL KEEP-ALIVE PASS" : `ADMIN-SIGNAL KEEP-ALIVE FAIL (${failures} case(s))`);
  return failures === 0 ? 0 : 1;
}

main().then(
  (c) => process.exit(c),
  (e) => {
    console.error("SIGNAL SWEEP FAILED:", e);
    process.exit(1);
  },
);
