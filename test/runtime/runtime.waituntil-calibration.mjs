// CALIBRATION for runtime.admin-refusal-keepalive.test.mjs -- can this harness distinguish a record that is written from a record that
// is abandoned when the request ends? Run this BEFORE trusting any product figure. It sweeps the delay
// between the response returning and the background write landing, across four arms:
//
//   bare-delay  / kept-delay   the write itself is behind an await (a floating promise)
//   bare-slowdo / kept-slowdo  the SUBREQUEST is still in flight when the response returns
//
// If bare == kept at every delay, the harness never tears the context down and CANNOT see the
// difference, so it must report could-not-check rather than clean.
//
// Usage: node test/runtime/runtime.waituntil-calibration.mjs [--n 5] [--delays 0,50,250,1000,3000] [--json <path>]
// Exit: 0 the instrument DISCRIMINATES at some delay; 4 it never discriminates (could-not-check); 1 driver fault.

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
const DELAYS = argOf("--delays", "0,50,250,1000,3000").split(",").map(Number);
const JSON_OUT = argOf("--json", null);

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

async function main() {
  const bundlePath = await bundle();
  const script = readFileSync(bundlePath, "utf8");
  const rows = [];
  let discriminated = false;
  let readerAlive = false;

  for (const d of DELAYS) {
    // A FRESH Miniflare per delay, so each row starts from an empty aggregate and no row can inherit
    // another's counts.
    const mf = new Miniflare({
      modules: true,
      script,
      scriptPath: bundlePath,
      compatibilityDate: "2026-06-01",
      durableObjects: { SCHEDULER: { className: "SchedulerDO", useSQLite: true }, REFUSAL_SLOW: { className: "RefusalSlowDO", useSQLite: true } },
      bindings: { ADMIN_TOKEN: "calibration-token", CONSOLE_ORIGIN: "https://console.test" },
      log: new Log(LogLevel.WARN),
    });
    await mf.ready;
    const hit = async (p) => {
      const r = await mf.dispatchFetch(`https://engine.test${p}`);
      return { status: r.status, text: await r.text() };
    };

    // Known positive of the right kind FIRST: an AWAITED write on the same recorder must be readable.
    await hit("/refusal/awaited");
    const kp = await hit("/refusal/read");
    let kpOk = false;
    try {
      kpOk = kp.status === 200 && (JSON.parse(kp.text)["update-apply:validation"]?.count ?? 0) === 1;
    } catch {
      kpOk = false;
    }
    if (kpOk) readerAlive = true;

    for (let i = 0; i < N; i++) await hit(`/refusal/bare-delay?d=${d}`);
    for (let i = 0; i < N; i++) await hit(`/refusal/kept-delay?d=${d}`);
    for (let i = 0; i < N; i++) await hit(`/refusal/bare-slowdo?d=${d}`);
    for (let i = 0; i < N; i++) await hit(`/refusal/kept-slowdo?d=${d}`);

    // Settle for well beyond the delay so anything that WOULD land has landed.
    await new Promise((r) => setTimeout(r, d + 2000));

    const refRaw = await hit("/refusal/read");
    const slowRaw = await hit("/refusal/slowread");
    if (refRaw.status !== 200 || slowRaw.status !== 200) {
      say(`d=${d}ms READER DID NOT REACH ITS ENDPOINT (read=${refRaw.status} slowread=${slowRaw.status})`);
      await mf.dispose();
      rows.push({ d, readerReached: false });
      continue;
    }
    const ref = JSON.parse(refRaw.text);
    const slow = JSON.parse(slowRaw.text);
    const row = {
      d,
      readerReached: true,
      knownPositiveAwaited: kpOk,
      bareDelay: ref["restore-apply:validation"]?.count ?? 0,
      keptDelay: ref["drill:validation"]?.count ?? 0,
      bareSlowdo: slow.bare,
      keptSlowdo: slow.kept,
    };
    row.discriminates = row.bareDelay !== row.keptDelay || row.bareSlowdo !== row.keptSlowdo;
    if (row.discriminates) discriminated = true;
    rows.push(row);
    say(
      `d=${String(d).padStart(5)}ms  kp=${kpOk ? "OK" : "DEAD"}  floating-promise bare=${row.bareDelay}/kept=${row.keptDelay}   in-flight-subrequest bare=${row.bareSlowdo}/kept=${row.keptSlowdo}   ${row.discriminates ? "<-- DISCRIMINATES" : "(identical)"}`,
    );
    await mf.dispose();
  }

  const out = { n: N, delays: DELAYS, rows, discriminated, readerAlive };
  if (JSON_OUT) writeFileSync(JSON_OUT, `${JSON.stringify(out, null, 1)}\n`);
  if (!readerAlive) {
    say("NO KNOWN POSITIVE EVER READ BACK -> the reader is dead. COULD-NOT-CHECK.");
    return 4;
  }
  if (!discriminated) {
    say("THE INSTRUMENT NEVER DISCRIMINATED at any delay: bare and kept are identical everywhere.");
    say("A product figure from this harness therefore proves nothing about survival. COULD-NOT-CHECK.");
    return 4;
  }
  say("THE INSTRUMENT DISCRIMINATES: it can see a record that is abandoned.");
  return 0;
}

main().then(
  (c) => process.exit(c),
  (e) => {
    console.error("CALIBRATION DRIVER FAILED:", e);
    process.exit(1);
  },
);
