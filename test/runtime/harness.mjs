// Shared real-workerd harness for the SchedulerDO runtime tests.
//
// Boots a single Miniflare instance running a REAL workerd isolate (the same runtime a live
// Cloudflare deployment uses), loads the esbuild-bundled test Worker entry (which exports the
// PRODUCTION SchedulerDO class, byte-for-byte from src/sched/scheduler-do.ts), binds the
// SCHEDULER Durable Object namespace with the SQLite-backed migration the production
// wrangler.toml declares, and hands the test a tiny request helper plus dispose().
//
// This is the seam the Node validators (test/validate-scheduler.ts, validate-runlog-lock.ts)
// CANNOT reach: those drive the DO class directly over an in-memory MockStorage, single-
// threaded and serial, so the DO input gate, real DurableObjectStorage transactions, the real
// crypto, and real alarm scheduling are never exercised. Here they are.

import { Miniflare, Log, LogLevel } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { bundleSchedulerWorker } from "./bundle.mjs";

const here = dirname(fileURLToPath(import.meta.url));

// startScheduler bundles the worker entry (fresh each run, so a source edit is always
// reflected) and boots Miniflare. Returns:
//   - req(method, path, body?)  -> { status, body }  drives the DO's HTTP surface via /do/<path>
//   - reqAll(method, path, bodies[]) -> issues N requests CONCURRENTLY (Promise.all) so the test
//     can create true in-flight contention the serial Node doubles cannot.
//   - mf  (the Miniflare instance, for getDurableObjectNamespace etc.)
//   - dispose()  tears workerd down (always call in a finally).
export async function startScheduler() {
  const bundlePath = await bundleSchedulerWorker();
  const script = readFileSync(bundlePath, "utf8");

  const mf = new Miniflare({
    modules: true,
    script,
    // scriptPath anchors module resolution + sourcemaps to the bundle location.
    scriptPath: bundlePath,
    // Match the production wrangler.toml compatibility_date so runtime semantics line up with deploy.
    compatibilityDate: "2026-06-01",
    // Bind ONLY the SchedulerDO namespace. The production wrangler.toml also declares RUNSEAL
    // (RunSealDO) with a v2 SQLite migration, but this suite does not exercise it and binding it
    // would force its much larger module graph (seal pipeline, keys, dest factory) to load in
    // workerd. Per the wrangler.toml v1 migration, SchedulerDO is a new_sqlite_class.
    durableObjects: { SCHEDULER: { className: "SchedulerDO", useSQLite: true } },
    // Quiet unless something genuinely warns/errors (keeps test output readable; flip to DEBUG
    // when diagnosing a workerd load failure).
    log: new Log(LogLevel.WARN),
  });

  // Force the isolate to come up now (and surface any module-load error here, with context)
  // rather than on the first request inside a test case.
  await mf.ready;

  const req = async (method, path, body) => {
    const r = await mf.dispatchFetch(`https://scheduler.test/do${path}`, {
      method,
      headers: body !== undefined ? { "content-type": "application/json" } : {},
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    // The DO always answers JSON (it is the router's internal contract).
    const text = await r.text();
    let parsed;
    try {
      parsed = text.length ? JSON.parse(text) : null;
    } catch {
      parsed = text;
    }
    return { status: r.status, body: parsed };
  };

  // Fire many requests at once so they are genuinely in flight together against the single DO.
  const reqAll = async (method, path, bodies) => Promise.all(bodies.map((b) => req(method, path, b)));

  const dispose = async () => {
    await mf.dispose();
  };

  return { mf, req, reqAll, dispose };
}

// A minimal assert/report helper matching the existing validators' ok()/summary style, so the
// runtime suite's output reads the same way and a failure sets a non-zero exit.
export function makeReporter(title) {
  let failures = 0;
  console.log(title);
  const ok = (label, cond) => {
    console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
    if (!cond) failures++;
  };
  const done = (passBanner) => {
    console.log(failures === 0 ? `\n${passBanner}` : `\n${failures} FAILURE(S)`);
    return failures;
  };
  return { ok, done, failures: () => failures };
}

// A standard enabled KV downpipe config the trigger/lock tests reuse.
export function kvConfig(id, overrides = {}) {
  return {
    id,
    name: `Runtime pipe ${id}`,
    cadenceSeconds: 3600,
    enabled: true,
    source: { type: "kv", binding: "KV_runtime", include: [], exclude: [] },
    ...overrides,
  };
}

// Re-export for convenience so the test file can import everything from the harness.
export { join, here };
