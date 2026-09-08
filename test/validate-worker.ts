// Validate the worker entrypoint (src/index.ts): fetch handler CORS, security headers,
// the immutable-headers regression, OPTIONS preflight, root path, the
// scheduled() handler swallowing a drive() error without crashing, AND the cron
// orchestration seal HAPPY PATH: scheduled() -> drive() ->
// /tick + /due -> runDownpipe -> /trigger -> seal -> /complete, plus buildAdapter's
// reserved-binding guard (RESERVED_BINDINGS). No network, no deploy.
// Run with: node test/validate-worker.ts
//
// This file is a thin orchestrator: the assertions live in the sibling area modules. It imports
// each group and CALLS them in the same order, then reports the shared `ok` tally and exits
// non-zero on any failure.
//   - validate-worker-http.ts    : root/404, CORS, security headers, immutable headers, run-now, error handler
//   - validate-worker-cron.ts    : scheduled() resilience + the cron reconciliation passes
//   - validate-worker-adapter.ts : buildAdapter reserved-binding guard + media dispatch
//   - validate-worker-digest.ts  : flushDigests delivery path
// Shared fixtures (the stubs/builders) live in validate-worker-helpers.ts.

import { failureCount } from "./validate-worker-helpers.ts";
import { run as runHttp } from "./validate-worker-http.ts";
import { run as runCron } from "./validate-worker-cron.ts";
import { run as runAdapter } from "./validate-worker-adapter.ts";
import { run as runDigest } from "./validate-worker-digest.ts";

async function main(): Promise<void> {
  console.log("worker entrypoint validations\n");

  // HTTP entrypoint: cases 1-8d (root, 404, CORS, security headers, TC-04 immutable headers,
  // run-now seal wiring, cache-control, last-resort error handler).
  await runHttp();

  // Cron orchestration: cases 9-11, 14-16 (scheduled() resilience, the seal happy path and its
  // negative controls, the guarded error-path /complete, and the post-run passes stocked + fail-open).
  await runCron();

  // buildAdapter: cases 12 + 12b (reserved-binding guard, media-source dispatch).
  await runAdapter();

  // flushDigests: case 13 (digest delivery path: fail / ok / empty).
  await runDigest();

  // -----------------------------------------------------------------------------------------
  // Done.
  // -----------------------------------------------------------------------------------------
  const failures = failureCount();
  console.log(failures === 0 ? "\nWORKER ENTRYPOINT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
