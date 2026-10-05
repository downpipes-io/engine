// Bundles the runtime test Worker entry (test/runtime/scheduler-worker.ts) into a single
// ESM file workerd can load, using the esbuild that already ships with the toolchain (the
// same bundler wrangler uses internally). No network, offline.
//
// Why we bundle ourselves rather than hand Miniflare a .ts scriptPath: workerd's module
// loader does not transpile TypeScript or resolve bare ".ts" import specifiers, and the
// SchedulerDO graph is all TS with ".ts" specifiers. esbuild collapses the graph to one
// JS module with the Workers conditions, which Miniflare loads into a real workerd isolate.
//
// Exported as a function so the test imports and calls it (keeping a single source of truth
// for the build flags), and runnable directly (`node test/runtime/bundle.mjs`) to eyeball
// the output or surface a bundle error on its own.

import { build } from "esbuild";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { realpathSync } from "node:fs";

const here = dirname(fileURLToPath(import.meta.url));
const ENTRY = join(here, "scheduler-worker.ts");
const OUTFILE = join(here, ".bundle", "scheduler-worker.js");

export async function bundleSchedulerWorker() {
  const result = await build({
    entryPoints: [ENTRY],
    outfile: OUTFILE,
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "browser",
    // Workers/workerd resolve the "workerd" then "browser" export conditions; matching that
    // here keeps the bundled graph the same one the deploy would pick.
    conditions: ["workerd", "browser"],
    // crypto.randomUUID / crypto.getRandomValues / crypto.subtle are provided by the workerd
    // runtime as globals; never shim them.
    external: [],
    // Keep class names intact: the DO is bound by class_name "SchedulerDO" in the Miniflare
    // config, so esbuild must not mangle/rename it.
    keepNames: true,
    legalComments: "none",
    write: true,
    logLevel: "silent",
    metafile: false,
    sourcemap: false,
  });
  if (result.errors.length > 0) {
    throw new Error(`esbuild failed:\n${result.errors.map((e) => e.text).join("\n")}`);
  }
  return OUTFILE;
}

// Allow `node test/runtime/bundle.mjs` to run the build standalone (handy for debugging the
// module graph in isolation from Miniflare).
// realpathSync on BOTH sides: fileURLToPath alone does not canonicalise, and macOS ships /tmp as a
// symlink to private/tmp, which is the path every scratch worktree here sits under. Without this the
// comparison fails through a symlinked path and the module silently decides it is not the entry point.
if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  bundleSchedulerWorker()
    .then((out) => {
      console.log(`bundled -> ${out}`);
    })
    .catch((e) => {
      console.error(e);
      process.exit(1);
    });
}
