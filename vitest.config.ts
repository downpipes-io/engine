// vitest-pool-workers config: runs the STARTER Worker-entrypoint test in a
// REAL workerd isolate via @cloudflare/vitest-pool-workers, the same runtime a live Cloudflare
// deployment uses. This is ADDITIVE to the bespoke Node validators (npm run validate) and the
// existing Miniflare runtime suite (npm run test:runtime); none of those are touched.
//
// Why a separate pool config rather than folding into the validators: the validators drive the
// crypto/format port directly in Node and intentionally never boot a worker. This pool boots the
// PRODUCTION src/index.ts entry (the real module graph, both Durable Objects bound) so the fetch
// entrypoint is exercised end to end against workerd, which Node doubles cannot reach.
//
// The bindings, Durable Object classes and SQLite migrations are read straight from the production
// wrangler.toml so the test environment cannot drift from deploy. compatibilityDate matches it too.
//
// Config shape: vitest-pool-workers 0.16 (vitest 4) registers via the cloudflareTest() PLUGIN rather
// than the older defineWorkersProject/test.poolOptions form.
//
// Coverage REPORTING is enabled but NON-GATING for now (no thresholds). A blocking 85/90% threshold
// is a deferred follow-up to be raised as the suite grows; gating it today would red CI against a
// deliberately small starter suite.
import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      // Boot the real Worker entry in workerd with the production bindings/DOs/migrations.
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        // Match the production compatibility date so runtime semantics line up with deploy.
        compatibilityDate: "2026-06-01",
      },
    }),
  ],
  test: {
    // Only the vitest-pool-workers tests; the Node validators stay on `node test/validate-*.ts`
    // and the Miniflare runtime suite stays on `npm run test:runtime`.
    include: ["test/vitest/**/*.test.ts"],
    coverage: {
      // istanbul works in the workers pool (v8 coverage is not available inside workerd).
      provider: "istanbul",
      reporter: ["text", "json", "html"],
      // NON-GATING: no thresholds. Raising these to 85% general / 90% on src/crypto + src/format is
      // a documented deferred follow-up, done as the starter suite is filled out, so CI is not red
      // against a small initial test set.
      reportsDirectory: "coverage/vitest",
      include: ["src/**/*.ts"],
    },
  },
});
