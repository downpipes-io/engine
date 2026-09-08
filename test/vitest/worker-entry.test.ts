// STARTER vitest-pool-workers test: exercises the engine's Worker fetch
// entrypoint (src/index.ts) inside a REAL workerd isolate, with the production module graph and
// both Durable Objects (SchedulerDO, RunSealDO) bound exactly as wrangler.toml declares them.
//
// This is the gap the Node validators cannot reach: they drive the crypto/format port directly and
// never boot a worker, so the default export's fetch() dispatch, the readiness probe and the
// security-header wrapping are never run under workerd. SELF.fetch routes through the actual deployed
// entry (the same one a live request hits), so a regression in the entrypoint or in the module graph
// that prevents the worker from loading at all is caught here.
//
// It is deliberately a SMALL starter set on unauthenticated, no-state paths:
//   - GET /ready  : the §12 readiness probe (no auth, reads no state). Proves the entry loads and
//                   answers, that both DO classes are exportable/bindable, and the base hardening
//                   headers are applied.
//   - an unknown path and an /admin path without credentials : prove the fetch dispatch routes and
//                   the unauthenticated admin surface fails closed rather than throwing.
//
// This file is the load-bearing seam later coverage on the entry + RunSealDO extends.
import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";

// ENGINE_VERSION is imported from the SAME source the worker reports, so the assertion tracks the
// real version constant rather than hard-coding a string that would drift.
import { ENGINE_VERSION } from "../../src/format/version.ts";

describe("Worker fetch entrypoint (real workerd)", () => {
  it("GET /ready returns the readiness payload with the engine version", async () => {
    const res = await SELF.fetch("https://engine.test/ready");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    const body = (await res.json()) as { status: string; service: string; version: string };
    expect(body.status).toBe("ok");
    expect(body.service).toBe("downpipe-engine");
    expect(body.version).toBe(ENGINE_VERSION);
  });

  it("GET /ready carries base hardening headers (proves withBaseSecurity ran)", async () => {
    const res = await SELF.fetch("https://engine.test/ready");
    // withBaseSecurity applies the engine's standard hardening set; nosniff is the most stable to
    // assert without coupling to the full header list (which other tests may extend).
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("an unknown path is routed by the entry and returns 404 (not a thrown 5xx)", async () => {
    const res = await SELF.fetch("https://engine.test/no-such-path");
    // The entry must answer with the 404 fall-through (src/index.ts handleNonAdminRoute) rather than
    // crash the isolate. Asserting the EXACT 404 catches a regression where the entry throws and a 500
    // (or any other 4xx/5xx) leaks through; a broad 4xx-or-5xx range would have hidden that.
    expect(res.status).toBe(404);
  });

  it("an /admin request without credentials returns 401 (fails closed, not a thrown 5xx)", async () => {
    const res = await SELF.fetch("https://engine.test/admin/status");
    // No bearer token and no Access JWT: the admin surface returns the 401 plaintext "unauthorised"
    // channel (src/admin/router.ts), not a 5xx from an unhandled throw. Asserting the exact 401 proves
    // the entry reaches the admin dispatch and fails closed; a 500/503 from a crashed isolate would NOT
    // satisfy this, which a broad 4xx-or-5xx range would have wrongly accepted.
    expect(res.status).toBe(401);
  });
});
