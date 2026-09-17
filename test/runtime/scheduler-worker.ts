// Minimal Worker ENTRYPOINT used ONLY by the real-workerd runtime tests
// (test/runtime/runtime.scheduler-do.test.ts), bundled by esbuild and loaded into a real
// workerd isolate by Miniflare. It is NOT part of the production deploy (the production
// entry is src/index.ts) and is not referenced by `npm run validate` / `tsc`.
//
// WHY a dedicated entry rather than reusing src/index.ts:
//  - src/index.ts also exports RunSealDO, whose module graph (seal/runstate.ts ->
//    admin/router.ts, keys-env.ts, dest/factory.ts, the whole seal pipeline) is far larger
//    and would have to load in workerd just to bind a DO this suite never exercises.
//  - This suite is about the SchedulerDO concurrency plane (run-lock, runlogIndex, alarm),
//    so we bind ONLY the SCHEDULER namespace and import ONLY SchedulerDO. A smaller module
//    graph is more likely to load cleanly in workerd and isolates the unit under test.
//
// The DO itself is byte-for-byte the production class (src/sched/scheduler-do.ts); this
// file adds no behaviour; it only forwards an HTTP request to a single, fixed DO instance
// so the test can drive the DO's own HTTP surface (the same surface src/index.ts's router
// reaches it through). A request to /do/<path> is forwarded to scheduler stub "runtime"
// at /<path>, preserving method, body and the X-Downpipes-Caller header the DO reads.

import { SchedulerDO } from "../../src/sched/scheduler-do.ts";

export { SchedulerDO };

interface RuntimeEnv {
  SCHEDULER: DurableObjectNamespace;
}

export default {
  async fetch(req: Request, env: RuntimeEnv): Promise<Response> {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/do/")) {
      return new Response("not found", { status: 404 });
    }
    // One fixed DO instance for the whole suite: idFromName("runtime") is deterministic, so
    // every request in a test run lands on the SAME SchedulerDO (its storage persists across
    // requests within the Miniflare instance, exactly like a live deployment's singleton).
    const id = env.SCHEDULER.idFromName("runtime");
    const stub = env.SCHEDULER.get(id);
    // Rebuild the forwarded request against the DO's internal origin, dropping the "/do"
    // prefix so /do/runlog-lock/acquire reaches the DO as /runlog-lock/acquire.
    const innerPath = url.pathname.slice("/do".length) + url.search;
    // Spread body only for methods that carry one: RequestInit.body is optional and exactOptionalPropertyTypes
    // rejects an explicit undefined (a GET/HEAD must not carry a body anyway).
    const hasBody = req.method !== "GET" && req.method !== "HEAD";
    const forwarded = new Request(`https://scheduler.internal${innerPath}`, {
      method: req.method,
      headers: req.headers,
      ...(hasBody ? { body: await req.text() } : {}),
    });
    return stub.fetch(forwarded);
  },
};
