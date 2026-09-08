// denied-apply-audit pass: a runtime Worker ENTRYPOINT that serves the PRODUCTION admin router (handleAdmin,
// src/admin/router.ts) plus the PRODUCTION SchedulerDO, inside a real workerd isolate under Miniflare.
//
// WHY. This settles whether an UNAUTHORISED restore APPLY (confirm:true by a role lacking restore.apply)
// records the denied-apply audit row the engine's own comment promises at router-restore.ts:246, driven
// against a real workerd isolate rather than inferred by reading the source.
//
// It adds NO behaviour to the router: /admin/* goes straight to handleAdmin. The only extra surface is
// /do/*, which forwards to the DO exactly as test/runtime/scheduler-worker.ts does, so the driver can mint
// a session token for an already-role-granted email (the DO method the passkey login path itself calls)
// without running a WebAuthn ceremony in Node.
//
// NOT part of the production deploy.

import { handleAdmin } from "../../src/admin/router.ts";
import { SchedulerDO } from "../../src/sched/scheduler-do.ts";

export { SchedulerDO };

// The env shape the driver binds. Deliberately loose: handleAdmin takes the production Env, and the
// Miniflare bindings below are the subset the driven routes read.
interface DeniedApplyAuditEnv {
  SCHEDULER: DurableObjectNamespace;
  ADMIN_TOKEN: string;
  CONSOLE_ORIGIN: string;
}

export default {
  async fetch(req: Request, env: DeniedApplyAuditEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/do/")) {
      // The SAME instance name schedulerStub (router-helpers.ts) resolves, so the /do/ forwarder and the
      // production router address ONE DO: a session minted here is verified against the same signing key
      // and the same role table the router reads. A different name would silently split the two.
      const id = env.SCHEDULER.idFromName("account-scheduler");
      const stub = env.SCHEDULER.get(id);
      const inner = new Request(`https://do.invalid${url.pathname.slice("/do".length)}${url.search}`, req);
      return stub.fetch(inner);
    }
    const slide: { cookie: string | null } = { cookie: null };
    // sealNow is never reached (no run is triggered here); waitUntil is the real ExecutionContext one, so
    // every fire-in-background diagnostic write the router makes is kept alive exactly as in production.
    const runtime = {
      sealNow: () => {
        /* never driven by this pass */
      },
      waitUntil: (task: Promise<unknown>) => ctx.waitUntil(task),
    };
    // biome-ignore lint/suspicious/noExplicitAny: the driver binds the subset of Env the driven routes read.
    const resp = await handleAdmin(req, env as any, runtime, slide);
    const headers = new Headers(resp.headers);
    if (slide.cookie !== null) headers.append("set-cookie", slide.cookie);
    return new Response(resp.body, { status: resp.status, headers });
  },
};
