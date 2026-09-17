// The control-plane STATUS route (GET /admin/control-plane/status) lives in its own file rather than
// router-identity.ts (which is already at the file's line-budget ceiling) -- the same reason
// handleControlPlaneRecoveryAck stays standalone. Any authenticated reader may read it (it
// carries no secret), exactly like /whoami; the console recovery banner polls it, and a recovery-required
// viewer (the post-wipe state) can still read it so the banner surfaces even before any Owner is restored.

import { maybeInjectControlPlaneRecoveryFault } from "./test-faults.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";

export async function handleControlPlaneStatus(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, sub } = ctx;
  switch (`${req.method} ${sub}`) {
    case "GET /control-plane/status": {
      // HARNESS-ONLY (no-op unless HARNESS_TEST_FAULTS): consumes an armed control-plane-recovery-
      // required fault and, when it fires, latches the REAL recovery-required flag via the SAME internal DO
      // route the cron health pass calls on a genuine wipe, so this read (and whoami, and the console banner)
      // see the real product behaviour rather than a spoofed response.
      await maybeInjectControlPlaneRecoveryFault(env, scheduler);
      return scheduler.fetch(doURL("/control-plane/recovery-status"), { method: "GET" });
    }
    default:
      return null;
  }
}
