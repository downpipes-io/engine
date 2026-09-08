// The control-plane STATUS route (GET /admin/control-plane/status). Any authenticated reader may read it (it
// carries no secret), exactly like /whoami; the console recovery banner polls it, and a recovery-required
// viewer (the post-wipe state) can still read it so the banner surfaces even before any Owner is restored.

import { doURL, type RouterCtx } from "./router-helpers.ts";

export async function handleControlPlaneStatus(ctx: RouterCtx): Promise<Response | null> {
  const { req, scheduler, sub } = ctx;
  switch (`${req.method} ${sub}`) {
    case "GET /control-plane/status": {
      return scheduler.fetch(doURL("/control-plane/recovery-status"), { method: "GET" });
    }
    default:
      return null;
  }
}
