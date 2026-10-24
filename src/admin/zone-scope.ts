// zone-scope.ts -- the save-time zone check for a cf-config source (see sources/zone-account.ts for why).
// The scheduler cannot reach the Cloudflare API, so the Worker checks a submitted zoneId before it forwards
// the downpipe. With no discovery token yet there is nothing to look the zone up with; the run path checks it.

import { zoneRefused } from "../sources/zone-account.ts";
import type { Env } from "../env.d.ts";
import { jsonError } from "./router-core.ts";
import { resolveDiscoveryToken } from "./router-helpers.ts";

const ZONE_REFUSAL = "the zoneId is not a zone of the source's account";

// zoneSaveRefusal returns a 400 when a cf-config source names a zone outside its account, else null.
export async function zoneSaveRefusal(env: Env, scheduler: DurableObjectStub, config: unknown): Promise<Response | null> {
  const source = (config as { source?: { type?: unknown; accountId?: unknown; zoneId?: unknown } } | null)?.source;
  if (source === undefined || source === null || source.type !== "cf-config") return null;
  if (typeof source.zoneId !== "string" || source.zoneId === "") return null;
  const token = await resolveDiscoveryToken(scheduler, env);
  if (token === null) return null;
  return (await zoneRefused(token, source)) ? jsonError(ZONE_REFUSAL, 400) : null;
}

// zoneBulkRefusal applies zoneSaveRefusal to every item of a bulk body; one refused item refuses the batch.
export async function zoneBulkRefusal(env: Env, scheduler: DurableObjectStub, bodyText: string): Promise<Response | null> {
  let items: unknown;
  try { // nosemgrep: incident-catch-returns-empty -- the DO route refuses an unparseable body with its own 400
    items = (JSON.parse(bodyText) as { downpipes?: unknown }).downpipes;
  } catch {
    // site-fault-waiver: src/admin/zone-scope.ts:zoneBulkRefusal:catch:1 -- the DO route refuses an unparseable body with its own 400
    return null;
  }
  if (!Array.isArray(items)) return null;
  for (const item of items) {
    const refused = await zoneSaveRefusal(env, scheduler, item);
    if (refused !== null) return refused;
  }
  return null;
}
