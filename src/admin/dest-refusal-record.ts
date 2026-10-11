// dest-refusal-record.ts -- the router's half of the record of a REFUSED destination save or clear (the closed
// vocabulary is in dest-save-refusal.ts; the scheduler writes the row in sched/dest-refusal-audit.ts). Used by
// router-destinations.ts for POST /destination and POST /destinations.

import { DEST_IN_USE_PREFIX, DEST_ORPHAN_PREFIX } from "../sched/dest-removal-text.ts";
import { doURL } from "../do-url.ts";
import type { DestProbeFailClass, DestRefusalDetail, DestRefusalProvider, DestSaveRefusal } from "./dest-save-refusal.ts";
import type { RouterCtx } from "./router-helpers.ts";

// DestRefused is a refusal of the save: the 400 the caller returns verbatim, and the closed facts the caller
// records for the support pack (never the sentence, which can quote the submitted endpoint or a store's error).
export interface DestRefused {
  response: Response;
  refusal: DestSaveRefusal;
  provider?: DestRefusalProvider;
  probeClass?: DestProbeFailClass;
  probeStatus?: number;
  regionHint?: string;
}

// recordDestRefusal writes the audit row for a REFUSED destination save or clear, so the support pack shows the
// attempt and the closed class that refused it. The scheduler re-validates the detail and caps the rows (one per
// class a minute, an hourly ceiling), so a client retry loop cannot flood the chain. Best-effort and awaited, so
// the row is not lost to Worker shutdown and the refusal the caller sees is never changed by it.
export async function recordDestRefusal(ctx: Pick<RouterCtx, "scheduler" | "caller" | "sourceIp">, detail: DestRefusalDetail): Promise<void> {
  try {
    await ctx.scheduler.fetch(doURL("/diag/dest-refusal-audit"), {
      method: "POST",
      body: JSON.stringify({ actorSubject: ctx.caller.subject, actorEmail: ctx.caller.email, actorMethod: ctx.caller.method, sourceIp: ctx.sourceIp, detail }),
      headers: { "content-type": "application/json" },
    });
  } catch {
    // site-fault-waiver: src/admin/dest-refusal-record.ts:recordDestRefusal:catch:1 -- the row is observation only; the refusal the caller sees was decided before it, and the admin-refusal counter beside it still counts the attempt
  }
}

// clearRefusalClass files a refused singular clear under its closed class, by the START of the scheduler's own
// refusal sentence (the two guards of removeDest), never by a word inside it (the downpipe names ride later).
export async function clearRefusalClass(resp: Response): Promise<DestSaveRefusal> {
  let message = "";
  try {
    const body = (await resp.clone().json()) as { error?: unknown };
    message = typeof body.error === "string" ? body.error : "";
  } catch {
    // site-fault-waiver: src/admin/dest-refusal-record.ts:clearRefusalClass:catch:1 -- an unreadable body files the refusal under the residual class clear-refused, which is the recorded outcome
  }
  if (message.startsWith(DEST_IN_USE_PREFIX)) return "clear-in-use";
  if (message.startsWith(DEST_ORPHAN_PREFIX)) return "clear-orphan-guard";
  return "clear-refused";
}

// refusedDetail is the closed detail a DestRefused carries to the row; id is the submitted id of an edit.
export function refusedDetail(r: DestRefused, id?: unknown): DestRefusalDetail {
  return { op: "set", refusal: r.refusal, ...(typeof id === "string" && id.trim() !== "" ? { id: id.trim() } : {}), ...(r.provider !== undefined ? { provider: r.provider } : {}), ...(r.probeClass !== undefined ? { probeClass: r.probeClass } : {}), ...(r.probeStatus !== undefined ? { probeStatus: r.probeStatus } : {}), ...(r.regionHint !== undefined ? { regionHint: r.regionHint } : {}) };
}
