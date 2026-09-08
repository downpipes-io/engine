// THE LAST-RESORT DISPATCH / SELECTION-PROBE / CORS RECORDERS.
//
// The Worker entry (index.ts) is where three separate blind spots live, and none of them touches DO state
// today:
//
//   The four last-resort catches (/admin dispatch, the non-admin dispatch that serves /support and
//         /metrics, the SCIM facade, the manual canary) log an errId and return a 500. The pack carries ZERO
//         trace of which surface threw or how often. The non-admin case is self-referential: a broken support
//         endpoint cannot report itself into a pack that never gets built -- but a fault RING surfaces it in
//         the next successful pull.
//
//   A run that fails "all destinations unreachable" carries the down destination IDS and no reasons.
//         The probes inside selectSealDestination knew whether it was an expired credential, a deleted
//         bucket, DNS, or a config that would not read, and threw every one of those answers away.
//
//   corsHeaders returns {} silently when an Origin does not match CONSOLE_ORIGIN. Move the console to a
//         new hostname (or misdeploy CONSOLE_ORIGIN) and the ENTIRE console goes dead, while the pack shows a
//         perfectly healthy engine with no admin traffic and no hint that the origin allowlist is rejecting
//         every preflight. The failure exists only as a browser-side CORS error, and the pack structurally
//         cannot carry browser-side state.
//
// All three route through recordDiagWrite, so a dropped record is itself counted in droppedWrites and lands
// the moment the DO comes back. None of them ever throws, and none alters the response the caller already
// decided.
//
// NO-CUSTODY: surfaces, route families, probe reasons and the auth-signal name are CLOSED enums; errId is the
// engine's existing irreversible 8-hex FNV exception id (the only join key to the Workers-Logs line); the
// destination label is the customer's own (the class replication[] already carries), clamped DO-side. The
// exception message, the stack, the raw path, the query string, the Origin header value, the configured
// CONSOLE_ORIGIN, the endpoint, the bucket and the credential NEVER ride.

import type { DestProbeReason, DispatchRouteFamily, DispatchSurface } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { doURL } from "../do-url.ts";

/**
 * routeFamilyOf reduces a request PATH to a closed product vocabulary member. The path itself (which carries
 * downpipe ids, run ids and a query string) never leaves this function: it is read ONLY to select an enum.
 *
 * @param pathname - the request path.
 * @returns the closed route family.
 */
export function routeFamilyOf(pathname: string): DispatchRouteFamily {
  const p = typeof pathname === "string" ? pathname : "";
  if (p.startsWith("/admin/downpipes") || p.startsWith("/admin/runs") || p.startsWith("/admin/trigger")) return "downpipes";
  if (p.startsWith("/admin/notify")) return "notify";
  if (p.startsWith("/admin/restore") || p.startsWith("/admin/drill")) return "restore";
  if (p.startsWith("/support") || p.startsWith("/admin/support") || p.startsWith("/metrics")) return "support";
  if (p.startsWith("/admin/keys")) return "keys";
  if (p.startsWith("/admin/identity") || p.startsWith("/admin/access") || p.startsWith("/scim")) return "identity";
  if (p.startsWith("/admin/destinations")) return "destinations";
  return "other";
}

/**
 * recordDispatchFault files ONE last-resort catch. Best-effort and never throwing: the 500 the caller is about
 * to return is already decided, and observing it must not delay or change it.
 *
 * @param scheduler - the scheduler DO stub.
 * @param row - the closed surface, the optional route family, the 8-hex errId, and the HTTP status.
 */
export async function recordDispatchFault(
  scheduler: DurableObjectStub,
  row: { surface: DispatchSurface; routeFamily?: DispatchRouteFamily; errId?: string; httpStatus?: number },
): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "dispatch-fault", () =>
      scheduler.fetch(doURL("/diag/dispatch-fault"), {
        method: "POST",
        body: JSON.stringify(row),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: a fault WHILE recording a fault must never mask the original */
  }
}

/**
 * classifyDestProbeError coarsens ONE destination-selection probe failure into a closed reason. It reads the
 * message ONLY to select an enum member and RETURNS that member; the message (which embeds the endpoint host,
 * the bucket and sometimes a chunk of S3 XML) never leaves this function.
 *
 * Auth first, deliberately: an expired or rotated credential is the single most common destination outage and
 * its fix (re-enter the key) is unrelated to every other class.
 *
 * @param e - the thrown probe error.
 * @returns the closed reason class.
 */
export function classifyDestProbeError(e: unknown): DestProbeReason {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (/is not configured|CONFIG_WRAP_KEY|could not unwrap|unreadable|not fully configured/i.test(m)) return "config-unreadable";
  if (/AccessDenied|InvalidAccessKeyId|SignatureDoesNotMatch|ExpiredToken|Unauthorized|Forbidden|status 40[13]/i.test(m)) return "auth";
  if (/NoSuchBucket|NoSuchKey|status 404|not found/i.test(m)) return "not-found";
  if (/timeout|timed out|deadline|aborted|ETIMEDOUT/i.test(m)) return "timeout";
  if (/status 5\d\d/i.test(m)) return "http-5xx";
  return "network";
}

/**
 * recordDestProbeFaults files the per-destination probe verdicts of ONE selection pass, so a run that fails
 * "all destinations unreachable" finally names a cause for each destination instead of listing bare ids.
 * A pass with no failures records nothing.
 *
 * @param scheduler - the scheduler DO stub.
 * @param rows - one {id, reason} per FAILING destination.
 * @param refusedUpstream - destinations the in-isolate accumulator refused before this call. They
 *        never reach the DO, so unless the count travels with the rows the pack cannot know they existed.
 */
export async function recordDestProbeFaults(scheduler: DurableObjectStub, rows: Array<{ id: string; reason: DestProbeReason }>, refusedUpstream = 0): Promise<void> {
  if (rows.length === 0) return;
  try {
    await recordDiagWrite(scheduler, "dest-probe-faults", () =>
      scheduler.fetch(doURL("/diag/dest-probe-faults"), {
        method: "POST",
        body: JSON.stringify({ rows, ...(refusedUpstream > 0 ? { refusedUpstream } : {}) }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort */
  }
}

/**
 * recordCorsRejection counts ONE request whose Origin failed the CONSOLE_ORIGIN match (G193). It rides the
 * EXISTING authSignals aggregate under the closed name cors-origin-rejected, so it needs no new pack section:
 * a non-zero count with no admin traffic is the unmistakable signature of "the console moved and nobody
 * updated CONSOLE_ORIGIN".
 *
 * The Origin header VALUE and the configured CONSOLE_ORIGIN are never sent: a count and a timestamp only.
 *
 * @param scheduler - the scheduler DO stub.
 */
export async function recordCorsRejection(scheduler: DurableObjectStub): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "auth-signal", () =>
      scheduler.fetch(doURL("/auth-signal"), {
        method: "POST",
        body: JSON.stringify({ name: "cors-origin-rejected" }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort */
  }
}
