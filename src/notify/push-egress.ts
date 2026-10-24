// push-egress.ts -- the operator egress allowlist (ASVS V13.2.4) as it applies to the audit-log push, the
// OTLP metrics push, the S3-drop sink and the syslog sink. The list is the same one the notification
// channels honour: an unset or empty list permits every public host, a set list permits only its entries
// (screenEgressAllowlist holds the match rule). The list is read from the scheduler DO each time it is
// needed, so a change applies to the next save and the next send.

import { noteSiteFault } from "../admin/site-faults.ts";
import { doURL } from "../do-url.ts";
import { screenEgressAllowlist } from "./types.ts";

// SchedulerFetcher is the one method of the scheduler stub this module uses.
export interface SchedulerFetcher {
  fetch(input: string, init?: RequestInit): Promise<Response>;
}

// PUSH_EGRESS_BLOCKED_CODE is the closed delivery reason recorded when the allowlist refuses a push target.
export const PUSH_EGRESS_BLOCKED_CODE = "egress-not-allowlisted" as const;

// readEgressAllowlist returns the account's current allowlist. It throws when the scheduler cannot answer,
// so a fault never reads as "no list set": a save fails and a send holds its cursor instead of passing.
export async function readEgressAllowlist(scheduler: SchedulerFetcher): Promise<string[]> {
  const resp = await scheduler.fetch(doURL("/config/egress-allowlist"), { method: "GET" });
  if (!resp.ok) throw new Error(`egress allowlist unreadable (DO responded ${resp.status})`);
  const body = (await resp.json()) as { egressAllowlist?: unknown };
  // The DO always answers a list (empty when none is set); an answer without one is a fault, not "no list".
  return requireEgressAllowlist(body.egressAllowlist, "egress allowlist unreadable (the answer carries no list)");
}

// requireEgressAllowlist turns a scheduler answer's egressAllowlist into the list, or throws the given message.
// The scheduler always answers a list (empty when none is set), and only an empty list permits every host. A
// missing field, a non-array or an array with a non-string element is a malformed answer: it never reads as
// "no list" and never loses elements, so a send that cannot read its list refuses.
export function requireEgressAllowlist(value: unknown, unreadableMessage: string): string[] {
  const list = parseEgressAllowlist(value);
  if (list === null) throw new Error(unreadableMessage);
  return list;
}

// parseEgressAllowlist answers the list, or null when the value is not an array of strings.
export function parseEgressAllowlist(value: unknown): string[] | null {
  return Array.isArray(value) && value.every((h): h is string => typeof h === "string") ? value : null;
}

// hostOfUrl returns the hostname of an absolute URL, or null when it does not parse.
function hostOfUrl(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch (e) {
    // The caller refuses a null host, so the push is not sent; the pack records that the stored target did not parse.
    noteSiteFault("notify.push-egress-url-parse", e);
    return null;
  }
}

// pushTargetAllowed reports whether a push target (an https URL, or a bare syslog host) may be reached under
// the allowlist. An unparseable URL is refused.
export function pushTargetAllowed(target: string, kind: "url" | "host", allowlist: readonly string[] | undefined): boolean {
  const host = kind === "url" ? hostOfUrl(target) : target;
  if (host === null) return false;
  return screenEgressAllowlist(host, allowlist);
}

// PUSH_EGRESS_REFUSAL is the 400 text a save returns when the allowlist refuses a syslog host.
export const PUSH_EGRESS_REFUSAL = "host is not on the egress allowlist";
