import type { ConfigWriteResult } from "../sources/cf-config-surfaces.ts";

// decodeConfigSnapshot decodes a verified cf-config record's plaintext into its JSON config, or throws a
// coarse "snapshot incomplete" when the backup captured a truncated / unavailable surface (the source
// stores {_truncated} / {_unavailable} sentinels). This stops a partial snapshot from ever being diffed
// or written against live config.
export function decodeConfigSnapshot(bytes: Uint8Array): unknown {
  const data = JSON.parse(new TextDecoder().decode(bytes)) as unknown;
  if (data !== null && typeof data === "object" && ("_truncated" in data || "_unavailable" in data)) {
    // A NOT-ATTEMPTED marker is a different fact from a read that was tried and refused, and it has a
    // different remedy (the discovery cache, and usually the discovery token, not a retry), so it gets its
    // own message. Both still throw, so neither is ever diffed or written against live config.
    if ((data as { notAttempted?: unknown }).notAttempted === true) {
      throw new Error("snapshot incomplete: the surface was not attempted at backup time (a prior discovery could not read it)");
    }
    // A DEFINITIVE plan-entitlement gate (cf-config-core.ts's isCfPlanEntitlementError) is a different
    // fact from a read that was tried and refused: the account's plan does not include this product, so
    // there is nothing here to restore, and no token change fixes it. Both still throw (there is no
    // config to diff or write either way), but the remedy is opposite -- upgrading a plan is a business
    // decision the operator makes elsewhere, not a token to re-scope -- so it gets its own message.
    if ((data as { planGated?: unknown }).planGated === true) {
      throw new Error("snapshot incomplete: this account's Cloudflare plan did not include this surface at backup time, so there is nothing to restore");
    }
    throw new Error("snapshot incomplete: the surface was truncated or unavailable at backup time");
  }
  return data;
}

// summariseDiff turns a cf-config write diff into a short, secret-free summary for the dry-run plan (e.g.
// "2 to add, 1 to change"). A "remove" action is config the LIVE account has that the snapshot does not;
// the additive restore LEAVES it in place, so it is reported as "live-only", never as a deletion.
export function summariseDiff(res: ConfigWriteResult): string {
  const add = res.changes.filter((c) => c.action === "add").length;
  const change = res.changes.filter((c) => c.action === "change").length;
  const liveOnly = res.changes.filter((c) => c.action === "remove").length;
  const parts: string[] = [];
  if (add > 0) parts.push(`${add} to add`);
  if (change > 0) parts.push(`${change} to change`);
  if (liveOnly > 0) parts.push(`${liveOnly} live-only (left in place)`);
  return parts.length > 0 ? parts.join(", ") : "no changes (already matches the snapshot)";
}

// coarseCfReason maps a cf-config read / write exception to an enumerated, secret-free reason (the token,
// the account id and any field value never appear), matching the coarse-reason discipline of restore.
export function coarseCfReason(e: unknown): string {
  const m = (e as Error).message ?? "";
  // Check the not-attempted case FIRST, because it is the more specific reading of "snapshot incomplete" and
  // it points at a different lever. The surface was never read, so re-running a backup on its own changes
  // nothing until the discovery cache is refreshed with a token that can read it.
  if (/not attempted at backup time/i.test(m))
    return "the backup never captured this surface: an earlier configuration discovery could not read it, and automatic capture reads only the surfaces discovery found in use. Check the discovery token's read scope, then rediscover and run a backup before restoring it";
  // Checked BEFORE the generic "snapshot incomplete" branch below, whose pattern this message also
  // matches: a plan gate is the more specific reading and points at a different remedy (no token or
  // re-run fixes it; the account's plan does not carry the product).
  if (/this account's Cloudflare plan did not include this surface/i.test(m))
    return "this account's Cloudflare plan did not carry this surface at backup time, so there is nothing captured to restore";
  if (/snapshot incomplete/i.test(m)) return "the backup snapshot for this surface is incomplete (truncated or unavailable at backup time); re-run a backup before restoring it";
  if (/401|403|authenticat|permission|scope|forbidden/i.test(m)) return "the Cloudflare token was rejected or lacks the edit scope for this surface";
  if (/429|rate/i.test(m)) return "Cloudflare rate-limited the request; retry shortly";
  if (/JSON|parse|unexpected token/i.test(m)) return "the snapshot could not be decoded as config";
  if (/HTTP \d|status \d|network|timeout|fetch/i.test(m)) return "a Cloudflare API request failed; check connectivity and retry";
  return "the Cloudflare config could not be applied";
}
