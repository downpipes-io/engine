// dest-io-attribution.ts -- WHICH destination each request timeout hit (from engine 0.3.7).
//
// dest-io.ts counts a request aborted at the fetch bound as the admin counter dest-io-timeout, fleet-wide and
// with no destination attached, so "8 timeouts" in the pack could not say which bucket black-holed. A
// destination instance built for a resolved destination id carries that id as a label (buildDestination's
// destinationId, Destination.labelIo), and each timeout it records is also tallied against the label here.
// An instance built with no id (the default, a probe with no id) counts as unattributed, never guessed.
//
// NO-CUSTODY: the key is the customer's own destination id (the class the pack already carries in
// destResolution and replication[]), control-stripped and clamped; every value is a clamped int or an epoch
// ms. Never an endpoint, a bucket, a status or an error text. This module is PURE and a leaf: the Worker side
// (dest-io.ts) builds the posted tally, the scheduler DO folds it (applyDestIoTimeouts) and the pack re-gates
// it (projectDestIoTimeouts), so the same bounds hold at every boundary.

/** The DO storage key of the folded per-destination timeout record. */
export const DEST_IO_TIMEOUTS_KEY = "diag:destiotimeouts";
/** How many destination ids one record (and one posted tally) may hold. Matches the destination probe cap. */
export const DEST_IO_TIMEOUT_IDS_CAP = 64;
const ID_MAX = 128;
const COUNT_CAP = 1_000_000;

/** One destination's folded timeouts: how many (clamped), and the DO clock (epoch ms) of the latest fold. */
export interface DestIoTimeoutRow {
  count: number;
  lastAt: number;
}
/** The stored record the scheduler DO folds tallies into, under DEST_IO_TIMEOUTS_KEY. */
export interface DestIoTimeouts {
  byDestination: Record<string, DestIoTimeoutRow>;
  unattributed?: DestIoTimeoutRow;
  // refused counts timeouts whose destination the capped record had no room for.
  refused?: number;
}
/** The tally the Worker posts: per labelled destination id, and the unlabelled remainder. */
export interface DestIoTimeoutTally {
  byId: Record<string, number>;
  unattributed: number;
}

function clampCount(n: unknown): number {
  return typeof n === "number" && Number.isFinite(n) && n > 0 ? Math.min(COUNT_CAP, Math.floor(n)) : 0;
}
function cleanId(id: string): string {
  let out = "";
  for (const ch of id) {
    const c = ch.charCodeAt(0);
    if (c >= 0x20 && c !== 0x7f) out += ch;
  }
  return out.slice(0, ID_MAX);
}

/**
 * applyDestIoTimeouts folds ONE posted tally into the stored record. PURE, and the DO's redaction chokepoint: a
 * non-object body folds nothing, an id is control-stripped and clamped, a count is clamped, and a new id past
 * the cap is refused and counted rather than evicting an older one.
 *
 * @param prior - the stored record, if any.
 * @param posted - the untrusted posted tally.
 * @param now - the DO clock.
 * @returns the new record.
 */
export function applyDestIoTimeouts(prior: DestIoTimeouts | undefined, posted: unknown, now: number): DestIoTimeouts {
  const out: DestIoTimeouts = { byDestination: { ...(prior?.byDestination ?? {}) }, ...(prior?.unattributed ? { unattributed: prior.unattributed } : {}), ...(prior?.refused ? { refused: prior.refused } : {}) };
  if (typeof posted !== "object" || posted === null) return out;
  const p = posted as { byId?: unknown; unattributed?: unknown };
  const byId = typeof p.byId === "object" && p.byId !== null ? (p.byId as Record<string, unknown>) : {};
  for (const [rawId, rawN] of Object.entries(byId)) {
    const n = clampCount(rawN);
    const id = cleanId(rawId);
    if (n === 0 || id === "") continue;
    const prev = out.byDestination[id];
    if (prev === undefined && Object.keys(out.byDestination).length >= DEST_IO_TIMEOUT_IDS_CAP) {
      out.refused = Math.min(COUNT_CAP, (out.refused ?? 0) + n);
      continue;
    }
    out.byDestination[id] = { count: Math.min(COUNT_CAP, (prev?.count ?? 0) + n), lastAt: now };
  }
  const un = clampCount(p.unattributed);
  if (un > 0) out.unattributed = { count: Math.min(COUNT_CAP, (out.unattributed?.count ?? 0) + un), lastAt: now };
  return out;
}

/**
 * projectDestIoTimeouts re-gates a stored record at the pack boundary: the same id clamp and count clamp, and
 * nothing but the three documented fields. Returns undefined when there is nothing to carry.
 *
 * @param raw - the record the DO returned (untrusted at this boundary).
 * @returns the projection, or undefined.
 */
export function projectDestIoTimeouts(raw: unknown): Record<string, unknown> | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const r = raw as { byDestination?: unknown; unattributed?: unknown; refused?: unknown };
  const row = (v: unknown): DestIoTimeoutRow | undefined => {
    if (typeof v !== "object" || v === null) return undefined;
    const x = v as { count?: unknown; lastAt?: unknown };
    const count = clampCount(x.count);
    return count > 0 ? { count, lastAt: clampCount(x.lastAt) } : undefined;
  };
  const byDestination: Record<string, DestIoTimeoutRow> = {};
  const src = typeof r.byDestination === "object" && r.byDestination !== null ? (r.byDestination as Record<string, unknown>) : {};
  for (const [k, v] of Object.entries(src).slice(0, DEST_IO_TIMEOUT_IDS_CAP)) {
    const id = cleanId(k);
    const rr = row(v);
    if (id !== "" && rr !== undefined) byDestination[id] = rr;
  }
  const unattributed = row(r.unattributed);
  const refused = clampCount(r.refused);
  if (Object.keys(byDestination).length === 0 && unattributed === undefined && refused === 0) return undefined;
  return { byDestination, ...(unattributed !== undefined ? { unattributed } : {}), ...(refused > 0 ? { refused } : {}) };
}
