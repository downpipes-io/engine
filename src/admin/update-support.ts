// The support window of a release (docs/SUPPORTED-VERSIONS.md). Fixes ship only in the next release. A
// release is supported until 90 days after its successor ships. The signed update channel carries
// `releases`, an append-only map from version to the RFC-3339 time that release shipped. The engine reads
// the map for its OWN running version and puts the result on GET /admin/updates as `supportedUntil` and
// `supportStatus`. The console shows a notice from 30 days before `supportedUntil`, and after it.
//
// supportedUntil(R) = releasedAt(successor of R) + 90 days, where the successor is the lowest released
// version above R in semver order. The latest release has no successor: it has no `supportedUntil` and its
// status is "supported". No date is typed by hand: every date comes from the signed channel.
//
// The map is additive. It sits inside the same detached hybrid signature as the rest of the channel, so
// nobody can change a date without the pinned key. An engine that predates it ignores it (isChannelShape
// tolerates unknown top-level fields). An absent or malformed map gives no date and no status; it never
// makes the channel fail.

import { log } from "../log.ts";

// SUPPORT_DAYS is how long a release stays supported after its successor ships.
export const SUPPORT_DAYS = 90;
// ENDING_DAYS is how many days before supportedUntil the status becomes "ending".
export const ENDING_DAYS = 30;

const DAY_MS = 24 * 60 * 60 * 1000;
const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})$/;

export type SupportStatus = "supported" | "ending" | "end-of-life";

export interface SupportView {
  supportedUntil?: string;
  supportStatus: SupportStatus;
}

// isReleasedAt is true for an RFC-3339 date-time that names a real calendar day and parses to an instant.
// The day check is needed because Date.parse rolls an impossible day, such as day 30 of month 2, into the next month.
export function isReleasedAt(v: unknown): v is string {
  if (typeof v !== "string" || !DATE_RE.test(v) || !Number.isFinite(Date.parse(v))) return false;
  const [y, m, d] = v.slice(0, 10).split("-").map(Number) as [number, number, number];
  const day = new Date(Date.UTC(y, m - 1, d));
  return day.getUTCMonth() === m - 1 && day.getUTCDate() === d;
}

function parts(v: string): [number, number, number] | null {
  const m = VERSION_RE.exec(v);
  return m === null ? null : [Number(m[1]), Number(m[2]), Number(m[3])];
}

function cmp(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1;
  return 0;
}

// sanitiseReleases narrows the raw map to well-formed `version -> releasedAt` pairs. A value that is not a
// plain object gives undefined (absent). `dropped` lists the versions whose date is malformed, so a caller
// can tell "no later release" from "a later release whose date cannot be read". A key that is not an
// X.Y.Z version is dropped with a warning. Pure apart from the log. The publisher uses it too.
export function sanitiseReleases(raw: unknown): { releases: Record<string, string>; dropped: string[] } | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    log("warn", "the signed channel's releases map is not an object; ignoring it (no support date is shown)");
    return undefined;
  }
  const releases: Record<string, string> = {};
  const dropped: string[] = [];
  for (const [version, at] of Object.entries(raw as Record<string, unknown>)) {
    if (parts(version) === null) {
      log("warn", "the signed channel's releases map has a key that is not a version; dropping it");
    } else if (isReleasedAt(at)) {
      releases[version] = at;
    } else {
      log("warn", "the signed channel's releases map has a malformed date; dropping it");
      dropped.push(version);
    }
  }
  return { releases, dropped };
}

// supportFor returns the support view of `running` at `nowMs`, or undefined when the channel cannot say:
// no map, a running version that is not X.Y.Z, or a later release whose date is malformed.
export function supportFor(raw: unknown, running: string, nowMs: number): SupportView | undefined {
  const s = sanitiseReleases(raw);
  if (s === undefined) return undefined;
  const core = running.trim().split("+")[0]!.split("-")[0]!;
  const me = parts(core);
  if (me === null) return undefined;
  const later = (v: string): boolean => {
    const p = parts(v);
    return p !== null && cmp(p, me) > 0;
  };
  if (s.dropped.some(later)) return undefined;
  let successor: string | undefined;
  for (const v of Object.keys(s.releases)) {
    if (later(v) && (successor === undefined || cmp(parts(v)!, parts(successor)!) < 0)) successor = v;
  }
  if (successor === undefined) return { supportStatus: "supported" };
  const until = Date.parse(s.releases[successor]!) + SUPPORT_DAYS * DAY_MS;
  const left = until - nowMs;
  const supportStatus: SupportStatus = left < 0 ? "end-of-life" : left <= ENDING_DAYS * DAY_MS ? "ending" : "supported";
  return { supportedUntil: new Date(until).toISOString(), supportStatus };
}
