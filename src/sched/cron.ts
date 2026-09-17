// A self-contained 5-field cron parser + next-fire computer for the downpipe scheduler.
//
// This is the "time-of-day / day-of-week / timezone" refinement the scheduler header and the
// DownpipeConfig.cadenceSeconds comment flagged as a follow-up. It is ADDITIVE: cadenceSeconds
// stays the default cadence path; a downpipe only uses this when it carries an explicit cron
// schedule (see DownpipeConfig.schedule and how completeRun/addDownpipe compute nextRunAt).
//
// SCOPE (the standard 5-field crontab grammar, no extensions):
//   field 1  minute        0-59
//   field 2  hour          0-23
//   field 3  day-of-month  1-31
//   field 4  month         1-12
//   field 5  day-of-week   0-6  (0 = Sunday; 7 is ALSO accepted as Sunday, the common crontab alias)
//
// Each field is one of:
//   *              every value in the field's range
//   N              a single value
//   A-B            an inclusive range (A <= B)
//   A,B,C          a comma list of any of the above terms
//   */n            a step over the WHOLE range (n >= 1): the field's min, min+n, min+2n, ...
//   A-B/n          a step over a sub-range
//   A/n            a step from A to the field's max (A, A+n, A+2n, ...)
//
// NOT supported (rejected so a malformed expr never silently mis-schedules): names (JAN/MON),
// @-macros (@daily), seconds, L/W/#/? qualifiers, 6/7-field forms, negative or out-of-range values.
//
// DAY-OF-MONTH vs DAY-OF-WEEK (Vixie-cron semantics, encoded here intentionally): when BOTH dom and
// dow are RESTRICTED (neither is "*"), a day matches if it satisfies EITHER (the union, e.g.
// "0 0 13 * 5" fires on the 13th OR on any Friday). When one of them is "*", only the other
// constrains (the "*" side is treated as "no constraint"). This matches Vixie/cron and is the
// behaviour operators expect; it is covered by tests.
//
// TIMEZONE / DST (the rule this module implements, documented for the live-verification note):
//   - timeZone is an IANA zone (e.g. "Australia/Sydney", "America/New_York", "UTC"). The cron
//     fields are matched against the WALL-CLOCK time in that zone. We use Intl.DateTimeFormat
//     (available on workerd) to read the zone's wall-clock fields for any instant and to measure
//     the zone's UTC offset at any instant.
//   - To find the next fire we walk forward minute-by-minute in WALL-CLOCK space (cheap: at most a
//     bounded number of minutes ahead, see MAX_SEARCH_MINUTES), test each candidate's wall-clock
//     fields against the cron, and convert the FIRST match back to an epoch via the zone offset at
//     that wall instant.
//   - SPRING-FORWARD (a local hour that does NOT exist, e.g. 02:00-03:00 skipped): a cron whose
//     only match falls inside the skipped hour can never match that exact wall-clock minute, so the
//     minute-walk simply steps past it and fires at the next REAL wall-clock minute the cron
//     matches (which, mapped to epoch, is the next valid instant). It never hangs and never
//     double-fires.
//   - FALL-BACK (a local hour that occurs TWICE, e.g. 02:00-03:00 repeated): we always pick the
//     FIRST occurrence (the earlier UTC instant) of an ambiguous wall-clock time. Because
//     nextFireAfter is strictly-after the previous fire (we advance the cursor by a full minute and
//     require result > fromEpochMs), a fall-back can never cause the SAME scheduled minute to fire
//     twice: the second occurrence's epoch is still > the first, so the next computed fire is the
//     following matching minute, not a repeat.
//   - If reliable IANA math were unavailable we would fall back to a fixed UTC offset; it is not
//     needed here (Intl is present on workerd), so the IANA path is the only path. No UTC-offset
//     fallback shim is shipped; UTC itself is just the zone "UTC" through the same path.

import { fieldBounds, parsePart, parseStep } from "./cron-field.ts";
import type { CronSpec, FieldSpec } from "./cron-types.ts";

// CronSpec/FieldSpec live in cron-types.ts so the field-parsing helpers can reference them without a
// cycle. Re-exported here so existing importers of "./cron.ts" see no change.
export type { CronSpec, FieldSpec } from "./cron-types.ts";

// MAX_SEARCH_MINUTES bounds the forward minute-walk so a cron that can NEVER match (e.g. an
// impossible day like Feb 30, "0 0 30 2 *") fails fast with a clear error instead of spinning.
// Four years of minutes (covers a leap-year cycle so any legitimately-rare-but-valid expr, e.g.
// Feb 29, is reachable). At one cheap field test per minute this is a tight bounded loop, only ever
// fully traversed by an expression with no valid match, which we want to reject rather than hang.
const MAX_SEARCH_MINUTES = 4 * 366 * 24 * 60;

// MS_PER_MINUTE is milliseconds in one minute, used to floor an epoch to its minute boundary and to
// step the minute-walk. Exported so schedule-window.ts shares the one definition rather than repeating
// the literal (it walks the same minute grid for blackout windows).
export const MS_PER_MINUTE = 60_000;

// parseField parses ONE comma-separated cron field into a FieldSpec, validating every term against
// the field's [min,max] range. It throws an Error with a field-named, human-readable reason on any
// malformed term (so config-validate can surface exactly what was wrong, and a run never parses).
// The per-part work (step split, body-to-range resolution, range-checked value add) lives in
// cron-field.ts; this stays a thin orchestrator over the comma list.
function parseField(raw: string, field: keyof CronSpec): FieldSpec {
  const bounds = fieldBounds(field);

  if (typeof raw !== "string" || raw.trim() === "") {
    throw new Error(`cron ${field} field is empty`);
  }
  const term = raw.trim();
  const star = term === "*";
  const values = new Set<number>();

  // Each comma-separated part is: "*", "N", "A-B", or any of those with a "/n" step suffix.
  for (const partRaw of term.split(",")) {
    const part = partRaw.trim();
    if (part === "") throw new Error(`cron ${field} field has an empty list item`);
    parsePart(values, parseStep(part, field), bounds);
  }

  if (values.size === 0) throw new Error(`cron ${field} field matched no values`);
  return { star, values };
}

// parseCron parses a whole 5-field expression into a CronSpec, throwing a clear Error on a wrong
// field count or any malformed field. Exactly five whitespace-separated fields are required.
export function parseCron(expr: string): CronSpec {
  if (typeof expr !== "string") throw new Error("cron expression must be a string");
  const trimmed = expr.trim();
  if (trimmed === "") throw new Error("cron expression is empty");
  // Reject the unsupported @-macros and named fields up front with a clear message rather than a
  // confusing per-field "not a number" error.
  if (trimmed.startsWith("@")) {
    throw new Error(`cron @-macros (e.g. "${trimmed}") are not supported; use the 5-field form`);
  }
  const fields = trimmed.split(/\s+/);
  if (fields.length !== 5) {
    throw new Error(`cron expression must have exactly 5 fields (minute hour day-of-month month day-of-week), got ${fields.length}`);
  }
  const [minute, hour, dom, month, dow] = fields as [string, string, string, string, string];
  return {
    minute: parseField(minute, "minute"),
    hour: parseField(hour, "hour"),
    dom: parseField(dom, "dom"),
    month: parseField(month, "month"),
    dow: parseField(dow, "dow"),
  };
}

// validateCron is the config-time guard: it parses (throwing on malformed) and discards the result.
// validateConfig calls this so a bad cron is rejected at save time with the parser's reason, never
// at run time.
export function validateCron(expr: string): void {
  parseCron(expr);
}

// WallTime is a wall-clock instant decomposed into the fields cron matches against, in some target
// zone. dow is 0=Sunday..6=Saturday. All fields are 1-based where cron is (month, dom), 0-based
// where cron is (minute, hour, dow).
interface WallTime {
  year: number;
  month: number; // 1-12
  dom: number; // 1-31
  hour: number; // 0-23
  minute: number; // 0-59
  dow: number; // 0-6, Sunday = 0
}

// cronMatches tests whether a wall-clock instant satisfies the cron spec, applying the Vixie dom/dow
// union rule (when both dom and dow are restricted, EITHER matching is a match; when one is "*",
// only the other constrains).
export function cronMatches(spec: CronSpec, w: WallTime): boolean {
  if (!spec.minute.values.has(w.minute)) return false;
  if (!spec.hour.values.has(w.hour)) return false;
  if (!spec.month.values.has(w.month)) return false;
  const domOK = spec.dom.values.has(w.dom);
  const dowOK = spec.dow.values.has(w.dow);
  // Both restricted -> union; either restricted-by-* -> the other governs; both "*" -> both true.
  if (spec.dom.star && spec.dow.star) return true;
  if (spec.dom.star) return dowOK;
  if (spec.dow.star) return domOK;
  return domOK || dowOK;
}

// ---- Timezone math via Intl.DateTimeFormat -------------------------------------------------------
// A small formatter cache: building an Intl.DateTimeFormat is comparatively costly, and the
// minute-walk reads the zone offset/fields many times per call. Keyed by IANA zone id. The set of
// canonical IANA zones is bounded at roughly 600, so the cache is naturally bounded; the explicit
// ceiling below caps it regardless and bypasses the cache (returning a fresh formatter) once the
// ceiling is reached, avoiding unbounded growth without a full LRU.
const FORMATTER_CACHE_MAX = 512;
const formatterCache = new Map<string, Intl.DateTimeFormat>();

function buildFormatter(timeZone: string): Intl.DateTimeFormat {
  // Throws a RangeError for an unknown IANA zone, the caller (parse/validate) surfaces it.
  return new Intl.DateTimeFormat("en-US", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    weekday: "short",
  });
}

function getFormatter(timeZone: string): Intl.DateTimeFormat {
  let fmt = formatterCache.get(timeZone);
  if (fmt === undefined) {
    fmt = buildFormatter(timeZone);
    if (formatterCache.size < FORMATTER_CACHE_MAX) formatterCache.set(timeZone, fmt);
  }
  return fmt;
}

// isValidTimeZone probes an IANA zone id with Intl, returning false for an unknown zone instead of
// throwing, so validateConfig can produce its own clear message.
export function isValidTimeZone(timeZone: string): boolean {
  if (typeof timeZone !== "string" || timeZone.trim() === "") return false;
  try {
    // Constructing with an invalid timeZone throws RangeError on a conformant runtime.
    new Intl.DateTimeFormat("en-US", { timeZone });
    return true;
  } catch {
    return false;
  }
}

const WEEKDAY_INDEX: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

// wallTimeInZone decomposes a UTC epoch (ms) into the target zone's wall-clock fields.
function wallTimeInZone(epochMs: number, timeZone: string): WallTime {
  const parts = getFormatter(timeZone).formatToParts(new Date(epochMs));
  const get = (t: Intl.DateTimeFormatPartTypes): string => parts.find((p) => p.type === t)?.value ?? "";
  const year = Number(get("year"));
  const month = Number(get("month"));
  const dom = Number(get("day"));
  const hour = Number(get("hour"));
  const minute = Number(get("minute"));
  const wd = get("weekday");
  const dow = WEEKDAY_INDEX[wd];
  // The formatter is pinned to en-US weekday:short, so V8/workerd always yields Sun..Sat. If a
  // different Intl build ever returns another abbreviation, fail loudly rather than silently
  // treating every day as Sunday and misfiring cron jobs.
  if (dow === undefined) throw new Error(`wallTimeInZone: unexpected weekday string "${wd}" from Intl`);
  // h23 renders midnight as 00; guard the rare "24" some engines historically produced for midnight.
  const normHour = hour === 24 ? 0 : hour;
  return { year, month, dom, hour: normHour, minute, dow };
}

// zoneOffsetMs returns (wall-clock - UTC) in ms for the given instant in the zone, i.e. how far
// ahead of UTC the zone's wall clock reads at that instant. East-of-UTC is positive. Computed by
// reading the zone's wall-clock fields for the instant and differencing against the same fields
// interpreted as UTC. Stable across DST because it is measured AT the instant.
function zoneOffsetMs(epochMs: number, timeZone: string): number {
  const w = wallTimeInZone(epochMs, timeZone);
  const asUTC = Date.UTC(w.year, w.month - 1, w.dom, w.hour, w.minute, 0, 0);
  // asUTC is the epoch that WOULD have produced these wall fields if they were UTC. The real epoch
  // is epochMs (floored to the minute below by the caller). The difference is the zone offset, but
  // rounded to the source instant's seconds; we floor both to the minute so the difference is a
  // whole-minute (or whole-offset) quantity, which all real zone offsets are.
  const flooredEpoch = Math.floor(epochMs / MS_PER_MINUTE) * MS_PER_MINUTE;
  return asUTC - flooredEpoch;
}

// wallFieldsToEpoch converts a target-zone WallTime (year/month/dom/hour/minute, seconds = 0) to a UTC
// epoch (ms), resolving DST by measuring the zone offset at the candidate instant and correcting.
// For a SKIPPED local time (spring forward) the corrected instant lands just past the gap (the
// caller's minute-walk never proposes a skipped minute as a match anyway, because that minute does
// not appear in the zone's wall clock). For an AMBIGUOUS local time (fall back) this returns the
// FIRST (earlier) occurrence deterministically.
function wallFieldsToEpoch({ year, month, dom, hour, minute }: WallTime, timeZone: string): number {
  // Initial guess: treat the wall fields as if they were UTC.
  const guess = Date.UTC(year, month - 1, dom, hour, minute, 0, 0);
  // Correct by the offset measured at the guess, then re-measure at the corrected instant and
  // correct again. Two iterations settle every real zone (including a DST transition, where the
  // first correction may land on the other side of the boundary and the second pins it).
  const o1 = zoneOffsetMs(guess, timeZone);
  let epoch = guess - o1;
  const o2 = zoneOffsetMs(epoch, timeZone);
  if (o2 !== o1) epoch = guess - o2;
  return epoch;
}

// localMinuteOfDay returns the wall-clock minute-of-day (0-1439, where 0 = local midnight) and the
// weekday (0=Sunday..6=Saturday) for a UTC epoch in the given IANA zone. The scheduler's
// blackout-window logic uses it so its windows track the SAME zone (and DST) as the cron fields,
// without re-implementing the Intl decomposition. Throws for an unknown zone (same as the rest of
// this module), caught at config-validate time.
export function localMinuteOfDay(epochMs: number, timeZone: string): { minuteOfDay: number; dow: number } {
  const w = wallTimeInZone(epochMs, timeZone);
  return { minuteOfDay: w.hour * 60 + w.minute, dow: w.dow };
}

// nextFireAfter computes the next epoch (ms) STRICTLY AFTER fromEpochMs at which the cron next
// matches in the given IANA timeZone. It walks forward minute-by-minute in the target zone's
// wall-clock space (so DST gaps/overlaps are handled by the zone's own clock), tests each minute's
// fields against the cron, and converts the first match back to a UTC epoch. Throws if timeZone is
// not a valid IANA zone, or if no match exists within MAX_SEARCH_MINUTES (an impossible expression
// such as Feb 30), both caught at config-validate time, never silently.
export function nextFireAfter(expr: string, fromEpochMs: number, timeZone: string): number {
  if (!Number.isFinite(fromEpochMs)) throw new Error("nextFireAfter: fromEpochMs must be a finite number");
  if (!isValidTimeZone(timeZone)) throw new Error(`nextFireAfter: unknown IANA time zone "${timeZone}"`);
  const spec = parseCron(expr);

  // Start at the first whole minute STRICTLY after fromEpochMs (cron fires on minute boundaries; a
  // fire must be after the cursor, never at the same minute we just fired). Walk in wall-clock
  // space by reading the zone fields for each candidate epoch and, on a match, re-deriving the
  // exact epoch from those wall fields (so the returned instant is the true minute boundary in the
  // zone, DST-correct, not the UTC-stepped guess which can drift across a transition).
  let cursor = Math.floor(fromEpochMs / MS_PER_MINUTE) * MS_PER_MINUTE + MS_PER_MINUTE;

  for (let i = 0; i < MAX_SEARCH_MINUTES; i++) {
    const w = wallTimeInZone(cursor, timeZone);
    if (cronMatches(spec, w)) {
      const fire = wallFieldsToEpoch(w, timeZone);
      // The re-derived epoch must still be strictly after the source instant. Across a fall-back
      // overlap the wall fields can map to an EARLIER instant than the cursor (the cursor sat in
      // the second occurrence, the first occurrence is earlier); if so, this matching wall-minute
      // already passed, so keep walking. This is what guarantees no double-fire across fall-back.
      if (fire > fromEpochMs) return fire;
    }
    cursor += MS_PER_MINUTE;
  }
  throw new Error(`cron expression "${expr}" has no next fire within ${MAX_SEARCH_MINUTES} minutes (is the date impossible, e.g. Feb 30?)`);
}
