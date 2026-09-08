// Schedule / cron / timezone / blackout helpers for a downpipe schedule. These are pure free
// functions (no Date.now, no storage), so they are deterministic and unit-tested with a fixed clock.
// This module is a leaf that depends only on the other leaves cron.ts and types.ts.
import { localMinuteOfDay, MS_PER_MINUTE } from "./cron.ts";
import type { BlackoutResolveClass, BlackoutWindow, DownpipeSchedule } from "./types.ts";

// SCHEDULE_TZ_DEFAULT is the IANA zone a DownpipeSchedule's cron + blackout minutes are interpreted
// in when schedule.timeZone is omitted. UTC keeps a cron-without-tz unambiguous and matches how a
// bare crontab is read on a UTC host; an operator who wants local time sets timeZone explicitly.
const SCHEDULE_TZ_DEFAULT = "UTC";

// MINUTES_PER_DAY bounds blackout-window minute fields (minutes since local midnight). A window may
// name 1440 (end-of-day exclusive) so the inclusive bound is 0..1440.
export const MINUTES_PER_DAY = 1440;

// SCHEDULE_MAX_BLACKOUT_WINDOWS bounds the per-downpipe blackout list so a malformed/abusive config
// cannot make the deferral loop unbounded. A handful of maintenance windows is the real-world need;
// this is a generous backstop, rejected (not truncated) so the operator knows it did not land.
export const SCHEDULE_MAX_BLACKOUT_WINDOWS = 32;

// SCHEDULE_BLACKOUT_DEFER_MAX_HOPS bounds how many consecutive blackout windows a single fire may be
// deferred across before the scheduler gives up and uses the last computed instant (rather than
// looping forever on a pathological set of back-to-back windows that a validateConfig pass somehow
// admitted). With windows capped and each hop advancing strictly past a window end, the loop
// terminates well within this bound; it is a defence-in-depth ceiling, not a normal path.
const SCHEDULE_BLACKOUT_DEFER_MAX_HOPS = 64;

// JITTER_FRACTION is how much of the cadence the spread may consume. It is applied BACKWARDS (see
// jitteredCadence), so a run lands up to 10% EARLY and never late: the configured cadence is a
// CEILING on the gap between two runs, and 90% of it is the floor. A Daily downpipe fires 21.6h to
// 24h after the previous run, a Weekly one 151.2h to 168h.
//
// The direction is deliberate and was a correction, not the original design (the first implementation
// ADDED the offset). A cadence on a backup is a promise about how stale the newest archive may get, so
// overshooting it is the harmful direction: a positive offset made a "daily" downpipe read as 24h to
// 26.4h and breach the interval the operator asked for. Subtracting keeps the promise, at the cost of
// running slightly sooner and doing slightly more work.
//
// Anything deriving a RUN COUNT from a nominal cadence must divide by the 0.9 floor, not the cadence,
// or it under-counts runs by up to a ninth (11.1%). That includes cost and quota projections.
const JITTER_FRACTION = 0.1;

// ---- Schedule helpers (cron / timezone / blackout) ----------------------------------------------
// These are pure free functions (no Date.now, no storage) so they are deterministic and unit-tested
// with a fixed clock; computeNextRunAt (the DO method) is the only caller that injects the real now.

// scheduleTimeZone resolves the effective IANA zone for a schedule: the explicit timeZone, or UTC.
export function scheduleTimeZone(schedule: DownpipeSchedule | undefined): string {
  return schedule?.timeZone && schedule.timeZone.trim() !== "" ? schedule.timeZone : SCHEDULE_TZ_DEFAULT;
}

// jitteredCadence is the cadence path's next-run instant, factored out so the cron path can sit
// beside it. It spreads same-cadence downpipes off a shared tick BACKWARDS: the result is greater
// than now + 90% of the cadence and at most now + the cadence, so a run is early by up to
// JITTER_FRACTION and never late. See JITTER_FRACTION above for why the offset subtracts.
export function jitteredCadence(now: number, cadenceSeconds: number): number {
  const base = now + cadenceSeconds * 1000;
  const jitter = cadenceSeconds * 1000 * JITTER_FRACTION * Math.random();
  return Math.floor(base - jitter);
}

// blackoutCoversMinute reports whether a single window covers a given minute-of-day on a given
// weekday. The window is [startMinute, endMinute): non-wrapping windows test start <= m < end;
// a window that WRAPS past midnight (start > end) covers [start, 1440) U [0, end). The optional
// `days` filter (0=Sunday..6=Saturday) restricts the window to those weekdays. A degenerate
// start === end window covers NOTHING (an empty half-open interval), which is the safe reading.
function blackoutCoversMinute(w: BlackoutWindow, minuteOfDay: number, dow: number): boolean {
  if (Array.isArray(w.days) && w.days.length > 0 && !w.days.includes(dow)) return false;
  if (w.startMinute === w.endMinute) return false;
  if (w.startMinute < w.endMinute) return minuteOfDay >= w.startMinute && minuteOfDay < w.endMinute;
  // wrapping window (e.g. 22:00 -> 06:00)
  return minuteOfDay >= w.startMinute || minuteOfDay < w.endMinute;
}

// activeBlackout finds the FIRST window (in list order) covering the instant, or null. It evaluates
// the instant's wall-clock minute-of-day + weekday IN THE SCHEDULE'S ZONE so windows track DST the
// same way the cron does. A wrapping window is matched on whichever side the instant falls.
function activeBlackout(epochMs: number, schedule: DownpipeSchedule | undefined): BlackoutWindow | null {
  const windows = schedule?.blackoutWindows;
  if (!windows || windows.length === 0) return null;
  const { minuteOfDay, dow } = localMinuteOfDay(epochMs, scheduleTimeZone(schedule));
  for (const w of windows) if (blackoutCoversMinute(w, minuteOfDay, dow)) return w;
  return null;
}

// blackoutEndEpoch returns the first epoch AT OR AFTER `epochMs` that is no longer inside `w`, i.e.
// the instant the active window ends. It walks day-local: the window's endMinute is a minutes-since-
// local-midnight boundary, so the end instant is the next time the local clock reaches endMinute
// (today if the instant is before endMinute on a non-wrapping window, else the next day; for a
// wrapping window the end is endMinute on the day the instant rolls into). We resolve it by stepping
// minute-by-minute from epochMs until the window no longer covers the instant, bounded to one day of
// minutes (a window is at most 24h, so its end is always within 1440 minutes). Stepping in WALL-CLOCK
// space via the zone keeps it DST-correct (a window spanning a DST change ends at the right wall
// minute). Returns the first uncovered minute boundary.
// It also reports whether the walk EXHAUSTED its bound without finding an uncovered minute (`exhausted`), the
// pathological case the old code silently swallowed by returning the cursor: the caller stamps it as the closed
// end-walk-exhausted class rather than deferring on a value it could not prove is outside the window (G322).
function blackoutEndEpoch(epochMs: number, w: BlackoutWindow, schedule: DownpipeSchedule | undefined): { at: number; exhausted: boolean } {
  const tz = scheduleTimeZone(schedule);
  let cursor = Math.floor(epochMs / MS_PER_MINUTE) * MS_PER_MINUTE;
  // A blackout window is at most a full day; +1 minute of slack covers the boundary minute. We never
  // loop more than MINUTES_PER_DAY+1 times because the window cannot cover more than a day of minutes.
  for (let i = 0; i < MINUTES_PER_DAY + 1; i++) {
    const { minuteOfDay, dow } = localMinuteOfDay(cursor, tz);
    if (!blackoutCoversMinute(w, minuteOfDay, dow)) return { at: cursor, exhausted: false };
    cursor += MS_PER_MINUTE;
  }
  // Unreachable for a well-formed (<=24h) window; return the cursor so we never hang, flagged exhausted.
  return { at: cursor, exhausted: true };
}

// deferPastBlackouts pushes a computed fire time OUT of any active maintenance window: if the fire
// lands inside a window it is moved to the first instant after that window, repeated in case the
// next window butts up against the previous one (back-to-back windows). It only ever moves a fire
// LATER, never earlier, and never cancels it. With no windows (the common case) it returns the input
// unchanged, so the cadence/cron path is untouched for every schedule-less or window-less config.
export function deferPastBlackouts(epochMs: number, schedule: DownpipeSchedule | undefined): number {
  return deferPastBlackoutsResolved(epochMs, schedule).at;
}

// deferPastBlackoutsResolved is deferPastBlackouts with its RESOLUTION OUTCOME (G322 blackout-windows-silently-
// violated). The deferred instant is byte-identical to the previous implementation on every path, so scheduling
// behaviour is unchanged; what is new is the closed class the caller stamps on the downpipe for the support pack:
//   - a hop-ceiling exhaustion that leaves the fire INSIDE a window is the silent change-freeze VIOLATION
//     ("a backup ran during our declared freeze"),
//   - a window saved with startMinute === endMinute covers an empty half-open interval, so it has NEVER applied
//     ("we have a freeze window that does nothing") -- reported even when the fire was outside the windows,
//     because the inertness is the fault, not the individual fire,
//   - an end-walk that cannot find an uncovered minute (or does not advance) bails on a value it cannot prove is
//     outside the window.
// The class is stamped WITHOUT the window minutes or days, consistent with the schedule-string pack exclusion.
export function deferPastBlackoutsResolved(epochMs: number, schedule: DownpipeSchedule | undefined): { at: number; class: BlackoutResolveClass } {
  const windows = schedule?.blackoutWindows;
  if (!windows || windows.length === 0) return { at: epochMs, class: "ok" };
  // A degenerate (start === end) window is inert for EVERY fire, so it is a standing config fault, detected up
  // front rather than inferred from one fire's path. Config validation now refuses it on the write path; this
  // catches a record stored by the older, looser validator.
  const degenerate = windows.some((w) => w !== null && typeof w === "object" && w.startMinute === w.endMinute);
  let cls: BlackoutResolveClass = degenerate ? "degenerate-window-inert" : "ok";
  let t = epochMs;
  for (let hop = 0; hop < SCHEDULE_BLACKOUT_DEFER_MAX_HOPS; hop++) {
    const w = activeBlackout(t, schedule);
    if (!w) return { at: t, class: cls };
    const end = blackoutEndEpoch(t, w, schedule);
    // An end-walk that ran out of minutes without leaving the window did not PROVE the instant it returns is
    // outside it; the deferral proceeds exactly as before (unchanged behaviour) but the class records it.
    if (end.exhausted) cls = "end-walk-exhausted";
    // Guard against a non-advancing step (a degenerate window): if the end did not move past t, bail
    // with t rather than spinning. blackoutEndEpoch always returns an uncovered minute >= t, so this
    // is defence-in-depth only -- but a bail leaves the fire INSIDE the window, so it is recorded.
    if (end.at <= t) return { at: t, class: "end-walk-exhausted" };
    t = end.at;
  }
  // The hop ceiling was exhausted. If the fire time is STILL covered by a window, the run will fire inside the
  // customer's declared change freeze: that is the violation the pack must carry.
  return { at: t, class: activeBlackout(t, schedule) !== null ? "hop-ceiling-fired-inside-window" : cls };
}
