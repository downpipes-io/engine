// Prove the 5-field cron parser + nextFireAfter + blackout deferral with a DETERMINISTIC clock and
// in-memory values only. No network, no deploy, no Date.now() in the assertions (every time is a
// fixed epoch passed explicitly). Run:
//   node test/validate-cron.ts
//
// What this covers:
//  - field parsing: "*", single values, lists ",", ranges "A-B", steps "*/n", "A-B/n", "A/n", the
//    day-of-week 7-as-Sunday alias;
//  - rejection of malformed expressions (wrong field count, out-of-range value, bad range, zero step,
//    @-macros, names, day-of-month 0) with a clear thrown error;
//  - nextFireAfter across minute / hour / day / month boundaries (strictly-after semantics);
//  - the Vixie dom/dow UNION rule (both restricted -> either matches; one "*" -> the other governs);
//  - a known IANA timezone shifts the fire vs UTC (Australia/Sydney, Asia/Kolkata half-hour offset);
//  - DST-FORWARD: a local time that does not exist on the spring-forward day fires at the next valid
//    instant (no hang, no double-fire); a local time that DOES exist that day is unaffected;
//  - DST-BACK: the first (earlier) occurrence of an ambiguous local time is taken, and the NEXT fire
//    is the following day, never a repeat of the doubled hour (no double-fire);
//  - an impossible expression (Feb 30) is rejected (throws) rather than hanging;
//  - blackout deferral: a fire inside a window moves to just after it; outside stays; wrapping
//    windows, back-to-back windows, weekday-filtered windows, and timezone-aware windows.

import {
  parseCron,
  validateCron,
  nextFireAfter,
  cronMatches,
  isValidTimeZone,
  localMinuteOfDay,
} from "../src/sched/cron.ts";
import { deferPastBlackouts, scheduleTimeZone } from "../src/sched/scheduler-do.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// throws asserts the thunk throws (a malformed-input rejection). It records the message so a wrong
// rejection (right throw, wrong reason) is still visible in the log.
function throws(label: string, fn: () => unknown): void {
  let threw = false;
  let msg = "";
  try {
    fn();
  } catch (e) {
    threw = true;
    msg = (e as Error).message;
  }
  ok(`${label}${threw ? ` (${msg.slice(0, 64)})` : ""}`, threw);
}

const U = (s: string): number => Date.parse(s); // UTC ISO -> epoch ms
// localISO renders an epoch in a zone as "M/D/YYYY, HH:MM:SS" for the DST assertions (compared by
// substring so the local wall-clock minute is what we check, independent of the host's own zone).
function localTime(ms: number, tz: string): string {
  return new Date(ms).toLocaleString("en-US", { timeZone: tz, hour12: false });
}

// ---- Field parsing -----------------------------------------------------------------------
function testFieldParsing(): void {
  {
    const star = parseCron("* * * * *");
    ok("parse: * minute has all 60 values", star.minute.values.size === 60 && star.minute.star === true);
    ok("parse: * hour has all 24 values", star.hour.values.size === 24);
    ok("parse: * dom has 31 values (1-31)", star.dom.values.size === 31 && star.dom.values.has(1) && star.dom.values.has(31));
    ok("parse: * month has 12 values", star.month.values.size === 12 && star.month.values.has(12));
    ok("parse: * dow has 7 values (0-6)", star.dow.values.size === 7 && star.dow.values.has(0) && star.dow.values.has(6));

    const single = parseCron("30 2 15 6 3");
    ok("parse: single minute 30", single.minute.values.size === 1 && single.minute.values.has(30) && single.minute.star === false);
    ok("parse: single hour 2", single.hour.values.has(2));
    ok("parse: single dom 15", single.dom.values.has(15));
    ok("parse: single month 6", single.month.values.has(6));
    ok("parse: single dow 3", single.dow.values.has(3));

    const list = parseCron("0,15,30,45 * * * *");
    ok("parse: list minute {0,15,30,45}", list.minute.values.size === 4 && [0, 15, 30, 45].every((v) => list.minute.values.has(v)));

    const range = parseCron("0 9-17 * * *");
    ok("parse: range hour 9-17 inclusive (9 values)", range.hour.values.size === 9 && range.hour.values.has(9) && range.hour.values.has(17) && !range.hour.values.has(8));

    const step = parseCron("*/15 * * * *");
    ok("parse: */15 minute = {0,15,30,45}", step.minute.values.size === 4 && [0, 15, 30, 45].every((v) => step.minute.values.has(v)));

    const subStep = parseCron("0-30/10 * * * *");
    ok("parse: 0-30/10 = {0,10,20,30}", subStep.minute.values.size === 4 && [0, 10, 20, 30].every((v) => subStep.minute.values.has(v)));

    const fromStep = parseCron("5/20 * * * *");
    ok("parse: 5/20 = {5,25,45}", fromStep.minute.values.size === 3 && [5, 25, 45].every((v) => fromStep.minute.values.has(v)));

    // day-of-week 7-as-Sunday alias normalises to 0
    const dow7 = parseCron("0 0 * * 7");
    ok("parse: dow 7 normalises to Sunday(0)", dow7.dow.values.size === 1 && dow7.dow.values.has(0));
    const dowRange = parseCron("0 0 * * 5-7");
    ok("parse: dow 5-7 = {5,6,0}", dowRange.dow.values.size === 3 && [5, 6, 0].every((v) => dowRange.dow.values.has(v)));

    // validateCron is the config-time guard (parses + discards)
    let vOK = true;
    try {
      validateCron("0 2 * * 1-5");
    } catch {
      vOK = false;
    }
    ok("validateCron: accepts a valid expression", vOK);
  }
}

// ---- Rejection of malformed expressions --------------------------------------------------
function testRejection(): void {
  {
    throws("reject: too few fields", () => parseCron("* * * *"));
    throws("reject: too many fields", () => parseCron("* * * * * *"));
    throws("reject: minute 60 out of range", () => parseCron("60 * * * *"));
    throws("reject: hour 24 out of range", () => parseCron("* 24 * * *"));
    throws("reject: dom 0 out of range", () => parseCron("* * 0 * *"));
    throws("reject: dom 32 out of range", () => parseCron("* * 32 * *"));
    throws("reject: month 13 out of range", () => parseCron("* * * 13 *"));
    throws("reject: dow 8 out of range", () => parseCron("* * * * 8"));
    throws("reject: zero step */0", () => parseCron("*/0 * * * *"));
    throws("reject: inverted range 5-1", () => parseCron("5-1 * * * *"));
    throws("reject: @-macro", () => parseCron("@daily"));
    throws("reject: named field", () => parseCron("0 0 * * MON"));
    throws("reject: non-numeric term", () => parseCron("a * * * *"));
    throws("reject: empty list item", () => parseCron("1,,2 * * * *"));
    throws("reject: empty string", () => parseCron("   "));
    throws("nextFireAfter: bad tz throws", () => nextFireAfter("* * * * *", U("2026-06-17T00:00:00Z"), "Mars/Phobos"));
    throws("nextFireAfter: non-finite from throws", () => nextFireAfter("* * * * *", NaN, "UTC"));
  }
}

// ---- nextFireAfter across boundaries (deterministic, UTC) --------------------------------
function testNextFireAfter(): void {
  {
    const from = U("2026-03-10T10:17:30Z");
    ok("next: every-minute -> next whole minute (strictly after)", nextFireAfter("* * * * *", from, "UTC") === U("2026-03-10T10:18:00Z"));
    ok("next: top-of-hour 0 * crosses to 11:00", nextFireAfter("0 * * * *", from, "UTC") === U("2026-03-10T11:00:00Z"));
    ok("next: */15 -> 10:30", nextFireAfter("*/15 * * * *", from, "UTC") === U("2026-03-10T10:30:00Z"));
    // day boundary: daily 02:30, current time is 10:17 -> tomorrow 02:30
    ok("next: daily 02:30 crosses the DAY boundary", nextFireAfter("30 2 * * *", from, "UTC") === U("2026-03-11T02:30:00Z"));
    // month boundary: "0 0 1 * *" (midnight on the 1st) from mid-March -> April 1 00:00
    ok("next: monthly 1st crosses the MONTH boundary", nextFireAfter("0 0 1 * *", from, "UTC") === U("2026-04-01T00:00:00Z"));
    // year boundary: Jan 1 00:00 from December
    ok("next: Jan-1 crosses the YEAR boundary", nextFireAfter("0 0 1 1 *", U("2026-12-15T12:00:00Z"), "UTC") === U("2027-01-01T00:00:00Z"));
    // strictly-after: a fire exactly on a matching minute returns the NEXT one, never the same minute
    ok("next: strictly-after (exact match minute is not returned)", nextFireAfter("0 * * * *", U("2026-03-10T11:00:00Z"), "UTC") === U("2026-03-10T12:00:00Z"));
    // a fire at :00.000 with seconds==0 still advances a full minute for "* * * * *"
    ok("next: from a whole minute advances exactly one minute", nextFireAfter("* * * * *", U("2026-03-10T10:18:00Z"), "UTC") === U("2026-03-10T10:19:00Z"));
  }
}

// ---- dom/dow union rule (Vixie cron) -----------------------------------------------------
function testUnion(): void {
  {
    const spec = parseCron("0 0 13 * 5"); // 13th of the month OR any Friday
    ok("union: matches the 13th (a Saturday) via dom", cronMatches(spec, { year: 2026, month: 6, dom: 13, hour: 0, minute: 0, dow: 6 }));
    ok("union: matches a Friday that is NOT the 13th via dow", cronMatches(spec, { year: 2026, month: 6, dom: 19, hour: 0, minute: 0, dow: 5 }));
    ok("union: does NOT match a non-13th non-Friday", !cronMatches(spec, { year: 2026, month: 6, dom: 14, hour: 0, minute: 0, dow: 0 }));
    // one side "*" -> only the other constrains
    const domOnly = parseCron("0 0 15 * *");
    ok("union: dom-only ignores weekday", cronMatches(domOnly, { year: 2026, month: 6, dom: 15, hour: 0, minute: 0, dow: 3 }) && !cronMatches(domOnly, { year: 2026, month: 6, dom: 16, hour: 0, minute: 0, dow: 1 }));
    const dowOnly = parseCron("0 0 * * 1"); // every Monday
    ok("union: dow-only ignores day-of-month", cronMatches(dowOnly, { year: 2026, month: 6, dom: 22, hour: 0, minute: 0, dow: 1 }) && !cronMatches(dowOnly, { year: 2026, month: 6, dom: 23, hour: 0, minute: 0, dow: 2 }));
  }
}

// ---- IANA timezone shifts the fire vs UTC ------------------------------------------------
function testTimezone(): void {
  {
    const from = U("2026-06-17T00:00:00Z");
    // Australia/Sydney is UTC+10 in June (no DST). At the `from` instant it is already 10:00 local on
    // the 17th, so the day's 09:00 has passed; the NEXT 09:00 Sydney is the 18th, which is 23:00Z on the
    // 17th. This both proves the zone shift (09:00 local != 09:00Z) and the strictly-after walk.
    const syd = nextFireAfter("0 9 * * *", from, "Australia/Sydney");
    ok("tz: next 09:00 Sydney (UTC+10) maps to 23:00Z (the 18th local)", syd === U("2026-06-17T23:00:00Z"));
    ok("tz: that instant reads as 09:00 local in Sydney", localTime(syd, "Australia/Sydney").includes("09:00:00"));
    ok("tz: same cron in UTC is DIFFERENT (09:00Z on the 17th)", nextFireAfter("0 9 * * *", from, "UTC") === U("2026-06-17T09:00:00Z"));

    // Asia/Kolkata is UTC+5:30 (half-hour offset); proves sub-hour zone math. 12:00 IST = 06:30 UTC.
    const kol = nextFireAfter("0 12 * * *", from, "Asia/Kolkata");
    ok("tz: 12:00 Kolkata (UTC+5:30) maps to 06:30 UTC", kol === U("2026-06-17T06:30:00Z"));
    ok("tz: that instant reads as 12:00 local in Kolkata", localTime(kol, "Asia/Kolkata").includes("12:00:00"));
  }
}

// ---- DST forward (spring-forward gap) ----------------------------------------------------
function testDstForward(): void {
  {
    // America/New_York springs forward at 02:00 -> 03:00 (02:00-02:59 do NOT exist).
    const before = U("2026-03-08T05:00:00Z"); // 00:00 EST local on 3/8
    // A cron at 02:30 cannot match the skipped local minute on 3/8; it must fire at the next valid
    // instant: the FOLLOWING day's 02:30 local (the rule: a non-existent local time fires at the next
    // valid matching instant; it never hangs and never double-fires).
    const skipped = nextFireAfter("30 2 * * *", before, "America/New_York");
    ok("DST-forward: 02:30 on the skipped day fires next valid day (3/9 02:30 local)", localTime(skipped, "America/New_York").includes("3/9/2026") && localTime(skipped, "America/New_York").includes("02:30:00"));
    ok("DST-forward: the fire is a finite future instant (no hang)", Number.isFinite(skipped) && skipped > before);
    // A local time that DOES exist that day (01:30) is unaffected.
    const exists = nextFireAfter("30 1 * * *", before, "America/New_York");
    ok("DST-forward: 01:30 (a real local time) fires on 3/8 01:30 local", localTime(exists, "America/New_York").includes("3/8/2026") && localTime(exists, "America/New_York").includes("01:30:00"));
    // A time AFTER the gap (03:30) fires normally on 3/8.
    const after = nextFireAfter("30 3 * * *", before, "America/New_York");
    ok("DST-forward: 03:30 (after the gap) fires 3/8 03:30 local", localTime(after, "America/New_York").includes("3/8/2026") && localTime(after, "America/New_York").includes("03:30:00"));
  }
}

// ---- DST back (fall-back overlap) --------------------------------------------------------
function testDstBack(): void {
  {
    // America/New_York falls back at 02:00 -> 01:00 (01:00-01:59 occur TWICE).
    const before = U("2026-11-01T04:00:00Z"); // 00:00 EDT local on 11/1
    // The rule: take the FIRST (earlier UTC) occurrence of an ambiguous local time. 01:30 EDT is
    // 05:30Z; 01:30 EST (the 2nd occurrence) is 06:30Z. We expect the earlier one.
    const first = nextFireAfter("30 1 * * *", before, "America/New_York");
    ok("DST-back: 01:30 takes the FIRST occurrence (05:30Z, the EDT one)", first === U("2026-11-01T05:30:00Z"));
    ok("DST-back: that instant reads as 01:30 local", localTime(first, "America/New_York").includes("11/1/2026") && localTime(first, "America/New_York").includes("01:30:00"));
    // The NEXT fire after that must be the FOLLOWING day, NOT the 2nd (06:30Z) occurrence of the same
    // wall-clock minute; this is the no-double-fire guarantee across fall-back.
    const next = nextFireAfter("30 1 * * *", first, "America/New_York");
    ok("DST-back: the NEXT fire is the following day, NOT a repeat of the doubled hour", localTime(next, "America/New_York").includes("11/2/2026") && localTime(next, "America/New_York").includes("01:30:00"));
    ok("DST-back: next is strictly later and skips the 06:30Z second occurrence", next > U("2026-11-01T06:30:00Z"));
  }
}

// ---- Impossible expression is rejected, not hung -----------------------------------------
function testImpossible(): void {
  {
    throws("impossible: Feb 30 never fires (rejected, not hung)", () => nextFireAfter("0 0 30 2 *", U("2026-01-01T00:00:00Z"), "UTC"));
    // A legitimately-rare but VALID date (Feb 29) DOES resolve within the search window.
    const leap = nextFireAfter("0 0 29 2 *", U("2026-06-01T00:00:00Z"), "UTC");
    ok("rare-but-valid: Feb 29 resolves (next leap day 2028-02-29)", leap === U("2028-02-29T00:00:00Z"));
  }
}

// ---- localMinuteOfDay (used by blackout windows) -----------------------------------------
function testLocalMinuteOfDay(): void {
  {
    const lm = localMinuteOfDay(U("2026-06-17T03:30:00Z"), "UTC");
    ok("localMinuteOfDay: 03:30Z UTC -> minute 210, Wednesday(3)", lm.minuteOfDay === 210 && lm.dow === 3);
    // In Sydney (UTC+10), 03:30Z is 13:30 local = minute 810, still Wednesday the 17th.
    const lmSyd = localMinuteOfDay(U("2026-06-17T03:30:00Z"), "Australia/Sydney");
    ok("localMinuteOfDay: 03:30Z in Sydney -> 13:30 local (minute 810)", lmSyd.minuteOfDay === 810 && lmSyd.dow === 3);
    ok("isValidTimeZone: known vs unknown", isValidTimeZone("Europe/Paris") === true && isValidTimeZone("Nowhere/Nope") === false && isValidTimeZone("") === false);
    ok("scheduleTimeZone: defaults to UTC, honours explicit", scheduleTimeZone(undefined) === "UTC" && scheduleTimeZone({ timeZone: "Asia/Tokyo" }) === "Asia/Tokyo" && scheduleTimeZone({ timeZone: "  " }) === "UTC");
  }
}

// ---- Blackout deferral -------------------------------------------------------------------
function testBlackout(): void {
  {
    const sched = { timeZone: "UTC", blackoutWindows: [{ startMinute: 120, endMinute: 240 }] }; // 02:00-04:00
    // a fire inside the window moves to just after it (the first instant >= endMinute)
    ok("blackout: 02:30 inside [02:00,04:00) defers to 04:00", deferPastBlackouts(U("2026-06-17T02:30:00Z"), sched) === U("2026-06-17T04:00:00Z"));
    // exactly at startMinute (inclusive) defers; exactly at endMinute (exclusive) does NOT
    ok("blackout: 02:00 (inclusive start) defers", deferPastBlackouts(U("2026-06-17T02:00:00Z"), sched) === U("2026-06-17T04:00:00Z"));
    ok("blackout: 04:00 (exclusive end) does NOT defer", deferPastBlackouts(U("2026-06-17T04:00:00Z"), sched) === U("2026-06-17T04:00:00Z"));
    // a fire outside the window is unchanged
    ok("blackout: 05:30 outside the window is unchanged", deferPastBlackouts(U("2026-06-17T05:30:00Z"), sched) === U("2026-06-17T05:30:00Z"));
    // no windows -> identity (the common case; cadence/cron path untouched)
    ok("blackout: no windows is identity", deferPastBlackouts(U("2026-06-17T02:30:00Z"), undefined) === U("2026-06-17T02:30:00Z") && deferPastBlackouts(U("2026-06-17T02:30:00Z"), { blackoutWindows: [] }) === U("2026-06-17T02:30:00Z"));

    // wrapping window 22:00-06:00 (start 1320 > end 360): a 23:30 fire defers to 06:00 the NEXT day
    const wrap = { timeZone: "UTC", blackoutWindows: [{ startMinute: 1320, endMinute: 360 }] };
    ok("blackout: wrapping 23:30 defers across midnight to next-day 06:00", deferPastBlackouts(U("2026-06-17T23:30:00Z"), wrap) === U("2026-06-18T06:00:00Z"));
    ok("blackout: wrapping 03:00 (early-morning side) defers to 06:00 same day", deferPastBlackouts(U("2026-06-17T03:00:00Z"), wrap) === U("2026-06-17T06:00:00Z"));
    ok("blackout: wrapping 12:00 (mid-day, outside) is unchanged", deferPastBlackouts(U("2026-06-17T12:00:00Z"), wrap) === U("2026-06-17T12:00:00Z"));

    // back-to-back windows: [02:00,03:00) and [03:00,04:00); a 02:30 fire hops both to 04:00
    const b2b = { timeZone: "UTC", blackoutWindows: [{ startMinute: 120, endMinute: 180 }, { startMinute: 180, endMinute: 240 }] };
    ok("blackout: back-to-back windows defer past BOTH to 04:00", deferPastBlackouts(U("2026-06-17T02:30:00Z"), b2b) === U("2026-06-17T04:00:00Z"));

    // weekday-filtered window: only Wednesday (dow 3). is Wed, is Thu.
    const wed = { timeZone: "UTC", blackoutWindows: [{ days: [3], startMinute: 120, endMinute: 240 }] };
    ok("blackout: day-filtered window defers ON the named weekday", deferPastBlackouts(U("2026-06-17T02:30:00Z"), wed) === U("2026-06-17T04:00:00Z"));
    ok("blackout: day-filtered window does NOT defer on another weekday", deferPastBlackouts(U("2026-06-18T02:30:00Z"), wed) === U("2026-06-18T02:30:00Z"));

    // timezone-aware window: 02:00-03:00 Australia/Sydney. A UTC instant that is 02:30 Sydney (UTC+10
    // in June = 16:30Z prior day) defers to 03:00 Sydney (17:00Z prior day).
    const syd = { timeZone: "Australia/Sydney", blackoutWindows: [{ startMinute: 120, endMinute: 180 }] };
    const sydDeferred = deferPastBlackouts(U("2026-06-16T16:30:00Z"), syd);
    ok("blackout: timezone-aware window defers in the schedule's zone (02:30->03:00 Sydney)", localTime(sydDeferred, "Australia/Sydney").includes("03:00:00"));
    ok("blackout: a Sydney-noon instant (outside the Sydney window) is unchanged", deferPastBlackouts(U("2026-06-17T02:00:00Z"), syd) === U("2026-06-17T02:00:00Z"));
  }
}

// ---- cron + blackout COMPOSED (the dispatch pipeline, deterministic) ---------------------
function testComposed(): void {
  {
    // The scheduler computes nextFireAfter then deferPastBlackouts. Prove the composition: a daily
    // 02:30 UTC cron whose fire lands in a 02:00-04:00 blackout ends up at 04:00.
    const sched = { timeZone: "UTC", blackoutWindows: [{ startMinute: 120, endMinute: 240 }] };
    const from = U("2026-06-17T10:00:00Z");
    const cronFire = nextFireAfter("30 2 * * *", from, scheduleTimeZone(sched));
    const deferred = deferPastBlackouts(cronFire, sched);
    ok("composed: cron 02:30 deferred out of [02:00,04:00) -> 04:00 next day", deferred === U("2026-06-18T04:00:00Z"));
  }
}

async function main(): Promise<void> {
  testFieldParsing();
  testRejection();
  testNextFireAfter();
  testUnion();
  testTimezone();
  testDstForward();
  testDstBack();
  testImpossible();
  testLocalMinuteOfDay();
  testBlackout();
  testComposed();

  console.log(failures === 0 ? "\nCRON VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
