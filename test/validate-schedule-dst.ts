// Prove the blackout / change-freeze window logic in schedule-window.ts stays
// correct across daylight-saving transitions and the UTC-vs-local day boundary, with a DETERMINISTIC
// clock and in-memory values only. No network, no deploy, no Date.now() in the assertions (every time
// is a fixed epoch passed explicitly). Run:
//   node test/validate-schedule-dst.ts
//
// Why this exists: validate-cron.ts already covers the DST spring-forward and fall-back edges of
// nextFireAfter (the CRON firing). It does NOT cover those edges for the blackout deferral: its
// testBlackout / testComposed cells all sit, a plain non-DST day. The window minutes are
// interpreted as minutes-since-local-midnight in the schedule's IANA zone, and the deferral walks the
// wall clock, so a DST transition is precisely where the window can silently go inert (a backup runs
// inside a declared freeze) or over-run. This file fills that gap against schedule-window.ts directly.
//
// What this covers, table-driven over deferPastBlackouts / deferPastBlackoutsResolved:
// - SPRING-FORWARD (America/New_York, ->03:00, 02:00-02:59 do NOT exist): a freeze
//    01:30-03:30 that spans the missing hour must still cover the POST-gap side (03:15 local). The
//    window must not go inert; a fire on either side of the gap defers to the window end, never fires
//    inside the freeze;
// - FALL-BACK (America/New_York, ->01:00, 01:00-01:59 occur TWICE): a freeze
//    01:00-02:00 must cover BOTH passes of the doubled hour and defer past both to 02:00 EST, so no
//    fire in either occurrence is let through mid-freeze;
//  - DAY-BOUNDARY (Australia/Sydney, UTC+11): a window evaluated in the schedule's zone whose local
//    day differs from the UTC day, including a wrapping overnight freeze that crosses local midnight;
//  - a degenerate (start === end) freeze covers nothing and is flagged inert (a change freeze that
//    silently does nothing);
//  - REFUTERS: a zone-blind (UTC-clock) impl leaves the post-gap spring-forward fire inert, and a
//    wall-arithmetic (non-walking) end lands the fall-back fire back inside the freeze. Each refuter
//    proves the matching graded cell would FAIL a broken implementation.

import {
  deferPastBlackouts,
  deferPastBlackoutsResolved,
  scheduleTimeZone,
} from "../src/sched/schedule-window.ts";
import { localMinuteOfDay } from "../src/sched/cron.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const U = (s: string): number => Date.parse(s); // UTC ISO -> epoch ms
// localTime renders an epoch in a zone as "M/D/YYYY, HH:MM:SS" so a DST assertion checks the local
// wall-clock the fire lands on, independent of the host's own zone (compared by substring).
function localTime(ms: number, tz: string): string {
  return new Date(ms).toLocaleString("en-US", { timeZone: tz, hour12: false });
}

type Cell = {
  name: string;
  tz: string;
  windows: Array<{ startMinute: number; endMinute: number; days?: number[] }>;
  from: string; // UTC ISO of the computed fire time entering the deferral
  expect: string; // UTC ISO of the expected deferred instant ("unchanged" cells repeat `from`)
  expectLocal?: string[]; // substrings the deferred instant must read as in `tz`
  expectClass: string; // the deferPastBlackoutsResolved class the fire must carry
};

// ---- Deferral across DST + the day boundary (table-driven) --------------------------------------
function testDeferralTable(): void {
  const cells: Cell[] = [
    // SPRING-FORWARD (EST UTC-5 -> EDT UTC-4). Freeze 01:30-03:30 local = minutes 90..210.
    {
      name: "spring: 01:45 (PRE-gap) inside freeze defers to 03:30 local",
      tz: "America/New_York",
      windows: [{ startMinute: 90, endMinute: 210 }],
      from: "2026-03-08T06:45:00Z", // 01:45 EST
      expect: "2026-03-08T07:30:00Z", // 03:30 EDT
      expectLocal: ["3/8/2026", "03:30:00"],
      expectClass: "ok",
    },
    {
      name: "spring: 03:15 (POST-gap) STILL inside freeze, window not inert, defers to 03:30",
      tz: "America/New_York",
      windows: [{ startMinute: 90, endMinute: 210 }],
      from: "2026-03-08T07:15:00Z", // 03:15 EDT, right after the missing hour
      expect: "2026-03-08T07:30:00Z", // 03:30 EDT
      expectLocal: ["3/8/2026", "03:30:00"],
      expectClass: "ok",
    },
    {
      name: "spring: 04:00 (after freeze) is unchanged",
      tz: "America/New_York",
      windows: [{ startMinute: 90, endMinute: 210 }],
      from: "2026-03-08T08:00:00Z", // 04:00 EDT
      expect: "2026-03-08T08:00:00Z",
      expectLocal: ["3/8/2026", "04:00:00"],
      expectClass: "ok",
    },
    // FALL-BACK (EDT UTC-4 -> EST UTC-5). Freeze 01:00-02:00 local = minutes 60..120.
    {
      name: "fall-back: 01:30 FIRST occurrence (EDT) inside freeze, walks BOTH passes to 02:00 EST",
      tz: "America/New_York",
      windows: [{ startMinute: 60, endMinute: 120 }],
      from: "2026-11-01T05:30:00Z", // 01:30 EDT (first pass)
      expect: "2026-11-01T07:00:00Z", // 02:00 EST (true end, past both passes)
      expectLocal: ["11/1/2026", "02:00:00"],
      expectClass: "ok",
    },
    {
      name: "fall-back: 01:30 SECOND occurrence (EST) inside freeze defers to 02:00 EST",
      tz: "America/New_York",
      windows: [{ startMinute: 60, endMinute: 120 }],
      from: "2026-11-01T06:30:00Z", // 01:30 EST (second pass)
      expect: "2026-11-01T07:00:00Z", // 02:00 EST
      expectLocal: ["11/1/2026", "02:00:00"],
      expectClass: "ok",
    },
    {
      name: "fall-back: 00:30 (before freeze) is unchanged",
      tz: "America/New_York",
      windows: [{ startMinute: 60, endMinute: 120 }],
      from: "2026-11-01T04:30:00Z", // 00:30 EDT
      expect: "2026-11-01T04:30:00Z",
      expectLocal: ["11/1/2026", "00:30:00"],
      expectClass: "ok",
    },
    {
      name: "fall-back: 02:00 EST (exclusive end) is unchanged",
      tz: "America/New_York",
      windows: [{ startMinute: 60, endMinute: 120 }],
      from: "2026-11-01T07:00:00Z", // 02:00 EST
      expect: "2026-11-01T07:00:00Z",
      expectLocal: ["11/1/2026", "02:00:00"],
      expectClass: "ok",
    },
    // DAY-BOUNDARY Australia/Sydney (UTC+11 in January): local day differs from the UTC day.
    {
      name: "day-boundary: 00:30 local (the 15th) is 13:30Z the 14th; defers to 02:00 local",
      tz: "Australia/Sydney",
      windows: [{ startMinute: 0, endMinute: 120 }], // 00:00-02:00 local
      from: "2026-01-14T13:30:00Z", // 00:30 on the 15th, Sydney
      expect: "2026-01-14T15:00:00Z", // 02:00 on the 15th, Sydney (still the 14th in UTC)
      expectLocal: ["1/15/2026", "02:00:00"],
      expectClass: "ok",
    },
    {
      name: "day-boundary: 14:00 local (the 15th) outside the freeze is unchanged",
      tz: "Australia/Sydney",
      windows: [{ startMinute: 0, endMinute: 120 }],
      from: "2026-01-15T03:00:00Z", // 14:00 on the 15th, Sydney
      expect: "2026-01-15T03:00:00Z",
      expectLocal: ["1/15/2026", "14:00:00"],
      expectClass: "ok",
    },
    {
      name: "day-boundary: WRAPPING overnight freeze 22:00-02:00, 23:30 local defers across midnight",
      tz: "Australia/Sydney",
      windows: [{ startMinute: 1320, endMinute: 120 }], // 22:00 -> 02:00 local, wraps midnight
      from: "2026-01-15T12:30:00Z", // 23:30 on the 15th, Sydney
      expect: "2026-01-15T15:00:00Z", // 02:00 on the 16th, Sydney
      expectLocal: ["1/16/2026", "02:00:00"],
      expectClass: "ok",
    },
    // DEGENERATE freeze on the spring day: start === end covers nothing and is flagged inert.
    {
      name: "degenerate: a start===end freeze covers NOTHING and is flagged inert",
      tz: "America/New_York",
      windows: [{ startMinute: 120, endMinute: 120 }],
      from: "2026-03-08T07:15:00Z", // 03:15 EDT
      expect: "2026-03-08T07:15:00Z", // unchanged: the window never applied
      expectLocal: ["3/8/2026", "03:15:00"],
      expectClass: "degenerate-window-inert",
    },
  ];

  for (const c of cells) {
    const sched = { timeZone: c.tz, blackoutWindows: c.windows };
    // scheduleTimeZone is the resolution the deferral uses; assert the cell's zone is what governs.
    ok(`${c.name} [zone ${c.tz}]`, scheduleTimeZone(sched) === c.tz);
    const got = deferPastBlackouts(U(c.from), sched);
    ok(`${c.name} [defer -> ${c.expect}]`, got === U(c.expect));
    for (const sub of c.expectLocal ?? []) {
      ok(`${c.name} [local includes ${sub}]`, localTime(got, c.tz).includes(sub));
    }
    ok(`${c.name} [class ${c.expectClass}]`, deferPastBlackoutsResolved(U(c.from), sched).class === c.expectClass);
  }
}

// ---- REFUTERS: prove the graded cells above catch a broken implementation -----------------------

// brokenDeferZoneBlind reads the wall-clock minute-of-day from the UTC clock instead of the schedule's
// zone. This is the classic bug that passes on a UTC host and fails silently under a real zone: on the
// spring-forward POST-gap fire it computes the wrong minute, decides the freeze does not cover the
// instant, and returns it UNCHANGED, so a backup runs inside the declared change freeze.
function brokenDeferZoneBlind(
  epochMs: number,
  windows: Array<{ startMinute: number; endMinute: number }>,
): number {
  const d = new Date(epochMs);
  const m = d.getUTCHours() * 60 + d.getUTCMinutes();
  for (const w of windows) {
    const covers =
      w.startMinute < w.endMinute
        ? m >= w.startMinute && m < w.endMinute
        : m >= w.startMinute || m < w.endMinute;
    if (covers) return epochMs + 60_000; // its own defer path (never reached on the refuted cell)
  }
  return epochMs; // inert
}

// brokenDeferArithmetic computes the window end by ADDING (endMinute - localStart) minutes instead of
// walking the wall clock. It uses the zone-correct start minute, so the fault is walk-vs-arithmetic,
// not a zone error. Across fall-back the wall clock gains an hour, so the arithmetic under-shoots and
// lands the fire back INSIDE the second pass of the doubled hour: still mid-freeze.
function brokenDeferArithmetic(
  epochMs: number,
  tz: string,
  w: { startMinute: number; endMinute: number },
): number {
  const start = localMinuteOfDay(epochMs, tz).minuteOfDay;
  const delta = ((w.endMinute - start) % 1440 + 1440) % 1440;
  return epochMs + delta * 60_000;
}

function testRefuters(): void {
  // Spring-forward inertness. Post-gap fire 03:15 EDT inside freeze 01:30-03:30.
  const sSched = { timeZone: "America/New_York", blackoutWindows: [{ startMinute: 90, endMinute: 210 }] };
  const springPost = U("2026-03-08T07:15:00Z");
  const realSpring = deferPastBlackouts(springPost, sSched);
  const brokenSpring = brokenDeferZoneBlind(springPost, sSched.blackoutWindows);
  ok("REFUTER[spring inert]: the real defer MOVES the post-gap fire out of the freeze to 03:30 (07:30Z)", realSpring === U("2026-03-08T07:30:00Z"));
  ok(
    "REFUTER[spring inert]: a zone-blind impl leaves it INERT (fires 07:15Z inside the freeze) -> the graded post-gap cell would FAIL it",
    brokenSpring === springPost && brokenSpring !== realSpring,
  );

  // Fall-back fires-inside. First-pass fire 01:30 EDT inside freeze 01:00-02:00.
  const fSched = { timeZone: "America/New_York", blackoutWindows: [{ startMinute: 60, endMinute: 120 }] };
  const fallFire = U("2026-11-01T05:30:00Z");
  const realFall = deferPastBlackouts(fallFire, fSched);
  // The one window declared on fSched two lines above; only the checker's indexed-access rule calls it optional.
  const fWindow = fSched.blackoutWindows[0]!;
  const brokenFall = brokenDeferArithmetic(fallFire, "America/New_York", fWindow);
  const brokenFallLm = localMinuteOfDay(brokenFall, "America/New_York");
  ok("REFUTER[fall-back inside]: the real defer WALKS past both passes to 02:00 EST (07:00Z)", realFall === U("2026-11-01T07:00:00Z"));
  ok(
    "REFUTER[fall-back inside]: a wall-arithmetic impl lands 06:00Z, local-minute 60 STILL inside the doubled-hour freeze -> the graded first-pass cell would FAIL it",
    brokenFall === U("2026-11-01T06:00:00Z") && brokenFallLm.minuteOfDay === 60 && brokenFall !== realFall,
  );
}

async function main(): Promise<void> {
  testDeferralTable();
  testRefuters();

  console.log(failures === 0 ? "\nSCHEDULE DST VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
