// The engine's cron tick interval, written down ONCE.
//
// WHY THIS FILE EXISTS. The interval lives in wrangler.toml as `crons = ["*/15 * * * *"]`, and six
// wrangler files carry it (production, dev, uat, internal, chaos, demo). Three places in src/ then
// RE-STATED it as a number: a CRON_CADENCE_MS in scheduler-do-limits.ts (from which the cron dead-man's
// stall threshold and sweep throttle are derived), a CRON_INTERVAL_MS in cron/drive.ts (passed to the DO so
// it can count MISSING ticks), and a bare 900_000 fallback in scheduler-do-support-diag.ts. Each was a
// hand-copy, and the comment above the first of them said an operator who retunes the cron "updates the
// cadence in one place" -- which was not true, and nothing checked it.
//
// WHAT THE DRIFT WOULD COST, which is why this is not tidiness. The retune the engine's own wrangler.toml
// invites (a tighter cron for a smaller RPO) would leave the dead-man thresholds calibrated for the OLD
// interval: CRON_DEADMAN_STALL_MS is three cadences, so at a five-minute cron the backstop would wait
// forty-five minutes to notice a dead driver instead of fifteen, and the tick-gap arithmetic in
// applyCronHealth would report two missing ticks for every one that was actually missed. Both are silent.
//
// test/validate-cron-cadence-pin.ts holds this constant to the cron literal in every wrangler file and
// refuses a re-stated literal in the three consumers, so the sentence above becomes true.
//
// THIS IS A FLOOR, NOT A CEILING, and the distinction belongs here rather than in a report. The cron is the
// dispatch driver for NEW runs, so a downpipe cadence shorter than this interval is not delivered: it
// dispatches at the next tick. Cloudflare cron triggers accept minute granularity, so the floor follows
// THIS number and not a platform limit. Narrowing it is one edit plus a cost decision (more invocations and
// DO reads per account, mostly no-ops); removing it is the deferred refinement wrangler.toml names, where
// the SchedulerDO alarm dispatches rather than only re-arming.
export const CRON_CADENCE_MS = 15 * 60 * 1000;
