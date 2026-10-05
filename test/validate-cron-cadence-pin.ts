// The engine's cron tick interval is ONE number, and this holds every copy of it to that one.
//
// WHAT WENT WRONG BEFORE THIS. `crons = ["*/15 * * * *"]` appears in six wrangler files, and src/ re-stated
// the same interval as a number in three separate places: CRON_CADENCE_MS in sched/scheduler-do-limits.ts
// (the cron dead-man's stall threshold and sweep throttle derive from it), CRON_INTERVAL_MS in
// cron/drive.ts (passed to the DO so it can count MISSING ticks), and a bare 900_000 fallback in
// sched/scheduler-do-support-diag.ts. The comment above the first said an operator who retunes the cron
// "updates the cadence in one place". Three hand-copies say otherwise, and nothing compared them.
//
// WHY IT MATTERS RATHER THAN BEING TIDINESS. The engine's own wrangler.toml invites the retune: the
// 15-minute tick is the EFFECTIVE FLOOR on a downpipe's cadence (the cron is the dispatch driver for new
// runs), so a customer wanting a tighter RPO is answered by narrowing this literal. Narrow it and leave the
// three copies behind, and the dead-man backstop waits three OLD cadences before deciding the driver is
// dead, while applyCronHealth's tick-gap arithmetic reports missing ticks that never existed. Both are
// silent, and both are in the code that is supposed to notice when backups stop.
//
// WHAT IS ASSERTED:
//   1. every wrangler file's cron is the same single "*/N * * * *" entry;
//   2. CRON_CADENCE_MS equals that N in milliseconds;
//   3. the two exported dead-man thresholds are still the documented multiples of it;
//   4. no consumer re-states the interval as a literal (the drift itself, read from the source).
//
// Run: node test/validate-cron-cadence-pin.ts

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CRON_CADENCE_MS } from "../src/cron/cron-cadence.ts";
import { CRON_DEADMAN_STALL_MS, CRON_DEADMAN_SWEEP_INTERVAL_MS } from "../src/sched/scheduler-do-limits.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENGINE_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");

// The three files that consume the interval. Each is named with what it does with it, so a failure below
// says which behaviour has drifted rather than only which line matched.
const CONSUMERS: Array<{ path: string; what: string }> = [
  { path: "src/cron/drive.ts", what: "passes the interval to the DO so it can count missing ticks" },
  { path: "src/sched/scheduler-do-limits.ts", what: "derives the cron dead-man stall threshold and sweep throttle" },
  { path: "src/sched/scheduler-do-support-diag.ts", what: "defaults the tick-gap interval when a caller omits it" },
];

// A duration literal, in the two forms this repo actually wrote the cadence in: the arithmetic form
// (15 * 60 * 1000, any spacing) and the millisecond literal (900_000 or 900000). The arithmetic form is
// matched for ANY minute count rather than only the current 15, deliberately: a maintainer who narrows the
// cron and updates one copy by hand would otherwise leave a matching-but-wrong literal that a 15-specific
// pattern misses, which is the exact drift this gate exists for.
const DURATION_LITERAL = /\b\d+\s*\*\s*60\s*\*\s*1000\b|\b900_?000\b/;

// restatesTheCadence reads a file's CODE (comments stripped) and returns the lines that write a duration
// literal in a CRON context. The "cron" qualifier is load-bearing in both directions. Without it the gate
// is red on FLEET_DRILL_INFLIGHT_TIMEOUT_MS = 30 * 60 * 1000, a different duration that happens to share
// the arithmetic shape, and narrowing the rule to silence that would be the classic move that builds the
// blind spot: it would have to exclude the shape the drift is written in. Requiring "cron" on the line
// instead keeps every shape in scope and excludes only the unrelated durations, and it still catches an
// inline `recordCronHealth(scheduler, 15 * 60 * 1000)` as well as a re-declared local constant.
function restatesTheCadence(text: string): string[] {
  const code = text.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
  return code.split("\n").filter((l) => /cron/i.test(l) && DURATION_LITERAL.test(l)).map((l) => l.trim());
}

function cronsIn(toml: string): string[] | null {
  const m = toml.match(/^crons\s*=\s*\[(.*)\]\s*$/m);
  if (m === null) return null;
  return [...(m[1] ?? "").matchAll(/"([^"]*)"/g)].map((x) => x[1] ?? "");
}

async function main(): Promise<void> {
  console.log("-- the cron literal, across every wrangler file --");
  const tomls = readdirSync(ENGINE_DIR).filter((f) => f.startsWith("wrangler") && f.endsWith(".toml"));
  ok(`there are wrangler files to read (${tomls.length} found)`, tomls.length > 0);

  const minutes = new Map<string, number>();
  for (const file of tomls.sort()) {
    const entries = cronsIn(readFileSync(join(ENGINE_DIR, file), "utf8"));
    if (entries === null) {
      // wrangler.deploy.toml and any generated sibling may carry no [triggers] at all. A file with no cron
      // is not a drift; it is simply not a scheduled deployment, so it is reported and skipped.
      console.log(`  note ${file} declares no crons`);
      continue;
    }
    ok(`${file}: exactly one cron entry (a second would make "the" interval ambiguous)`, entries.length === 1);
    const entry = entries[0] ?? "";
    const m = entry.match(/^\*\/(\d+) \* \* \* \*$/);
    ok(`${file}: the cron is an every-N-minutes trigger ("${entry}")`, m !== null);
    if (m !== null) minutes.set(file, Number(m[1]));
  }

  const distinct = new Set(minutes.values());
  ok(`every wrangler file declares the SAME interval (${[...distinct].join(", ")} minute(s))`, distinct.size === 1);

  console.log("\n-- the one constant, and what derives from it --");
  const declared = [...distinct][0];
  ok(
    `CRON_CADENCE_MS matches the cron literal (constant ${CRON_CADENCE_MS} ms, wrangler */${declared ?? "?"})`,
    declared !== undefined && CRON_CADENCE_MS === declared * 60_000,
  );
  // The two multiples are documented at their declarations: the backstop presumes the driver dead after
  // three missed cadences, and throttles itself to one sweep per cadence so it stands in for the missing
  // tick rather than hammering the fleet.
  ok("CRON_DEADMAN_STALL_MS is still three cadences", CRON_DEADMAN_STALL_MS === 3 * CRON_CADENCE_MS);
  ok("CRON_DEADMAN_SWEEP_INTERVAL_MS is still one cadence", CRON_DEADMAN_SWEEP_INTERVAL_MS === CRON_CADENCE_MS);

  console.log("\n-- no consumer re-states the interval --");
  for (const c of CONSUMERS) {
    const text = readFileSync(join(ENGINE_DIR, c.path), "utf8");
    ok(`${c.path} imports the constant (it ${c.what})`, /from "[^"]*cron-cadence\.ts"/.test(text));
    const restated = restatesTheCadence(text);
    ok(`${c.path} states no cadence literal of its own${restated.length > 0 ? ` (found: ${restated[0]})` : ""}`, restated.length === 0);
  }
  // The source file itself is the ONE place the literal is allowed, and it must actually hold one: a
  // constant that had become a re-export or a computed value would make the assertions above vacuous.
  ok(
    "src/cron/cron-cadence.ts is where the literal lives",
    DURATION_LITERAL.test(readFileSync(join(ENGINE_DIR, "src/cron/cron-cadence.ts"), "utf8").replace(/^\s*\/\/.*$/gm, "")),
  );

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nCRON-CADENCE-PIN VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
