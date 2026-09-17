// Every /admin/config/... path the console CALLS must be a route this engine SERVES.
//
// WHY THIS EXISTS. A route string is duplicated across two repos with nothing tying the copies together. The
// console builds `${t.base}/admin/config/...` in its client; the engine matches an exact `case "POST
// /config/..."` label. Rename either side and nothing fails to compile, nothing fails a test, and the break
// only appears as a 404 in a browser.
//
// This workstream added two such pairs (GET and POST /config/attended-cadence), which is what prompted it.
// The posture-ack statements have a cross-repo contract already (both repos pin the same SHA-384, so a
// one-sided edit fails a validator on both sides); the route strings had nothing.
//
// SCOPE, and it is narrow ON PURPOSE, because the wide version was measured and declined. Comparing EVERY
// console engine path against every engine route label reports 14 unmatched out of 124, and all 14 are false
// positives: the engine dispatches auth, reports, evidence packs and IdP providers by path SEGMENT
// (`sub === "providers"`, `kind === "evidence-pack"`) rather than by an exact case label, so a gate over the
// whole surface would be noise. The config routes ARE exact-match on both sides, so this compares just those:
// 10 console paths against 9 served labels, with one legitimate exception.
//
// THE ONE EXCEPTION is `/config/changes/`, which the console builds as a PREFIX with an id appended. It is
// named here rather than pattern-matched away, so a second prefix route has to be added deliberately rather
// than slipping in under a loosened rule.
//
// SIBLING POSTURE matches verify-doc-links and the posture-docs parity gate: absent console SKIPS by default
// so a single-repo checkout stays buildable, and FAILS under --require, which is what CI passes.
//
// DOWNPIPES_CONSOLE_ROOT is honoured as the override because that is the name the workspace already uses for
// "where the console is" when running the engine's validate. Until now nothing in this repo read it.
//
// Run with `node test/validate-console-route-parity.ts [--require]`.
//
// COMMENTS ARE NOT CODE, and this gate learned that the hard way rather than by argument. Both extractors
// below used to run over raw source. A router comment quoting a route label verbatim, which is ordinary in
// these files because they explain their own dispatch, put a phantom into `served`, and the gate then agreed
// that a route the router no longer dispatches was still being served. Proven, not supposed: renaming
// `case "POST /config/attended-cadence"` to `-set` while leaving a comment naming the old label passed every
// assertion here, including the two that pin that exact pair BY NAME, on a router guaranteed to 404 the
// console. That is the third scanner in this repo found reading comments as code.
//
// The fix is TOTALITY, not a wider pattern. blankComments is quote-aware and offset-preserving, so a label
// inside a comment cannot be seen at all, rather than being excluded by a rule that enumerates the comment
// spellings someone thought of. It is the same shared stripper the reachability and cross-repo gates use, so
// there is one place for this class to be got right. A self-test below drives a fixture containing exactly
// the defect through the real extractor, so a future edit that drops the blanking fails HERE, loudly, instead
// of quietly restoring the blindness.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments } from "../scripts/lib/blank-comments.mjs";
import { verdictReached, verdictSkipped } from "./lib/verdict-guard.ts";
import { requireFreshSiblings } from "../scripts/sibling-freshness.mjs";
import { reportSiblings } from "../scripts/lib/sibling-lag.mjs";

const HERE = fileURLToPath(new URL("..", import.meta.url));
const REQUIRE = process.argv.includes("--require");

const CLIENT = "src/lib/api/client-config-control.ts";

/** Where the console might be, best first. The extra levels are for the worktree layout, as in the docs gate. */
function consoleCandidates(): string[] {
  return [
    process.env.DOWNPIPES_CONSOLE_ROOT,
    resolve(HERE, "../console"),
    resolve(HERE, "../../console"),
    resolve(HERE, "../../../console"),
    resolve(HERE, "../../../../console"),
  ].filter((p): p is string => typeof p === "string" && p !== "");
}

const root = consoleCandidates().find((c) => existsSync(resolve(c, CLIENT)));
if (root === undefined) {
  if (REQUIRE) {
    console.error(`FAIL console-route-parity: --require was passed and ${CLIENT} was not found in any candidate console checkout.`);
    process.exit(1);
  }
  console.log("ok   console-route-parity: SKIPPED, no console checkout beside this engine (pass --require to fail instead)");
  // DECLARE the skip, for the reason given in validate-posture-and-docs-parity.ts: the coverage job runs a
  // plain `npm run validate` with no sibling repos, so this is the path CI takes, and a silent exit 0
  // having checked nothing is indistinguishable from a pass.
  verdictSkipped("no console checkout beside this engine (pass --require to fail instead)");
  process.exit(0);
}

// WHICH CONSOLE TREE, and REFUSE when it is not the sibling's main. Same posture as the posture-docs gate,
// for the same reason and with a sharper edge, because the console lands roughly 48 times a day.
//
// This gate compares EXACT route labels the console calls against the case labels this engine serves. Both
// errors are live against a stale console and neither is visible in the output:
//   a route the console has SINCE STARTED CALLING is absent from the old client, so the gate cannot demand
//   it and prints a clean pass over a call the engine does not serve;
//   a route the console has SINCE STOPPED CALLING is still in the old client, so the gate demands an engine
//   route that nothing calls any more.
// The first is a false green, and this workspace treats a false negative as costing what a false positive
// costs. Refusing produces no answer, which is worse than a right answer and better than a confident wrong
// one that names no tree.
reportSiblings([{ name: "console", path: root }], { gate: "console-route-parity" });
requireFreshSiblings([{ name: "console", path: root }], {
  gate: "console-route-parity",
  consequence: "it would compare this engine's routes against an older console client than the one that ships",
  exit: (code: number) => {
    verdictSkipped(`REFUSED, exit ${code}: the console checkout beside this engine is behind its own origin/main, so nothing was concluded`);
    process.exit(code);
  },
});

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

console.log("\n-- every config route the console calls is one this engine serves --\n");

// Both sides are read through blankComments: the router because a comment there quoting a case label is the
// proven defect, and the console client because the same trick works in reverse (a commented-out fetch would
// invent a call the console never makes, and the gate would then demand a route nobody needs, or mask the
// disappearance of one that is genuinely still called from live code).
const CLIENT_PATH = resolve(root, CLIENT);
const ROUTER_PATH = resolve(HERE, "src/admin/router-config-version.ts");
const clientRaw = readFileSync(CLIENT_PATH, "utf8");
const routerRaw = readFileSync(ROUTER_PATH, "utf8");
const client = blankComments(clientRaw);
const router = blankComments(routerRaw);

// METHOD AND PATH, not path alone. Path-level parity has a hole worth naming: a console POST to a path that
// only carries a GET label would pass, and the first version of this gate did exactly that. Renaming just the
// POST label left the GET label serving the same path, the set still contained it, and the mutation went
// undetected. The console's method sits in the same fetch call, so there is no reason to compare less.
//
// engineFetch defaults to GET when no method is given, mirroring fetch itself.
// calledFrom / servedFrom are the extractors, taken out of line so the self-test at the bottom can drive the
// SAME code the gate runs on. A self-test that reimplements the extraction proves only that the copy works.
function calledFrom(src: string): string[] {
  return [
  ...new Set(
    [...src.matchAll(/\$\{t\.base\}\/admin(\/config\/[A-Za-z0-9/_-]+)`,\s*\{([^}]*)/g)].map((m) => {
      const method = /method:\s*"(GET|POST|PUT|DELETE)"/.exec(m[2] as string)?.[1] ?? "GET";
      return `${method} ${m[1] as string}`;
    }),
  ),
  ].sort();
}
function servedFrom(src: string): Set<string> {
  return new Set([...src.matchAll(/case "((?:GET|POST) \/config\/[A-Za-z0-9\/_-]+)"/g)].map((m) => m[1] as string));
}

const called = calledFrom(client);
const served = servedFrom(router);

// WHAT THIS DOES NOT COVER, stated rather than left implicit. The extractor matches a path followed by the
// fetch options, so a path built with an interpolated id (`/config/changes/${id}/approve`) is not captured
// at all. That is correct rather than a hole to paper over: the engine serves those by path SEGMENT, not by
// an exact case label, so an exact-label comparison could never judge them. They are covered by the
// change-management journey, not here.

// A gate that compares nothing reads exactly like a passing gate.
ok(`the console client names config routes (${called.length} found)`, called.length >= 8);
ok(`this router serves config routes (${served.size} labels)`, served.size >= 5);

const unmatched = called.filter((p) => !served.has(p));
ok("every config path the console calls is served by an exact route label here", unmatched.length === 0);
if (unmatched.length > 0) {
  console.log(`       called but not served: ${unmatched.join(", ")}`);
  console.log("       Either the engine route was renamed and the console was not, or the reverse. Both are a 404 in a browser and nothing else.");
}

// Both methods must be represented, or an extractor that silently stopped matching POSTs would leave this
// comparing reads only and still reporting a pass.
ok("the extractor sees both GET and POST calls", called.some((p) => p.startsWith("GET ")) && called.some((p) => p.startsWith("POST ")));

// The two this workstream added, pinned by name. The general rule above would catch a rename, but naming
// them says WHICH pair the gate was written for, so a future reader can tell whether it still matters.
for (const p of ["GET /config/attended-cadence", "POST /config/attended-cadence"]) {
  ok(`the attended-cadence route is on both sides (${p})`, called.includes(p) && served.has(p));
}

// THE EXTRACTORS ARE DRIVEN AGAINST THE DEFECT THEY EXIST TO SURVIVE. Everything above is a comparison of
// two real files, and a comparison of two real files cannot tell you whether the blanking is still happening:
// remove it today and every assertion above still passes, because no comment in either file currently quotes
// a route label. That is precisely the state this gate was in when the rename was masked. So the fixtures
// below carry the defect explicitly and run through the SAME calledFrom / servedFrom the gate used.
{
  const routerFixture = [
    '// Renamed to attended-cadence-set; the old case "POST /config/attended-cadence" label is gone.',
    '/* case "GET /config/legacy-block": served until the block-comment era. */',
    '    case "POST /config/attended-cadence-set": {',
  ].join("\n");
  const servedFixture = servedFrom(blankComments(routerFixture));
  ok("self-test: a LINE comment quoting a case label does not enter the served set", !servedFixture.has("POST /config/attended-cadence"));
  ok("self-test: a BLOCK comment quoting a case label does not enter the served set", !servedFixture.has("GET /config/legacy-block"));
  ok("self-test: the real dispatched label IS still extracted (the blanking is not eating live code)", servedFixture.has("POST /config/attended-cadence-set"));

  const clientFixture = [
    '// await engineFetch(`${t.base}/admin/config/ghost-route`, { method: "POST" });',
    'await engineFetch(`${t.base}/admin/config/real-route`, { method: "POST" });',
  ].join("\n");
  const calledFixture = calledFrom(blankComments(clientFixture));
  ok("self-test: a commented-out console fetch does not enter the called set", !calledFixture.includes("POST /config/ghost-route"));
  ok("self-test: the live console fetch IS still extracted", calledFixture.includes("POST /config/real-route"));
}

console.log(`\n${failures === 0 ? "CONSOLE-ROUTE-PARITY PASS" : `CONSOLE-ROUTE-PARITY: ${failures} FAILED`}\n`);
verdictReached(failures);
process.exit(failures === 0 ? 0 : 1);
