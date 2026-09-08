// validate-gate-observed-as-refused: drive EVERY capability-gated admin route as the least-privileged
// principal this engine can produce, and assert what the gate actually does.
//
// WHY LEAST-PRIVILEGED MATTERS. An owner holds all twenty-one capabilities, so an assertion that drives a
// route as the owner cannot observe a gate that refuses anybody less privileged: a route with NO gate and
// a route gated at any level return the identical 200 to an owner. A suite that only ever asserts that a
// permitted caller succeeds cannot distinguish a gate from an open door, no matter which principal it runs
// as.
//
// WHY ONE PRINCIPAL COVERS THE WHOLE SURFACE, WHICH IS WHAT MAKES THIS TRACTABLE. The capability table
// (identity-rbac.ts ROLE_CAPABILITIES) splits exactly two ways against VIEWER:
//   - viewer's own seven capabilities (downpipe.read, audit.read, restore.dryrun, restore.verify,
//     reports.read, posture.read, roles.read) are held by ALL SIX built-in roles, so no reachable
//     principal is refused by a gate naming one. Call these the FLOOR capabilities.
//   - every other capability is lacked by viewer, and viewer is the resting role for any authenticated
//     caller with no grant, so viewer is the weakest principal a gate naming one can refuse.
// A custom role cannot subtract from the floor either: custom-role resolution seeds the set from
// ROLE_CAPABILITIES[builtin.role] and unions on top (scheduler-do-rbac.ts). So viewer is the correct
// least-privileged driver for EVERY gated route, and the assertion each route gets is decided by which
// side of that split its capability falls on:
//   - non-floor capability: a viewer MUST be refused 403 and the refusal MUST name that capability.
//   - floor capability:     a viewer MUST NOT be refused. That half is DECLARED (VIEWER_REACHABLE), not
//                           derived, because a derived expectation re-reads the very line a tightening
//                           changed and would stay green through the tightening instead of catching it.
//
// AND THE REFUSAL MUST BE THE ONE WE THINK IT IS. A 401, a 403, a 404 and a 429 are all refusals and
// only one of them is authorisation. So this validator does three things about it:
//   - it asserts the exact status 403, never "not 200";
//   - it asserts the 403 body carries required = the capability the SOURCE names, so a route refusing
//     for some other reason cannot be counted as its gate working;
//   - it asserts STATICALLY, per case, that gate() appears before rateLimited() in the case body, so a
//     429 can never stand in for the gate on any route here.
// Each route is driven by its OWN fresh viewer email, so every route has its own rate-limit bucket
// (rateLimitKey is sub:<subject>) and no route can be starved by the ones before it.
//
// THE ENUMERATION IS DERIVED, NOT KEPT BY HAND. The route list is read from the spoke sources at run
// time by matching `case "<METHOD> <path>":` inside a `switch (\`${req.method} ${sub}\`)` and taking the
// gate() calls in that case's brace-matched body. A route added with a gate is therefore covered the day
// it is added, and a route whose gate is REMOVED turns this red rather than quietly dropping out.
//
// Run: node test/validate-gate-observed-as-refused.ts

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Capability, ROLE_CAPABILITIES } from "../src/admin/identity.ts";
import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { AUD, makeScheduler, makeSigner, TEAM } from "./validate-rbac-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const HERE = dirname(fileURLToPath(import.meta.url));
const ADMIN_DIR = join(HERE, "..", "src", "admin");

// The floor is READ from the table rather than restated, so a capability moved into or out of viewer's
// set moves this validator's expectation with it instead of leaving a stale literal behind.
const FLOOR: ReadonlySet<Capability> = ROLE_CAPABILITIES.viewer;

interface GatedRoute {
  file: string;
  line: number;
  method: string;
  path: string;
  caps: Capability[];
  gateBeforeRateLimit: boolean;
}

// stripComments blanks every // and /* */ comment, preserving byte offsets and newlines so every line
// number and every brace position stays exactly where it was.
//
// THIS IS NOT TIDINESS, IT IS THE DIFFERENCE BETWEEN THIS FILE MEASURING THE ROUTER AND MEASURING
// NOTHING. A comment containing an apostrophe ("the customer's own data", "the caller's") can make a
// brace-matcher that treats ' as a string delimiter swallow the rest of the file from there, so the case
// body runs past its own closing brace into the NEXT case and picks up that case's gate. A scanner that
// reads the wrong case's gate does not merely miss a route: it asserts a refusal that should not happen,
// which is the false-negative direction.
function stripComments(src: string): string {
  const out = src.split("");
  let i = 0;
  let quote: string | null = null;
  let esc = false;
  while (i < src.length) {
    const c = src[i];
    if (quote !== null) {
      if (esc) esc = false;
      else if (c === "\\") esc = true;
      else if (c === quote) quote = null;
      i++;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") {
        out[i] = " ";
        i++;
      }
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? src.length : end + 2;
      for (; i < stop; i++) if (src[i] !== "\n") out[i] = " ";
      continue;
    }
    i++;
  }
  return out.join("");
}

// braceBody returns the source of the case body starting at the first "{" after `from`, brace-matched,
// skipping string and template contents so a brace inside a message cannot end the body early. A case
// with no braces (a bare `return` arm) has no gate to find, so those are simply not indexed.
function braceBody(src: string, from: number): { body: string; end: number } | null {
  const open = src.indexOf("{", from);
  if (open === -1) return null;
  // Only accept a brace that opens the case body: nothing but whitespace between the colon and it.
  if (/[^\s]/.test(src.slice(from, open))) return null;
  let depth = 0;
  let quote: string | null = null;
  let esc = false;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (quote !== null) {
      if (esc) {
        esc = false;
        continue;
      }
      if (c === "\\") {
        esc = true;
        continue;
      }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      quote = c;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return { body: src.slice(open, i + 1), end: i + 1 };
    }
  }
  return null;
}

function enumerateGatedRoutes(): GatedRoute[] {
  const out: GatedRoute[] = [];
  const files = readdirSync(ADMIN_DIR)
    .filter((f) => f.startsWith("router") && f.endsWith(".ts"))
    .sort();
  for (const f of files) {
    const src = stripComments(readFileSync(join(ADMIN_DIR, f), "utf8"));
    const caseRe = /case\s+"(GET|POST|PUT|PATCH|DELETE) (\/[^"]*)"\s*:/g;
    let m: RegExpExecArray | null = caseRe.exec(src);
    while (m !== null) {
      const after = m.index + m[0].length;
      const b = braceBody(src, after);
      if (b !== null) {
        const caps: Capability[] = [];
        const gateRe = /gate\(caller,\s*"([a-z.]+)"\)/g;
        let g: RegExpExecArray | null = gateRe.exec(b.body);
        let firstGateAt = -1;
        while (g !== null) {
          if (firstGateAt === -1) firstGateAt = g.index;
          if (!caps.includes(g[1] as Capability)) caps.push(g[1] as Capability);
          g = gateRe.exec(b.body);
        }
        if (caps.length > 0) {
          const rl = b.body.search(/rateLimited\(/);
          out.push({
            file: f,
            line: src.slice(0, m.index).split("\n").length,
            method: m[1] ?? "",
            path: m[2] ?? "",
            caps,
            gateBeforeRateLimit: rl === -1 || firstGateAt < rl,
          });
        }
      }
      caseRe.lastIndex = b === null ? after : b.end;
      m = caseRe.exec(src);
    }
  }
  return out;
}

// The floor is a claim about the whole table, not about viewer alone, so it is asserted rather than
// assumed: a capability in viewer's set that some OTHER built-in lacks would make "no reachable
// principal is refused" false, and the floor-side assertions below would then be wrong in the one
// direction that matters.
function assertFloorIsUniversal(): void {
  const roles = Object.keys(ROLE_CAPABILITIES) as Array<keyof typeof ROLE_CAPABILITIES>;
  let holes = 0;
  for (const cap of FLOOR) for (const r of roles) if (!ROLE_CAPABILITIES[r].has(cap)) holes++;
  ok(`every built-in role holds all ${FLOOR.size} of viewer's capabilities (the floor is universal)`, holes === 0);
  let belowViewer = 0;
  for (const r of roles) for (const cap of ROLE_CAPABILITIES[r]) if (!FLOOR.has(cap)) belowViewer += 0;
  ok("viewer is the least-privileged built-in (no role holds fewer capabilities)", roles.every((r) => ROLE_CAPABILITIES[r].size >= FLOOR.size) && belowViewer === 0);
}

interface Forbidden {
  error?: string;
  required?: string;
  have?: string;
}

// BODIES: the routes whose gate sits BEHIND a request-shape check, with the body that reaches the gate.
//
// This exists because the first run of this validator got a 400 from POST /restore and POST
// /restore/request and would have reported "the gate does not refuse a viewer". It does refuse a viewer;
// the request never reached it. Both routes reject a missing or non-ULID runId before any role is
// consulted, deliberately and in writing ("the runId check above stays first so a malformed/empty
// request is a plain 400, never a 403/429"), because the shape check discloses nothing about authority.
// A 400 and a 403 are both refusals and only one of them is authorisation: this table is how the
// distinction is kept rather than blurred.
//
// POST /restore additionally decides its capability FROM the body: confirm:true gates restore.apply (the
// F1 rule), and an omitted confirm gates restore.dryrun, which is at the floor. So the body carries
// confirm:true, which is the branch a viewer must be refused on.
//
// Every entry is checked for staleness below: an entry whose route answers 403 with the DEFAULT empty
// body no longer needs a body, and the validator says so rather than letting the table accumulate.
// VIEWER_REACHABLE: the routes a viewer MUST still reach, DECLARED rather than derived.
//
// Every one of these is gated at a capability in the viewer floor today, so refusing a viewer here is a
// regression that blanks a screen the console renders to viewers, restore-operators and access-admins.
// The list is written out because a derived one cannot do this job: see the comment at the loop below.
const VIEWER_REACHABLE: readonly string[] = [
  "GET /posture",
  "GET /coverage",
  "GET /config/history",
  "GET /config/version",
  "GET /config/diff",
  "GET /config/approval-policy",
  "GET /config/attended-cadence",
  "GET /config/changes",
  "GET /owner-actions",
  "GET /destinations",
  "GET /sources/discover",
  "GET /sources/discovery-status",
  "GET /roles",
  "GET /keys/vintages",
  "GET /notify/rules",
  "GET /notify/history",
  "GET /expiry",
  "GET /otlp-push",
  "GET /downpipes/roster-hygiene",
  "GET /push",
  "GET /group-roles",
  "GET /custom-roles",
  "GET /audit",
  "GET /audit/verify",
  "GET /audit/export",
  "POST /restore/capsule",
  "POST /restore/verify",
  "POST /restore/attest",
  "POST /retention-prune/candidate",
  "GET /support",
  "GET /support/bundle",
  "POST /support/bundle",
  "GET /downpipes",
  "GET /history",
  "GET /runs/at",
  "GET /rto",
  "GET /replication",
  "GET /update/status",
];

const VALID_RUN_ID = "01JZZZZZZZZZZZZZZZZZZZZZZZ";
const BODIES: Record<string, unknown> = {
  "POST /restore": { runId: VALID_RUN_ID, confirm: true },
  "POST /restore/request": { runId: VALID_RUN_ID, reason: "gate observation" },
};

async function main(): Promise<void> {
  const routes = enumerateGatedRoutes();

  // The guard below exists because an enumeration that reads NOTHING would turn every assertion
  // below green over an empty set, and would do it silently. A bare count floor is a weak guard (any
  // number satisfies it once someone picks it to fit), so the scan is asserted against NAMED routes on
  // the highest-consequence surfaces: if the scanner stops seeing these, it is broken whatever it counts.
  const seen = new Set(routes.map((r) => `${r.method} ${r.path}`));
  const MUST_FIND = [
    "POST /keys/install", // keys
    "POST /roles", // roles
    "POST /restore", // restore: the apply is this route with confirm:true, there is no /restore/apply
    "POST /retention-prune/apply", // retention prune
    "POST /custody/send-share", // custody
    "GET /audit/export", // audit egress
    "POST /policy/require-access", // owner posture
  ];
  const missing = MUST_FIND.filter((r) => !seen.has(r));
  ok(`the spoke scan found ${routes.length} capability-gated routes, including every named high-consequence one${missing.length > 0 ? ` (missing: ${missing.join(", ")})` : ""}`, routes.length > 0 && missing.length === 0);
  // A route that LOSES its gate leaves this enumeration silently, taking its assertion with it, so the
  // named list above is not enough on its own: it only covers seven routes. This floor is the arm for the
  // other 119. It may be raised when the surface genuinely grows and must never be lowered to fit a
  // removal; a removal is the finding.
  const GATED_ROUTE_FLOOR = 126;
  ok(`the gated surface has not shrunk below its recorded floor of ${GATED_ROUTE_FLOOR} routes (found ${routes.length})`, routes.length >= GATED_ROUTE_FLOOR);
  assertFloorIsUniversal();

  // A 429 is a refusal and it is not authorisation. Asserted from the SOURCE so it holds for every
  // route here whether or not this run happens to trip a limiter.
  const late = routes.filter((r) => !r.gateBeforeRateLimit);
  ok(
    `every gated route calls gate() before rateLimited(), so a 429 can never stand in for the gate${late.length > 0 ? ` (late: ${late.map((r) => `${r.method} ${r.path}`).join(", ")})` : ""}`,
    late.length === 0,
  );

  const signer = await makeSigner();
  const sched = makeScheduler();
  const accessEnv = (): Env =>
    ({
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      // Present so a route that needs them gets past its own configuration checks rather than
      // answering 400 before it reaches anything interesting. None of them confers authority.
      ADMIN_TOKEN: "gate-observed-bare-token",
      WORKER_NAME: "downpipe-engine",
    }) as unknown as Env;

  const call = async (email: string, method: string, path: string, body?: unknown): Promise<Response> => {
    const assertion = await signer.tokenFor(email);
    return handleAdmin(
      new Request(`https://engine.example${path}`, {
        method,
        headers: {
          "cf-access-jwt-assertion": assertion,
          "content-type": "application/json",
          origin: "https://engine.example",
        },
        ...(method === "GET" ? {} : { body: JSON.stringify(body ?? {}) }),
      }),
      accessEnv(),
    );
  };

  // Bootstrap a distinct owner FIRST. The role table makes the first authenticated Access caller the
  // Owner, so without this the first viewer email in the loop would silently become the owner and every
  // refusal assertion after it would be asserting the wrong thing about the wrong principal.
  const bootstrap = await call("gate-observed-owner@acme.example", "GET", "/admin/whoami");
  const who = (await bootstrap.json()) as { role?: string };
  ok("the bootstrap Access caller is the Owner, so every later email rests at viewer", bootstrap.status === 200 && who.role === "owner");
  const restingProbe = await call("gate-observed-resting@acme.example", "GET", "/admin/whoami");
  const resting = (await restingProbe.json()) as { role?: string };
  ok("an authenticated caller with no grant rests at viewer (the principal every assertion below drives)", restingProbe.status === 200 && resting.role === "viewer");

  let refusalAsserted = 0;
  let floorAsserted = 0;
  const wrongKind: string[] = [];
  const bodyNeeded = new Map<string, boolean>();

  console.log("\n-- a viewer is refused 403 on every route gated above the floor, and the refusal names the capability --");
  for (const r of routes) {
    const label = `${r.method} ${r.path}`;
    // A case may carry more than one gate (a branch that tightens). The refusal a viewer must see is the
    // first one it fails, and a viewer fails every non-floor capability, so the expected `required` is the
    // first non-floor capability in source order.
    const nonFloor = r.caps.filter((c) => !FLOOR.has(c));
    if (nonFloor.length === 0) continue;
    // A fresh email per route: its own subject, so its own rate-limit bucket, so no route can be
    // starved by the ones before it, and its resting role is viewer with no grant needed.
    const email = `gate-observed-${r.method}-${r.path.replace(/[^a-z0-9]/gi, "-")}@acme.example`.toLowerCase();
    const body = BODIES[label];
    if (body !== undefined) {
      // Staleness: if the empty body now reaches the gate, the entry is dead weight and must go, or the
      // table quietly starts hiding a route that no longer needs help.
      const bare = await call(`stale-${email}`, r.method, `/admin${r.path}`);
      bodyNeeded.set(label, bare.status !== 403);
      await bare.text();
    }
    const resp = await call(email, r.method, `/admin${r.path}`, body);
    if (resp.status !== 403) wrongKind.push(`${label} answered ${resp.status}`);
    const text = await resp.text();
    let forbidden: Forbidden = {};
    try {
      forbidden = JSON.parse(text) as Forbidden;
    } catch {
      forbidden = {};
    }
    ok(`${label}: a viewer is refused 403 (gate ${nonFloor[0]})`, resp.status === 403);
    ok(`${label}: the refusal names ${nonFloor[0]} and the role held, not some other refusal`, forbidden.error === "forbidden" && forbidden.required === nonFloor[0] && forbidden.have === "viewer");
    refusalAsserted++;
  }

  console.log("\n-- a viewer is NOT refused on any DECLARED viewer-reachable route, which is the tripwire for a tightening --");
  // The list this iterates is VIEWER_REACHABLE, not the derived floor set, and that is the whole point.
  // A derived expectation cannot catch a tightening: it re-reads the capability from the same line the
  // tightening changed, so it simply moves the route to the refusal side and stays green instead of
  // catching the change. So the reachable set is DECLARED and the derived scan is used only to prove the
  // declaration is complete.
  for (const label of VIEWER_REACHABLE) {
    const r = routes.find((x) => `${x.method} ${x.path}` === label);
    if (r === undefined) {
      ok(`${label}: is still a gated route in the router (declared viewer-reachable)`, false);
      continue;
    }
    const email = `gate-floor-${r.method}-${r.path.replace(/[^a-z0-9]/gi, "-")}@acme.example`.toLowerCase();
    const resp = await call(email, r.method, `/admin${r.path}`);
    await resp.text();
    // Deliberately NOT "=== 200". A reachable route may answer 400 for a body this validator does not
    // build or 404 for a resource it did not create, and neither is an authorisation outcome. 403 is the
    // only status that means the gate refused the least-privileged principal, and it is the only one this
    // asserts against, so the assertion stays honest about what it observed.
    ok(`${label}: a viewer is not refused (gate ${r.caps.join(", ")}); answered ${resp.status}`, resp.status !== 403);
    floorAsserted++;
  }
  // Completeness both ways, so the declared list cannot drift from the router in either direction: a new
  // floor-gated route must be declared (or it goes unasserted), and a declared route that is no longer
  // floor-gated must be removed (or the declaration is claiming something the source no longer says).
  const derivedFloor = routes.filter((r) => !r.caps.some((c) => !FLOOR.has(c))).map((r) => `${r.method} ${r.path}`);
  const undeclared = derivedFloor.filter((l) => !VIEWER_REACHABLE.includes(l));
  const overDeclared = VIEWER_REACHABLE.filter((l) => !derivedFloor.includes(l));
  ok(`every floor-gated route in the router is declared viewer-reachable${undeclared.length > 0 ? ` (undeclared: ${undeclared.join(", ")})` : ""}`, undeclared.length === 0);
  ok(`every declared viewer-reachable route is still gated at the floor in the router${overDeclared.length > 0 ? ` (tightened or gone: ${overDeclared.join(", ")})` : ""}`, overDeclared.length === 0);

  signer.restoreFetch();

  console.log(`\n-- surface: ${routes.length} gated routes, ${refusalAsserted} driven to a refusal as viewer, ${floorAsserted} driven to a floor pass as viewer --`);
  if (wrongKind.length > 0) console.log(`-- routes whose refusal was NOT a 403: ${wrongKind.join("; ")}`);
  ok("every gated route got an assertion driven as the least-privileged principal", refusalAsserted + floorAsserted === routes.length);

  const stale = [...bodyNeeded.entries()].filter(([, needed]) => !needed).map(([label]) => label);
  const unused = Object.keys(BODIES).filter((label) => !bodyNeeded.has(label));
  ok(
    `every BODIES entry is still load-bearing and still names a driven route${stale.length > 0 ? ` (stale: ${stale.join(", ")})` : ""}${unused.length > 0 ? ` (never driven: ${unused.join(", ")})` : ""}`,
    stale.length === 0 && unused.length === 0,
  );

  console.log(failures === 0 ? "\nGATE-OBSERVED-AS-REFUSED PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
