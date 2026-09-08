// validate-admin-route-manifest: the admin surface's two hand-kept enumerations, checked against a SCAN OF
// THE SPOKE SOURCE rather than against anything exported. Run: node test/validate-admin-route-manifest.ts
//
// WHY A SOURCE SCAN AND NOT A LIST. The failure this file exists to catch is ENUMERATION DRIFT: a statement
// that was correct when it was written and was not updated when a member was added. An exported list cannot
// see a member that never joined it, so a check built on one is blind to exactly the case it is for. The same
// pattern (deriving the change-controlled kinds from enforceChangeControl's call sites) is applied here to the
// admin router: an absence -- a route dispatched with no capability gate, a hand-kept field list missing an
// entry, a catalogue missing an endpoint -- is the thing prose cannot show and a scan can.
//
// ---- WHAT THIS FILE GUARANTEES, AND WHAT IT DOES NOT ------------------------------------------------
// It guarantees that the set of dispatched admin routes calling NO router-side capability gate cannot change
// without this file going red -- in BOTH directions. A new ungated route is red. A route that loses its gate
// is red. A route that GAINS a gate is red until it is removed from the declaration below, so the record
// cannot silently overstate the surface either.
//
// It does NOT certify that any member of that set is CORRECTLY ungated. Most carry a `class` string; four of
// the five classes are re-derived from source here and are therefore checked facts, and the fifth,
// "none-established", carries no claim at all and means what it says: this pass did not establish a
// mechanism for that route. Saying "reviewed" over 35 routes read once would be the rubber stamp this
// whole exercise is against, and a false negative about a capability gate is the expensive direction.
//
// TWO THINGS ARE OUT OF SCOPE AND ARE NAMED RATHER THAN LEFT TO BE DISCOVERED. (1) The pre-switch matchers in
// router.ts (reports, cost/estate-size, and the two dynamic-id approve/reject matchers) are not `case`
// labels, so the dispatch scan does not see them; each gates inline at its own matcher and validate-session
// .ts's HI-04 structural check already reads that source directly for the approve legs. (2) The scan asks
// only whether a route calls gate(caller, ...) at the ROUTER. A route may be authorised somewhere else
// entirely -- in the Durable Object, at the spoke's entry, or by a break-glass bearer -- and three of the
// four checked classes below are exactly that. "No router gate" is a precise statement about one place.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { blankComments } from "./lib/blank-comments.mjs";

let failures = 0;
// checks counts every assertion actually run, and it is handed to verdictReached as its `checks` argument
// (a COUNT, not a name). That arm is the guard against this file's own worst failure mode: a scan that reads
// nothing would otherwise assert nothing and exit 0, which is the vacuous pass every check here exists to
// stop being possible elsewhere.
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ADMIN_DIR = fileURLToPath(new URL("../src/admin/", import.meta.url));

// ---- The scan ---------------------------------------------------------------------------------------
// Comments are blanked first (scripts/lib/blank-comments.mjs) because this repo has already shipped a
// scanner that read a commented-out line as live code. String CONTENT is left intact, which is what lets the
// `case "<METHOD> <sub>"` labels and the gate(caller, "<cap>") calls be read at all.
interface DispatchedCase {
  key: string; // `${METHOD} ${sub}`, the exact string the router's switch is keyed on
  file: string;
  line: number;
  gates: string[];
  body: string;
}

function spokeFiles(): string[] {
  return readdirSync(ADMIN_DIR)
    .filter((f) => /^router.*\.ts$/.test(f))
    .sort();
}

// scanDispatch derives every dispatched admin route case from source. A case body runs from its own label to
// the next label in the same file (or end of file), which is how these spokes are written: one flat switch
// per handler, no nested switch on the same key. The body is what the gate scan reads.
function scanDispatch(): DispatchedCase[] {
  const out: DispatchedCase[] = [];
  for (const file of spokeFiles()) {
    const lines = blankComments(readFileSync(join(ADMIN_DIR, file), "utf8")).split("\n");
    const labels: Array<{ i: number; key: string }> = [];
    for (let i = 0; i < lines.length; i++) {
      const m = /^\s*case "((?:GET|POST|PUT|DELETE|OPTIONS) \/[^"]*)":/.exec(lines[i] ?? "");
      if (m?.[1] !== undefined) labels.push({ i, key: m[1] });
    }
    for (let k = 0; k < labels.length; k++) {
      const start = labels[k]?.i ?? 0;
      const end = k + 1 < labels.length ? (labels[k + 1]?.i ?? lines.length) : lines.length;
      const body = lines.slice(start, end).join("\n");
      out.push({
        key: labels[k]?.key ?? "",
        file,
        line: start + 1,
        gates: [...body.matchAll(/\bgate\(caller,\s*"([^"]+)"\)/g)].map((m) => m[1] ?? ""),
        body,
      });
    }
  }
  return out;
}

// ---- The SECOND scan: the Durable Object side ---------------------------------------------------------
// The first scan can only ever say what the ROUTER does. Four of the classes below are claims about what
// happens on the OTHER side of scheduler.fetch, and a claim about the other side that is checked on this
// side is not checked at all -- which is exactly how "the DO enforces it" survived as a reason for five
// reads whose DO arms took no caller. So the arms are scanned too, and the handlers they name after that.

const SCHED_DIR = fileURLToPath(new URL("../src/sched/", import.meta.url));

// scanDoArms derives every Durable Object route arm from the DO's own routing spokes, keyed the same way the
// admin scan is (`${METHOD} ${path}`). `conveys` is the load-bearing field: whether the arm decodes the
// forwarded caller at all. An arm that never calls decodeCaller CANNOT enforce anything about the caller,
// whatever the router sent it.
function scanDoArms(): Map<string, { file: string; conveys: boolean; body: string }> {
  const out = new Map<string, { file: string; conveys: boolean; body: string }>();
  for (const file of readdirSync(SCHED_DIR).filter((f) => /^scheduler-do-routing.*\.ts$/.test(f)).sort()) {
    const lines = blankComments(readFileSync(join(SCHED_DIR, file), "utf8")).split("\n");
    const labels: Array<{ i: number; key: string }> = [];
    for (let i = 0; i < lines.length; i++) {
      const m = /^\s*case "((?:GET|POST|PUT|DELETE) \/[^"]*)":/.exec(lines[i] ?? "");
      if (m?.[1] !== undefined) labels.push({ i, key: m[1] });
    }
    for (let k = 0; k < labels.length; k++) {
      const start = labels[k]?.i ?? 0;
      const end = k + 1 < labels.length ? (labels[k + 1]?.i ?? lines.length) : lines.length;
      const body = lines.slice(start, end).join("\n");
      if (!out.has(labels[k]?.key ?? "")) out.set(labels[k]?.key ?? "", { file, conveys: /decodeCaller\(/.test(body), body });
    }
  }
  return out;
}

// indexSchedHandlers maps every async method in src/sched to its BODY, so a claim about a named handler
// ("it re-resolves the caller's capability") can be checked against that handler rather than against the one
// line that calls it. The body is found by matching the parameter list's parens, then skipping the return
// type (tracking <> depth, because `Promise<{ ok: true }>` contains a brace that is not the body), then
// brace-matching. Only `async` members are indexed, which keeps the abstract declarations in
// scheduler-do-base.ts out: those have a signature and no body, and indexing one would let a check pass
// against an empty string. Where two files define the same name the LONGER body wins.
function indexSchedHandlers(): Map<string, string> {
  const out = new Map<string, string>();
  for (const file of readdirSync(SCHED_DIR).filter((f) => f.endsWith(".ts"))) {
    const src = blankComments(readFileSync(join(SCHED_DIR, file), "utf8"));
    const re = /^\s{2,6}async\s+([A-Za-z][A-Za-z0-9_]*)\s*\(/gm;
    let m: RegExpExecArray | null = re.exec(src);
    for (; m !== null; m = re.exec(src)) {
      let i = src.indexOf("(", m.index + m[0].length - 1);
      let depth = 0;
      for (; i < src.length; i++) {
        const c = src[i];
        if (c === "(") depth++;
        else if (c === ")") { depth--; if (depth === 0) break; }
      }
      let angle = 0;
      let open = -1;
      for (let k = i + 1; k < src.length; k++) {
        const c = src[k];
        if (c === "<") angle++;
        else if (c === ">") { if (angle > 0) angle--; }
        else if (c === "{" && angle === 0) { open = k; break; }
        else if (c === ";" && angle === 0) break;
      }
      if (open < 0) continue;
      depth = 0;
      let j = open;
      for (; j < src.length; j++) {
        const c = src[j];
        if (c === "{") depth++;
        else if (c === "}") { depth--; if (depth === 0) break; }
      }
      const body = src.slice(open, j + 1);
      const prev = out.get(m[1] ?? "");
      if (prev === undefined || body.length > prev.length) out.set(m[1] ?? "", body);
    }
  }
  return out;
}

// forwardedDoPaths reads the DO paths a router case forwards to, straight out of its doURL(...) calls. The
// query string is dropped (the arm is keyed on the pathname), and a template hole ends the path.
function forwardedDoPaths(d: DispatchedCase): string[] {
  const method = d.key.split(" ")[0] ?? "";
  return [...d.body.matchAll(/doURL\(\s*[`"]([^`"$?]*)/g)].map((m) => `${method} ${m[1] ?? ""}`);
}

// handlerNamesIn returns the DO methods an arm calls on itself, which is where the authority re-check lives
// when there is one. The response wrappers are excluded: they carry no authority and matching them would let
// every arm look like it named a handler.
const ARM_WRAPPERS = new Set(["json", "jsonStatus", "ownerActionJson", "text"]);
function handlerNamesIn(armBody: string): string[] {
  return [...armBody.matchAll(/\bthis\.([A-Za-z][A-Za-z0-9_]*)\s*\(/g)].map((m) => m[1] ?? "").filter((n) => !ARM_WRAPPERS.has(n));
}

// ---- The declaration --------------------------------------------------------------------------------
// EVERY dispatched admin route that calls no gate(caller,...) at the router,. The class is
// the mechanism, where one was established from source:
//
//   break-glass-token     the body calls requireLiveBreakGlassToken, so the route needs the live ADMIN_TOKEN
//                         bearer rather than a capability. CHECKED below.
//   owner-action-gate     the body calls ownerActionGate, the dual-control owner-action chokepoint. CHECKED.
//   spoke-owner-only      the spoke's handler refuses a non-owner ONCE before its switch, so no per-case gate
//                         is possible or wanted. CHECKED below, at the file level.
//   delegated-to-handler  the case body's only act is to return another handler, which carries the gate.
//                         CHECKED below.
//   case-owner-only       the case body itself refuses caller.role !== "owner" before it acts. Distinct from
//                         spoke-owner-only, which is one refusal for a whole file. CHECKED below.
//   do-recheck-capability the router forwards the caller and the DO RE-RESOLVES its authority from the DO's
//                         own tables before answering: the arm decodes the caller and the handler it names
//                         calls requireCapabilityResolved, which throws AuthError -> 403 on a miss. CHECKED
//                         below in all three parts. This is the one class where the router is the WRONG home
//                         for the gate: every member has a self arm (a caller may always read or revoke their
//                         OWN credentials and needs roles.write only for someone else's), and "self or the
//                         capability" cannot be expressed as gate(caller, cap) at the router.
//   self-scoped-handler   the router forwards the caller and the DO handler acts ONLY on that caller's own
//                         principal (its own passkeys, its own sessions), so there is no other subject to
//                         authorise. CHECKED: the arm decodes the caller, the handler reads caller.email or
//                         caller.subject, and it does NOT call requireCapabilityResolved (which is what
//                         separates this class from the one above).
//   self-scoped-router    the answer is built at the router from the caller's OWN identity and goes nowhere
//                         else (GET /whoami returns the caller; POST /email/test sends only to caller.email).
//                         CHECKED: the body reads caller.email/method/role and forwards no DO path.
//   capability-scoped-response  the router resolves callerCan(caller, cap) and passes the verdict to the DO,
//                         which FILTERS the response by it rather than refusing: a non-approver sees their own
//                         requests, an approver sees every one. A gate would be wrong here, because the route
//                         is legitimately readable by both and they must see different rows. CHECKED below.
//   authenticated-only    AUTHENTICATION IS THE WHOLE OF THE PROTECTION, and that is a measured fact rather
//                         than a shrug: the route calls no gate, and NOTHING DOWNSTREAM CAN ENFORCE EITHER,
//                         because no principal is conveyed to any Durable Object arm it forwards to. CHECKED
//                         below. It is NOT a certification that the route is correctly ungated, which is why
//                         every member carries `why` -- the reason it stays here rather than moving.
//   none-established      NO mechanism was established. Not a verdict, and it must never be read as one. It is
// EMPTY today, because the 35 routes that carried it were each resolved:
//                         nine were given a viewer-floor gate, and the rest fell into the classes
//                         above. It stays in the union because a route whose mechanism is genuinely unknown
//                         must have somewhere honest to sit, and inventing a reason for one is the rubber
//                         stamp this whole file is against.
//
// WHAT THE SWEEP FOUND, KEPT HERE BECAUSE IT IS THE REASON THE CLASSES ARE SHAPED THIS WAY. "The
// DO enforces it" was the obvious reason to give the forwarded reads and it was FALSE for five of them: GET
// /notify/rules, GET /notify/history, GET /expiry, GET /group-roles and GET /custom-roles each forwarded
// callerHeaders(caller) exactly as their gated write siblings do, and the arm on the other side
// (listNotifyRules, listNotifyHistory, listExpiryStatuses, listGroupRoles, listCustomRoles) took no caller
// argument at all. THE CALLER WAS CONVEYED AND DISCARDED, which is worse than sending none, because the
// forwarding line is the evidence a reader uses to conclude the route is authorised elsewhere. That is why
// do-recheck-capability is checked at the ARM and the HANDLER and not merely at the router's header call,
// and why authenticated-only is checked by proving no arm decodes a caller rather than by asserting it.
//
// The engine's resting role for any authenticated caller is viewer, custom roles are strictly additive over
// their built-in floor, and all six built-ins hold downpipe.read, audit.read, restore.dryrun, restore.verify,
// reports.read, posture.read and roles.read -- so nothing on this list is currently reachable by a principal
// that some OTHER route would refuse the same data to. That is a property of the role table, not of these
// routes, which is precisely why the set is worth pinning.
type UngatedClass =
  | "break-glass-token" | "owner-action-gate" | "spoke-owner-only" | "delegated-to-handler"
  | "case-owner-only" | "do-recheck-capability" | "self-scoped-handler" | "self-scoped-router"
  | "capability-scoped-response" | "authenticated-only" | "none-established";
const UNGATED: ReadonlyArray<{ key: string; cls: UngatedClass; why?: string }> = [
  { key: "POST /demo/reset", cls: "break-glass-token" },
  { key: "POST /control-plane/restore", cls: "break-glass-token" },
  { key: "POST /control-plane/restore-sealed", cls: "break-glass-token" },
  { key: "POST /control-plane/apply-staged", cls: "break-glass-token" },
  { key: "POST /support/credentials", cls: "owner-action-gate" },
  { key: "POST /update/ramp", cls: "delegated-to-handler" },
  { key: "POST /update/ramp/settle", cls: "delegated-to-handler" },
  { key: "POST /canary/config", cls: "case-owner-only" },
  { key: "POST /support/credentials/delete", cls: "case-owner-only" },
  // Every member of this class has a SELF arm, which is exactly why the gate cannot move to the router: a
  // member may always list or revoke their OWN credentials and needs roles.write only for someone else's,
  // and gate(caller, "roles.write") at the router would refuse the self case that is the whole point of the
  // route. The DO is the right home and it is the home the code already uses.
  { key: "GET /passkey/credentials", cls: "do-recheck-capability" },
  { key: "GET /passkey/credentials/all", cls: "do-recheck-capability" },
  { key: "GET /signin-factors", cls: "do-recheck-capability" },
  { key: "POST /passkey/credentials/delete", cls: "do-recheck-capability" },
  { key: "POST /signin-factors/revoke", cls: "do-recheck-capability" },
  { key: "POST /sessions/terminate-user", cls: "do-recheck-capability" },
  { key: "POST /sessions/terminate-all", cls: "do-recheck-capability" },
  { key: "POST /sessions/terminate-others", cls: "self-scoped-handler" },
  { key: "POST /stepup/begin", cls: "self-scoped-handler" },
  { key: "POST /stepup/finish", cls: "self-scoped-handler" },
  { key: "GET /whoami", cls: "self-scoped-router" },
  { key: "POST /email/test", cls: "self-scoped-router" },
  { key: "GET /restore/approvals", cls: "capability-scoped-response" },
  { key: "GET /retention-prune/approvals", cls: "capability-scoped-response" },
  // authenticated-only: nothing but authorise() stands in front of these, PROVEN by the fact that no
  // principal reaches any DO arm they forward to. `why` is the reason each stays, not an approval.
  { key: "GET /status", cls: "authenticated-only", why: "the onboarding/health presence report, read before any role table exists; it is booleans and counts computed at the router from env plus aggregate DO reads, and every gated route it summarises is separately gated" },
  { key: "GET /setup-state", cls: "authenticated-only", why: "the first-run wizard's own state, which the console must read while the account still has no owner and therefore no capability to name" },
  { key: "GET /destination", cls: "authenticated-only", why: "the same first-run presence surface as GET /setup-state, over one destination; the credential is never in the view (destStatusOf redacts)" },
  { key: "GET /preflight", cls: "authenticated-only", why: "the pre-run readiness probe, computed at the router from env with no DO subject; rate-limited rather than gated because it is the surface an operator retries when something is already wrong" },
  { key: "GET /updates", cls: "authenticated-only", why: "the update-channel check, computed from env and the signed channel document; it discloses published version numbers, not account state" },
  { key: "GET /licence", cls: "authenticated-only", why: "the effective assurance tier, deliberately fail-open (a bad or absent licence answers 200 tier community), so a gate here would refuse the one read that explains why a gated feature is unavailable" },
  { key: "GET /control-plane/status", cls: "authenticated-only", why: "the control-plane recovery status; no capability in this engine names it, and the recovery surfaces it reports on are each break-glass-token gated in their own right" },
  { key: "GET /drill-evidence", cls: "authenticated-only", why: "its POST sibling gates drill.run, but drill.run is NOT in the viewer floor and the DO's own arm documents the read as any role, so matching the sibling would refuse readers the engine says may read; no read capability names drill evidence" },
  { key: "GET /canary", cls: "authenticated-only", why: "its own comment CLAIMED a gate on 'the read capability every authenticated role holds' and it gated on nothing (corrected in place); no route discloses canary state under a capability, so there is none to derive, and its write siblings gate run.trigger and owner, both above the viewer floor" },
  { key: "GET /drill-all", cls: "authenticated-only", why: "the fleet-drill status rollup, which carried the SAME false gating claim as GET /canary and named it as its model; POST /drill-all gates drill.run, which viewer and access-admin do not hold, so matching the sibling would refuse readers rather than pin a floor" },
];

// The catalogue lines in router.ts that name a REAL route the dispatch scan cannot see, because the route is
// matched before the switch and so has no `case` label. Each is a genuine surface, not a stale line, and
// listing them here is what lets the catalogue check treat every OTHER line as something that must dispatch.
const CATALOGUE_PRE_SWITCH: ReadonlyArray<{ key: string; why: string }> = [
  { key: "GET /health", why: "the unauthenticated liveness probe, answered before authorise()" },
  { key: "POST /auth/recovery", why: "the /admin/auth/* passkey front door, handled before the auth gate" },
  { key: "POST /auth/recovery-codes/regenerate", why: "same front door as the line above" },
  { key: "POST /auth/recovery-codes/confirm", why: "same front door as the line above" },
  { key: "POST /config/changes/<id>/approve", why: "a per-request ULID path segment, matched by matchConfigChangeAction" },
  { key: "POST /config/changes/<id>/reject", why: "same dynamic matcher as the line above" },
];

// The two numbers router.ts's catalogue header states about itself. They are asserted, not decorative: a
// vague fraction is the one form of the claim that can never be checked.
const HEADER_CATALOGUED = 51;
const HEADER_DISPATCHED = 160;

// ---- Assertions -------------------------------------------------------------------------------------
const dispatched = scanDispatch();
const byKey = new Map(dispatched.map((d) => [d.key, d]));

console.log("-- the scan itself, before anything is concluded from it --");
// A scanner that reads nothing must go RED, not clean: reporting a vacuous pass is the gate lying in the one
// direction it exists to prevent.
ok("the dispatch scan found admin route cases at all (a silent zero is the failure this check exists for)", dispatched.length > 100);
ok("no two spokes dispatch the same METHOD+sub (the switch is keyed on exact equality, so a duplicate is dead code)", byKey.size === dispatched.length);
ok(`every dispatched case parses to a METHOD and an /-prefixed sub`, dispatched.every((d) => /^(GET|POST|PUT|DELETE|OPTIONS) \//.test(d.key)));

console.log("-- (1) the ungated set is EXACTLY the declared set, in both directions --");
const scannedUngated = new Set(dispatched.filter((d) => d.gates.length === 0).map((d) => d.key));
const declared = new Set(UNGATED.map((u) => u.key));
const newlyUngated = [...scannedUngated].filter((k) => !declared.has(k)).sort();
const nowGated = [...declared].filter((k) => !scannedUngated.has(k)).sort();
ok(
  `no dispatched route calls no capability gate without being declared here (found ${newlyUngated.length}${newlyUngated.length > 0 ? `: ${newlyUngated.join(", ")}` : ""})`,
  newlyUngated.length === 0,
);
ok(
  `no declared entry has quietly GAINED a gate (the record must not overstate the surface either) (found ${nowGated.length}${nowGated.length > 0 ? `: ${nowGated.join(", ")}` : ""})`,
  nowGated.length === 0,
);
const ghostDeclarations = UNGATED.filter((u) => !byKey.has(u.key)).map((u) => u.key);
ok(
  `every declared entry is a route the spokes actually dispatch (no string drifts to a silent no-op) (found ${ghostDeclarations.length}${ghostDeclarations.length > 0 ? `: ${ghostDeclarations.join(", ")}` : ""})`,
  ghostDeclarations.length === 0,
);

console.log("-- (2) every mechanism class is re-derived from source, so every reason here is a checked fact --");
const doArms = scanDoArms();
const schedHandlers = indexSchedHandlers();
// The two scans must have READ something. A scan that silently matched nothing would make every class check
// below pass for the wrong reason (an arm that does not exist conveys no caller, so authenticated-only would
// go green over the entire surface), which is the vacuous pass this file exists to make impossible.
ok("the Durable Object arm scan found route arms at all (a silent zero would make authenticated-only vacuously true)", doArms.size > 100);
ok("the src/sched handler index found handler bodies at all (a silent zero would make every do-recheck claim unfalsifiable)", schedHandlers.size > 100);
for (const { key, cls, why } of UNGATED) {
  const d = byKey.get(key);
  if (d === undefined) continue; // already reported as a ghost above
  const arms = forwardedDoPaths(d).map((p) => doArms.get(p)).filter((a): a is { file: string; conveys: boolean; body: string } => a !== undefined);
  if (cls === "break-glass-token") {
    ok(`${key} classed break-glass-token really calls requireLiveBreakGlassToken`, /requireLiveBreakGlassToken\(/.test(d.body));
  } else if (cls === "owner-action-gate") {
    ok(`${key} classed owner-action-gate really calls ownerActionGate`, /ownerActionGate\(/.test(d.body));
  } else if (cls === "delegated-to-handler") {
    ok(`${key} classed delegated-to-handler really returns another handler`, /\breturn\s+handle[A-Za-z]+\(/.test(d.body));
  } else if (cls === "case-owner-only") {
    ok(`${key} classed case-owner-only really refuses a non-owner in its own body`, /caller\.role\s*!==\s*"owner"/.test(d.body));
  } else if (cls === "do-recheck-capability") {
    // Three parts, and the middle one is the part the sweep proved cannot be assumed: the router
    // sending a caller and the DO arm decoding one are DIFFERENT facts, and five reads had the first without
    // the second. The third resolves the handler the arm names and reads ITS body, because an arm that
    // decodes a caller and hands it to a handler that ignores it is the same defect one level further down.
    const named = arms.flatMap((a) => handlerNamesIn(a.body));
    const rechecks = named.some((n) => /requireCapabilityResolved\(/.test(schedHandlers.get(n) ?? ""));
    ok(`${key} classed do-recheck-capability forwards the caller to the DO`, /callerHeaders\(caller\)/.test(d.body));
    ok(`${key} classed do-recheck-capability reaches a DO arm that DECODES that caller (not merely receives it)`, arms.length > 0 && arms.every((a) => a.conveys));
    ok(`${key} classed do-recheck-capability names a handler that calls requireCapabilityResolved`, rechecks);
  } else if (cls === "self-scoped-handler") {
    const named = arms.flatMap((a) => handlerNamesIn(a.body));
    const bodies = named.map((n) => schedHandlers.get(n) ?? "").filter((b) => b.length > 0);
    ok(`${key} classed self-scoped-handler reaches a DO arm that decodes the caller`, arms.length > 0 && arms.every((a) => a.conveys));
    ok(`${key} classed self-scoped-handler names a handler that scopes to the caller's own principal`, bodies.some((b) => /caller\??\.(email|subject)/.test(b)));
    // The negative half, and it is what keeps this class from swallowing the one above: a handler that DOES
    // re-check a capability is do-recheck-capability, and calling it self-scoped would understate it.
    ok(`${key} classed self-scoped-handler names no handler that re-checks a capability (that would be the class above)`, bodies.every((b) => !/requireCapabilityResolved\(/.test(b)));
  } else if (cls === "self-scoped-router") {
    ok(`${key} classed self-scoped-router builds its answer from the caller's own identity`, /caller\.(email|method|role)\b/.test(d.body));
    ok(`${key} classed self-scoped-router forwards no DO path (there is no other subject to reach)`, forwardedDoPaths(d).length === 0);
  } else if (cls === "capability-scoped-response") {
    ok(`${key} classed capability-scoped-response really resolves a capability with callerCan`, /callerCan\(caller,\s*"[^"]+"\)/.test(d.body));
    ok(`${key} classed capability-scoped-response reaches a DO arm that decodes the caller to filter on`, arms.length > 0 && arms.every((a) => a.conveys));
  } else if (cls === "authenticated-only") {
    // THE CLASS THAT HAS TO BE PROVED RATHER THAN ASSERTED. "Nothing else protects it" is only worth writing
    // down if a later edit that DOES add protection turns it red, and only credible if the absence is read
    // off the far side. So: no caller may be conveyed anywhere. A route that starts forwarding a caller has
    // stopped being authenticated-only whether or not anyone updated this table.
    ok(`${key} classed authenticated-only conveys no principal to any DO arm it forwards to`, !/callerHeaders\(caller\)/.test(d.body) && arms.every((a) => !a.conveys));
    ok(`${key} classed authenticated-only carries the reason it stays there`, typeof why === "string" && why.length > 40);
  }
}
// A `why` on any other class would be a reason nobody checks, sitting next to a mechanism that is checked.
ok("only authenticated-only entries carry a `why` (a reason on a checked class would be unread prose)", UNGATED.every((u) => u.why === undefined || u.cls === "authenticated-only"));
// spoke-owner-only is a FILE-level property (the refusal sits once, before the switch), so it is checked once
// per file rather than once per case: every case classed that way must live in a spoke whose handler refuses
// a non-owner, and that refusal must appear BEFORE the first case label.
{
  // An entry whose route the scan could not resolve is already red at the ghost assertion above, so it is
  // skipped here rather than being turned into a readFileSync on an empty path: a check must fail with the
  // reason it was written for, not with an I/O error that buries it.
  const files = new Set(UNGATED.filter((u) => u.cls === "spoke-owner-only").map((u) => byKey.get(u.key)?.file ?? "").filter((f) => f !== ""));
  for (const file of files) {
    const src = blankComments(readFileSync(join(ADMIN_DIR, file), "utf8"));
    const refusal = src.search(/caller\.role\s*!==\s*"owner"/);
    const firstCase = src.search(/^\s*case "(?:GET|POST|PUT|DELETE|OPTIONS) \//m);
    ok(`${file} refuses a non-owner before its first route case (the spoke-owner-only class)`, refusal >= 0 && firstCase >= 0 && refusal < firstCase);
  }
}

console.log("-- (3) router.ts's own endpoint catalogue: no line may name a route that does not exist --");
// The catalogue lines are read from the RAW file (not blanked), because the catalogue IS a comment block.
const catalogueLines: Array<{ key: string; line: number }> = [];
{
  const raw = readFileSync(join(ADMIN_DIR, "router.ts"), "utf8").split("\n");
  for (let i = 0; i < raw.length; i++) {
    const m = /^\/\/\s{3}(GET|POST|PUT|DELETE)\s+(\/admin\/\S*)/.exec(raw[i] ?? "");
    if (m?.[1] !== undefined && m[2] !== undefined) catalogueLines.push({ key: `${m[1]} ${m[2].replace(/^\/admin/, "")}`, line: i + 1 });
  }
}
ok("the catalogue block was found at all (a regex that stops matching must not read as an empty, clean catalogue)", catalogueLines.length > 20);
const preSwitch = new Set(CATALOGUE_PRE_SWITCH.map((p) => p.key));
const catalogueGhosts = catalogueLines.filter((c) => !byKey.has(c.key) && !preSwitch.has(c.key));
ok(
  `every catalogued line names a dispatched route or a declared pre-switch surface (found ${catalogueGhosts.length}${catalogueGhosts.length > 0 ? `: ${catalogueGhosts.map((g) => `${g.key} @router.ts:${g.line}`).join(", ")}` : ""})`,
  catalogueGhosts.length === 0,
);
// ...and the pre-switch allowlist may not outlive the lines it excuses, so a deleted catalogue line does not
// leave a permanent hole in the check above.
const staleAllowlist = CATALOGUE_PRE_SWITCH.filter((p) => !catalogueLines.some((c) => c.key === p.key)).map((p) => p.key);
ok(
  `every declared pre-switch allowance still corresponds to a real catalogue line (found ${staleAllowlist.length}${staleAllowlist.length > 0 ? `: ${staleAllowlist.join(", ")}` : ""})`,
  staleAllowlist.length === 0,
);

console.log("-- (4) the catalogue's coverage claim is a measurement, not a characterisation --");
const cataloguedThatDispatch = catalogueLines.filter((c) => byKey.has(c.key)).length;
ok(
  `the catalogue covers ${HEADER_CATALOGUED} dispatched routes as its header states (scanned ${cataloguedThatDispatch})`,
  cataloguedThatDispatch === HEADER_CATALOGUED,
);
ok(
  `the spokes dispatch ${HEADER_DISPATCHED} route cases as the header states (scanned ${dispatched.length})`,
  dispatched.length === HEADER_DISPATCHED,
);
// The two numbers must also be the numbers actually written in router.ts, or this file would be asserting
// against its own copy of them and the header could say anything.
{
  const raw = readFileSync(join(ADMIN_DIR, "router.ts"), "utf8");
  ok(
    `router.ts's header states the same two numbers this file asserts (${HEADER_CATALOGUED} of ${HEADER_DISPATCHED})`,
    new RegExp(`${HEADER_CATALOGUED}\\s+CATALOGUED\\s+OF\\s+${HEADER_DISPATCHED}\\s+DISPATCHED`, "i").test(raw),
  );
}

console.log(failures === 0 ? "ADMIN ROUTE MANIFEST VECTORS PASS" : `ADMIN ROUTE MANIFEST: ${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
