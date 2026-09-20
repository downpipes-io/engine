// Prove that gate(), the per-route capability check every admin route shares, LOGS a capability-gate
// 403 (ASVS V16.3.2: authorization failures, including capability-gate denials, are logged) and logs
// nothing at all on a grant.
//
// WHY THIS EXISTS. gate() is called from ~150 sites across the router spokes and answers a bare 403
// with no side effect: measured 2026-09-13, only 18 of those call sites' routes were named in the hub's
// ADMIN_WRITE_SURFACES table (router.ts's one write-refusal recorder), so 113+ capability-gate denials
// reached neither the tamper-evident audit chain nor Workers Logs. This drives the REAL gate() and
// asserts a Layer 2 log line is emitted on every denial and NONE on a grant, so a revert of the fix (the
// call to logCapabilityDenied removed from inside gate()) is caught here rather than by a later reviewer
// re-deriving the same route inventory.
//
// Run: node test/validate-capability-gate-denied-logged.ts
//
// House style: Australian English, no em dashes, no rule-of-three.

import { gate } from "../src/admin/router-core.ts";
import type { Caller } from "../src/admin/identity.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// captureErrors swaps console.error for a collector, exactly as test/validate-errlog.ts does, and does
// NOT suppress the real console.error so the run's own output still reaches the terminal.
function captureErrors(): { lines: string[]; restore: () => void } {
  const lines: string[] = [];
  const real = console.error;
  console.error = (...args: unknown[]) => {
    lines.push(args.map((a) => String(a)).join(" "));
    real(...args);
  };
  return { lines, restore: () => { console.error = real; } };
}

function viewerCaller(): Caller {
  return { method: "access", email: "viewer@example.com", subject: "sub-viewer", role: "viewer", groups: [] };
}

function main(): void {
  console.log("capability-gate-denied logging (ASVS V16.3.2):");

  // 1) A DENIAL logs exactly one Layer 2 line naming the required capability and the caller's role.
  {
    const cap = captureErrors();
    const resp = gate(viewerCaller(), "keys.ceremony");
    cap.restore();
    ok("a denied gate() returns a 403", resp !== null && resp.status === 403);
    ok(`a denied gate() logs exactly one line (got ${cap.lines.length})`, cap.lines.length === 1);
    const line = cap.lines[0] ?? "";
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      parsed = undefined;
    }
    const rec = parsed as { level?: string; event?: string } | undefined;
    ok("the logged line is well-formed JSON", rec !== undefined);
    ok(`the logged line is level "error" (got ${JSON.stringify(rec?.level)})`, rec?.level === "error");
    ok(`the logged event names the required capability (got ${JSON.stringify(rec?.event)})`, typeof rec?.event === "string" && rec.event.includes("capability=keys.ceremony"));
    ok(`the logged event names the caller's role (got ${JSON.stringify(rec?.event)})`, typeof rec?.event === "string" && rec.event.includes("have=viewer"));
    ok("the logged event never carries the caller's email", typeof rec?.event === "string" && !rec.event.includes("viewer@example.com"));
    ok("the logged event never carries the caller's subject", typeof rec?.event === "string" && !rec.event.includes("sub-viewer"));
  }

  // 2) A GRANT logs nothing at all (the noise-discipline half: a working check succeeding is not a
  // security event, and a line for every one of them would drown the denials this exists to surface).
  {
    const cap = captureErrors();
    const resp = gate(viewerCaller(), "downpipe.read");
    cap.restore();
    ok("a granted gate() returns null", resp === null);
    ok(`a granted gate() logs nothing (got ${cap.lines.length} line(s))`, cap.lines.length === 0);
  }

  // 3) Two distinct denials on the SAME caller log two distinct lines, each naming its own capability:
  // a flood of denials is not silently coalesced into one, and a later denial does not overwrite an
  // earlier one's fields.
  {
    const cap = captureErrors();
    gate(viewerCaller(), "keys.ceremony");
    gate(viewerCaller(), "access.policy");
    cap.restore();
    ok(`two denials log two lines (got ${cap.lines.length})`, cap.lines.length === 2);
    ok("the first line names its own capability", (cap.lines[0] ?? "").includes("capability=keys.ceremony"));
    ok("the second line names its own capability", (cap.lines[1] ?? "").includes("capability=access.policy"));
  }

  console.log(failures === 0 ? "\ncapability-gate-denied logging: PASS" : `\ncapability-gate-denied logging: ${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main();
