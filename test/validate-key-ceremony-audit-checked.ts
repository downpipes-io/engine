// A LOST key-ceremony audit is COUNTED, not believed.
//
// WHY THIS EXISTS. recordAudit does not throw when the audit DO answers a non-2xx. It counts an
// "audit-write" drop and then returns normally, parsing the DO's error body as an AuditEvent. Its own
// comment says a non-2xx "still surfaces to the caller exactly as before", and as before means it does not
// surface as an error at all.
//
// router-keys.ts wraps the keys-installed append in a try/catch whose whole purpose is to notice that loss
// and count a "key-ceremony-audit" drop, with a comment that a ceremony leaving no audit event makes the
// pack read as though no ceremony ever happened. That catch could never fire for the commonest form of the
// loss, so the install handler believed it had audited.
//
// The check is that a real append carries a numeric seq. This file proves the DIFFERENCE that makes:
// a 2xx append counts nothing, a non-2xx counts the key-ceremony loss.
//
// Run: node test/validate-key-ceremony-audit-checked.ts

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { recordAudit } from "../src/admin/router-audit.ts";
import type { Caller } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const SRC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "src");
const caller = { subject: "s", email: "a@example.invalid", method: "token", role: "owner" } as unknown as Caller;

/** A scheduler stub whose /audit answers with the given status and body. */
function schedulerAnswering(status: number, body: unknown): { fetch: (u: string, i?: RequestInit) => Promise<Response> } {
  return {
    fetch: async () => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
  };
}

async function testRecordAuditDoesNotThrow(): Promise<void> {
  console.log("\n-- the behaviour that made the catch unreachable --");
  const sched = schedulerAnswering(500, { error: "storage" });
  let threw = false;
  let returned: unknown;
  try {
    returned = await recordAudit(sched as never, caller, null, "keys-installed", "success", { kind: "key-ceremony" });
  } catch {
    threw = true;
  }
  ok("recordAudit does NOT throw on a non-2xx (this is why a bare try/catch could not see the loss)", threw === false);
  ok("and it returns the DO's ERROR BODY, which carries no numeric seq", typeof (returned as { seq?: unknown })?.seq !== "number");
}

async function testTheCheckCountsTheLoss(): Promise<void> {
  console.log("\n-- the seq check is what makes the loss countable --");
  const good = await recordAudit(schedulerAnswering(200, { seq: 42, ts: "t", actorEmail: null, actorMethod: "token" }) as never, caller, null, "keys-installed", "success", { kind: "key-ceremony" });
  ok("a 2xx append returns an event carrying a numeric seq", typeof good.seq === "number");

  const bad = await recordAudit(schedulerAnswering(503, { error: "unavailable" }) as never, caller, null, "keys-installed", "success", { kind: "key-ceremony" });
  ok("a non-2xx append returns something with NO numeric seq, so the caller can tell", typeof (bad as { seq?: unknown }).seq !== "number");

  // The generic loss IS counted by recordAudit itself; the point of the fix is the key-ceremony-specific one.
  ok("recordAudit counts the generic audit-write loss", (pendingDroppedWrites()["audit-write"] ?? 0) > 0);
}

// STRUCTURAL. A behaviour test alone would pass while router-keys.ts went back to trusting the append, which
// is exactly the shape this repo has been caught by before, so the call site itself is read.
function testTheCallSiteChecks(): void {
  console.log("\n-- the key-ceremony call site actually checks --");
  const src = readFileSync(path.join(SRC, "admin", "router-keys.ts"), "utf8");
  ok("router-keys.ts has an auditChecked helper that binds the append's return value", /async function auditChecked\([\s\S]{0,600}?const appended = await recordAudit\(/.test(src));
  ok("it counts a key-ceremony-audit drop when the append carries no numeric seq", /typeof appended\?\.seq !== "number"[\s\S]{0,300}?noteDroppedWrite\("key-ceremony-audit"\)/.test(src));
  ok("and flushes it, so the loss reaches the durable aggregate rather than an isolate", /typeof appended\?\.seq !== "number"[\s\S]{0,400}?flushDroppedWrites\(scheduler\)/.test(src));
  // THE INVARIANT: NO recordAudit call outside the helper may carry a key-ceremony target. The helper is
  // then the single place that decides whether the append landed.
  const helper = /async function auditChecked\([\s\S]*?\n\}/.exec(src);
  ok("the auditChecked helper is present", helper !== null);
  const outside = helper === null ? src : src.slice(0, helper.index) + src.slice(helper.index + helper[0].length);
  const outsideLines = outside.split("\n");
  const leaked: string[] = [];
  outsideLines.forEach((line, i) => {
    if (!line.includes("recordAudit(")) return;
    if (outsideLines.slice(i, i + 4).join("\n").includes('kind: "key-ceremony"')) leaked.push(line.trim().slice(0, 60));
  });
  ok(`no key-ceremony append bypasses the helper (leaked: ${leaked.join(" | ") || "none"})`, leaked.length === 0);
  const checkedCalls = (src.match(/await auditChecked\(/g) ?? []).length;
  ok(`the key-ceremony appends route through auditChecked (found ${checkedCalls})`, checkedCalls >= 5);
}

console.log("KEY-CEREMONY AUDIT APPEND IS CHECKED");
await testRecordAuditDoesNotThrow();
await testTheCheckCountsTheLoss();
testTheCallSiteChecks();

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
