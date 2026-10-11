// Three support-pack timestamps that no pack could carry, although their writers run.
//
// adminRouteErrors.lastAt and recovery.recoveryRefusals.lastAt: the DO records stamp lastAt as epoch
// milliseconds (diag-records.ts applyAdminRouteError, applyRecoveryRefusal), and the pack read it with clampTs,
// which admits only a string. Both were dropped from every pack, so "when did the update route last fail" and
// "when was the last manual recovery refused" had no answer beside the counts.
//
// schedDiag.posture.overrides[].at: the override writer (POST /posture/accept) stores acceptedAt, and
// readPostureDiag read `at`, so every override reached the pack with no time. An override accepted the day
// before an incident could not be told from one accepted a year before.
//
// Each block drives the REAL SchedulerDO through its real route, builds the real bundle, and asserts the field
// in the built bundle. The controls check that each field is a number or an ISO timestamp by construction:
// text, a zero seed, a fraction or a negative stamp does not ride, and neither does the override's reason or
// the accepting owner's e-mail.
//
// Run: node test/validate-pack-dead-timestamps.ts

import { buildSupportBundle } from "../src/admin/support.ts";
import { fetchAdminRouteErrors } from "../src/admin/support-sections-faults.ts";
import { fetchSchedDiag } from "../src/admin/support-sections-diag.ts";
import { fetchRecoveryStatus } from "../src/admin/support-sections-recovery.ts";
import type { Env } from "../src/env.d.ts";
import { makeScheduler, OWNER_ACCESS_HEADER } from "./validate-posture-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const SENTINEL_EMAIL = "sntl-owner@acme.example";
const SENTINEL_REASON = "SNTL-reason bucket acme-prod-ledger";

function realDO(): { stub: DurableObjectStub; post: (path: string, body: unknown, caller?: string) => Promise<Response>; get: (path: string) => Promise<unknown> } {
  const { stub: dobj } = makeScheduler();
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(String(input), init)),
  } as unknown as DurableObjectStub;
  const post = (path: string, body: unknown, caller?: string): Promise<Response> =>
    dobj.fetch(new Request(`https://scheduler.internal${path}`, { method: "POST", headers: { "content-type": "application/json", ...(caller !== undefined ? { "x-downpipe-caller": caller } : {}) }, body: JSON.stringify(body) }));
  const get = async (path: string): Promise<unknown> => (await dobj.fetch(new Request(`https://scheduler.internal${path}`))).json();
  return { stub, post, get };
}

function stub(routes: Record<string, unknown>): DurableObjectStub {
  return {
    fetch: async (input: RequestInfo | URL) => {
      const path = new URL(input instanceof Request ? input.url : String(input)).pathname;
      return new Response(JSON.stringify(path in routes ? routes[path] : {}), { status: 200 });
    },
  } as unknown as DurableObjectStub;
}

const isStamp = (v: unknown): boolean => typeof v === "number" && Number.isSafeInteger(v) && v > 0;

async function main(): Promise<void> {
  console.log("adminRouteErrors.lastAt, through the real DO and the built bundle:");
  {
    const d = realDO();
    const before = Date.now();
    await d.post("/diag/admin-route-error", { route: "update-apply", stage: "deploy-driver" });
    const stored = ((await d.get("/admin-route-errors")) as { errors?: { lastAt?: unknown } }).errors;
    ok("population: the DO record stamps lastAt as epoch ms (a number)", isStamp(stored?.lastAt) && (stored?.lastAt as number) >= before);
    const bundle = await buildSupportBundle({} as unknown as Env, d.stub);
    const are = bundle.adminRouteErrors as Record<string, unknown> | undefined;
    ok("the section is built (mutatingFaults rides)", are?.mutatingFaults === 1);
    ok("adminRouteErrors.lastAt rides as the stored epoch-ms integer", isStamp(are?.lastAt) && are?.lastAt === stored?.lastAt);
  }

  console.log("recovery.recoveryRefusals.lastAt, through the real DO and the built bundle:");
  {
    const d = realDO();
    await d.post("/diag/recovery-refusal", { surface: "estate-import", cls: "verify-threw" });
    const stored = ((await d.get("/recovery-refusals")) as { refusals?: { lastAt?: unknown } }).refusals;
    ok("population: the DO record stamps lastAt as epoch ms (a number)", isStamp(stored?.lastAt));
    const bundle = await buildSupportBundle({} as unknown as Env, d.stub);
    const rr = (bundle.recovery as Record<string, unknown> | undefined)?.recoveryRefusals as Record<string, unknown> | undefined;
    ok("the refusal block is built (total rides)", rr?.total === 1);
    ok("recovery.recoveryRefusals.lastAt rides as the stored epoch-ms integer", isStamp(rr?.lastAt) && rr?.lastAt === stored?.lastAt);
  }

  console.log("schedDiag.posture.overrides[].at, through the real accept route and the built bundle:");
  {
    const d = realDO();
    const accepted = await d.post("/posture/accept", { checkId: "beacon-off", reason: SENTINEL_REASON, kind: "risk-accepted" }, OWNER_ACCESS_HEADER);
    ok("the owner's accept is stored (200)", accepted.status === 200);
    const bundle = await buildSupportBundle({} as unknown as Env, d.stub);
    const posture = (bundle.schedDiag as Record<string, unknown> | undefined)?.posture as { overrides?: Array<Record<string, unknown>> } | undefined;
    const ov = posture?.overrides?.[0];
    ok("the override is read (closed check id and kind ride)", ov?.checkId === "beacon-off" && ov?.overrideKind === "risk-accepted");
    ok("its at is an ISO timestamp from the stored acceptedAt", typeof ov?.at === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/.test(ov.at as string));
    ok("only the check id, the kind and the time ride", ov !== undefined && Object.keys(ov).sort().join(",") === "at,checkId,overrideKind");
    const text = JSON.stringify(bundle);
    ok("REDACTION: the override's reason and the owner's e-mail are not in the bundle", !text.includes("SNTL-reason") && !text.includes("o@example.au"));
  }

  console.log("controls: each field is a number or a timestamp by construction:");
  {
    const errs = (lastAt: unknown) => fetchAdminRouteErrors(stub({ "/admin-route-errors": { errors: { total: 1, mutatingFaults: 0, lastAt } } }));
    const drops: Array<[string, unknown]> = [["text", `2026-09-01 ${SENTINEL_EMAIL}`], ["the zero seed", 0], ["NaN", Number.NaN], ["a negative stamp", -5], ["a fraction", 1.5], ["an unsafe integer", 2 ** 60]];
    let dropped = 0;
    for (const [, v] of drops) if ((await errs(v)).lastAt === undefined) dropped++;
    ok(`adminRouteErrors.lastAt drops text, 0, NaN, negative, fractional and unsafe values (${dropped} of ${drops.length})`, dropped === drops.length);
    let rrDropped = 0;
    for (const [, v] of drops) {
      const rec = await fetchRecoveryStatus(stub({ "/recovery-refusals": { refusals: { total: 1, lastAt: v } } }), {});
      if ((rec.recoveryRefusals as Record<string, unknown> | undefined)?.lastAt === undefined) rrDropped++;
    }
    ok(`recoveryRefusals.lastAt drops the same values (${rrDropped} of ${drops.length})`, rrDropped === drops.length);
    const diag = await fetchSchedDiag(stub({ "/sched-diag": { posture: { overrides: [{ checkId: "beacon-off", overrideKind: "risk-accepted", at: `accepted by ${SENTINEL_EMAIL}` }] } } }));
    const pov = ((diag.posture as Record<string, unknown> | undefined)?.overrides as Array<Record<string, unknown>> | undefined)?.[0];
    ok("a stored override time that is not an ISO timestamp does not ride", pov?.checkId === "beacon-off" && pov.at === undefined && !JSON.stringify(diag).includes(SENTINEL_EMAIL));
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-pack-dead-timestamps (${failures} failure(s))`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
