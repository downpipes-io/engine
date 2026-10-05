// The update settle must record the canary baseline it decided against, and whether that baseline was a failed read.
//
// decideKeep compares the post-deploy canary verdict with the BASELINE read before the update: an alive baseline
// that goes not-alive is the regression the ramp rolls back on. A failed baseline read is coerced to "pending",
// which can never show a regression, so the guard is off for that settle. The canaryBaseline was in neither the
// /update-settled record nor the audit detail (router-updates.ts, router-updates-ramp.ts), and the failed read left
// only a fleet-wide counter (update-degraded-baseline-read-failed) that no settle pointed at.
//
// With the change the gate reports a failed read (baselineMeasured), the apply carries it in the pending, both
// settle paths record canaryBaseline and canaryBaselineReadFailed in the settled record and name the baseline in
// the audit detail, and the pack projects both, closed.
//
// Run: node test/validate-update-settle-baseline.ts

import { readFileSync } from "node:fs";
import { fetchUpdateStatus } from "../src/admin/support-sections-runs.ts";
import { settleAfterPromote, settleAfterRamp } from "../src/admin/update-apply.ts";
import { makeHealthGate } from "../src/admin/update-gate.ts";
import type { HealthGate } from "../src/admin/update-types.ts";
import type { Env } from "../src/env.d.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { blankComments } from "../scripts/lib/blank-comments.mjs";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const canaryStub = (mode: "alive" | "throw"): DurableObjectStub =>
  ({
    fetch: async (input: RequestInfo | URL) => {
      const p = new URL(String(input)).pathname;
      if (p === "/canary") {
        if (mode === "throw") throw new Error("DO unavailable");
        return new Response(JSON.stringify({ status: "alive" }), { status: 200 });
      }
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    },
  }) as unknown as DurableObjectStub;

const driver = { deployVersion: async () => undefined } as never;
const args = { fromVersion: "v-old", toVersion: "v-new", recommendedVersion: "0.4.0" };

async function main(): Promise<void> {
  console.log("A. the production gate reports a failed baseline read:");
  const env = {} as unknown as Env;
  const broken = makeHealthGate(env, canaryStub("throw"), "0.4.0") as HealthGate & { baselineMeasured?: () => Promise<{ status: string; readFailed: boolean }> };
  const healthy = makeHealthGate(env, canaryStub("alive"), "0.4.0") as typeof broken;
  const b1 = typeof broken.baselineMeasured === "function" ? await broken.baselineMeasured() : undefined;
  ok("a DO fault reads as {pending, readFailed: true}", b1?.status === "pending" && b1.readFailed === true);
  const b2 = typeof healthy.baselineMeasured === "function" ? await healthy.baselineMeasured() : undefined;
  ok("a healthy read is {alive, readFailed: false}", b2?.status === "alive" && b2.readFailed === false);
  ok("baseline() is unchanged: the failed read is still pending", (await broken.baseline()) === "pending");

  console.log("B. both settle orchestrators carry the flag:");
  const failedGate: HealthGate = { baseline: async () => { throw new Error("read failed"); }, flyNow: async () => "ailing", selfCheck: async () => true };
  const ramp = (await settleAfterRamp(driver, failedGate, args)) as { canaryBaseline?: string; canaryBaselineReadFailed?: boolean };
  ok("settleAfterRamp: canaryBaseline pending with canaryBaselineReadFailed", ramp.canaryBaseline === "pending" && ramp.canaryBaselineReadFailed === true);
  const promote = (await settleAfterPromote(driver, failedGate, args)) as { canaryBaseline?: string; canaryBaselineReadFailed?: boolean };
  ok("settleAfterPromote (no carried baseline): the same", promote.canaryBaseline === "pending" && promote.canaryBaselineReadFailed === true);
  const okGate: HealthGate = { baseline: async () => "alive", flyNow: async () => "alive", selfCheck: async () => true };
  const clean = (await settleAfterRamp(driver, okGate, args)) as { canaryBaselineReadFailed?: boolean };
  ok("control: a baseline that was read carries no flag", clean.canaryBaselineReadFailed === undefined);

  console.log("C. every settle record and audit detail names the baseline (both routes):");
  const writes: Array<{ file: string; body: string }> = [];
  const audits: Array<{ file: string; body: string }> = [];
  for (const f of ["router-updates.ts", "router-updates-ramp.ts"]) {
    const text = blankComments(readFileSync(new URL(`../src/admin/${f}`, import.meta.url), "utf8"));
    // Each write is read as a STATEMENT (to its first ";"), since a body can start on the next line. The
    // superseded and expired records are not settle decisions (no canary was consulted) and are excluded.
    for (const m of text.matchAll(/"\/update-settled"[^;]*;/g)) {
      const body = m[0];
      if (body.includes('outcome: "superseded"') || body.includes('outcome: "expired"')) continue;
      writes.push({ file: f, body });
    }
    for (const line of text.split("\n")) {
      if (line.includes('"update-applied" : "update-rolled-back"')) audits.push({ file: f, body: line });
    }
  }
  ok(`population: ${writes.length} settle-decision writes to /update-settled`, writes.length >= 3);
  const bare = writes.filter((w) => !w.body.includes("canaryBaseline") && !w.body.includes("baselineFields"));
  ok(`every one carries the baseline${bare.length > 0 ? ` (missing in ${bare.map((w) => w.file).join(", ")})` : ""}`, bare.length === 0);
  ok(`population: ${audits.length} settle audit rows`, audits.length >= 2);
  ok("every settle audit detail names the baseline", audits.every((a) => a.body.includes("baseline ${")));
  const apply = readFileSync(new URL("../src/admin/router-updates.ts", import.meta.url), "utf8").split("\n").find((l) => l.includes('"/update-pending"')) ?? "";
  ok("the apply's pending record carries a failed baseline read forward", apply.includes("canaryBaselineReadFailed"));

  console.log("D. the pack projects both, closed:");
  const last = { outcome: "applied", recommendedVersion: "0.4.0", canaryVerdict: "ailing", canaryBaseline: "pending", canaryBaselineReadFailed: true };
  const stub = (l: unknown): DurableObjectStub => ({ fetch: async () => new Response(JSON.stringify({ pending: null, last: l }), { status: 200 }) }) as unknown as DurableObjectStub;
  const u = (await fetchUpdateStatus(env, stub(last))) as { last?: Record<string, unknown> };
  ok("updates.last.canaryBaseline rides", u.last?.canaryBaseline === "pending");
  ok("updates.last.canaryBaselineReadFailed rides", u.last?.canaryBaselineReadFailed === true);
  const odd = (await fetchUpdateStatus(env, stub({ ...last, canaryBaseline: "SNTL-U5 free text" }))) as { last?: Record<string, unknown> };
  ok("control: a baseline outside the liveness vocabulary is dropped", !JSON.stringify(odd).includes("SNTL-U5"));
  const notBool = (await fetchUpdateStatus(env, stub({ ...last, canaryBaselineReadFailed: "yes SNTL-U5" }))) as { last?: Record<string, unknown> };
  ok("control: a failed-read flag that is not the boolean true is dropped", notBool.last?.canaryBaselineReadFailed === undefined && !JSON.stringify(notBool).includes("SNTL-U5"));

  console.log("E. through the real DO: the settled record keeps both fields and the pack reads them back:");
  {
    const dobj = new SchedulerDO({ storage: new MockStorage() } as unknown as DurableObjectState);
    const real = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(input instanceof Request ? input : new Request(String(input), init)) } as unknown as DurableObjectStub;
    await real.fetch("https://scheduler.internal/update-settled", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ outcome: "applied", recommendedVersion: "0.4.0", fromVersion: "v-old", toVersion: "v-new", canaryVerdict: "ailing", canaryBaseline: "pending", canaryBaselineReadFailed: true, at: Date.now(), by: null }) });
    const packed = (await fetchUpdateStatus(env, real)) as { last?: Record<string, unknown> };
    ok("the pack reads canaryBaseline back from the stored settled record", packed.last?.canaryBaseline === "pending");
    ok("the pack reads canaryBaselineReadFailed back from the stored settled record", packed.last?.canaryBaselineReadFailed === true);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-update-settle-baseline (${failures} failure(s))`);
  verdictReached(failures, checks);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
