// The update lifecycle's `reason` must NOT ride into the pack, because it is no longer engine-authored text.
//
// WHY. The pack's own comment used to say the reason was "an ENGINE-authored refusal class, bounded to 200
// chars". That was true once. It is not true now: the update paths build the sentence as
//
//   `could not roll back to version ${toVersion} (...): ${msg(e)}`      update-rollback.ts
//   `the new version could not be uploaded; your engine is unchanged: ${msg(e)}`   update-ramp.ts
//   `the console bundle did not verify: ${msg(e)}`                       update-orchestrate.ts
//
// so the raw Cloudflare deploy-driver error, which can embed a URL, an account id or a script name, was riding
// into the SEALED bundle behind a 200-char clamp. A clamp is not a redaction. It bounds the length of the leak.
//
// The operator still sees the full sentence in their OWN console. What the customer SENDS US is the closed class.
//
// This test plants a hostile platform error inside the reason and asserts that not one byte of it reaches the
// bundle, while the DIAGNOSIS (the closed class) still does. Run: node test/validate-update-reason-redaction.ts
import { fetchUpdateStatus, UPDATE_REASON_CLASSES, SETTLE_STEP_DETAIL_CLASSES, READBACK_DETAIL_CLASSES } from "../src/admin/support-sections-runs.ts";
import { makeHealthGate, probeSettleVerdict } from "../src/admin/update-gate.ts";
import { readBackUploaded, type HealthGate, type SafeApplyInput } from "../src/admin/update-apply.ts";
import type { DeployDriver } from "../src/admin/update-types.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A real Cloudflare deploy error carries exactly this kind of material.
const SECRET_URL = "https://api.cloudflare.com/client/v4/accounts/ACCT-9f2c-CUSTOMER/workers/scripts/acme-prod-engine";
const PLATFORM_ERROR = `Error 10021: script acme-prod-engine not found (${SECRET_URL}) token=cf_live_SECRET_TOKEN_VALUE`;

function schedulerDouble(last: Record<string, unknown>, lastConsole: Record<string, unknown>): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/update-status") {
        return new Response(JSON.stringify({ last, lastConsole }), { headers: { "content-type": "application/json" } });
      }
      return new Response("{}", { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("the raw platform error in an update `reason` NEVER reaches the pack:");

  const env = {} as Env;

  // The worst case: a FAILED ROLLBACK. The customer is serving a version they did not want, so this is the one
  // row support most needs, and it is exactly the path that interpolates the driver's error.
  const sched = schedulerDouble(
    {
      outcome: "rollback-failed",
      at: 1_700_000_000,
      reason: `could not roll back to version v1.2.3 (the previously-live version is still serving): ${PLATFORM_ERROR}`,
    },
    {
      outcome: "refused",
      at: 1_700_000_000,
      reason: `the new console version could not be uploaded; your console is unchanged: ${PLATFORM_ERROR}`,
    },
  );

  const updates = await fetchUpdateStatus(env, sched);
  const text = JSON.stringify(updates);

  ok("the Cloudflare error text is ABSENT from the projected section", !text.includes("Error 10021"));
  ok("the account id is ABSENT", !text.includes("ACCT-9f2c-CUSTOMER"));
  ok("the script name is ABSENT", !text.includes("acme-prod-engine"));
  ok("the API URL is ABSENT", !text.includes("api.cloudflare.com"));
  ok("the token is ABSENT", !text.includes("cf_live_SECRET_TOKEN_VALUE"));
  ok("the free-text `reason` key itself is GONE from last", (updates.last as Record<string, unknown>)?.reason === undefined);
  ok("the free-text `reason` key itself is GONE from lastConsole", (updates.lastConsole as Record<string, unknown>)?.reason === undefined);

  // ...and the DIAGNOSIS survives. Redacting the evidence into uselessness would be its own failure: the whole
  // point of the class is that support can still act.
  const last = updates.last as Record<string, unknown>;
  const lastConsole = updates.lastConsole as Record<string, unknown>;
  ok("the failed ROLLBACK is still diagnosable (reasonClass = rollback-failed)", last?.reasonClass === "rollback-failed");
  ok("the failed console UPLOAD is still diagnosable (reasonClass = upload-failed)", lastConsole?.reasonClass === "upload-failed");
  ok("every projected class is a member of the closed vocabulary", (UPDATE_REASON_CLASSES as readonly string[]).includes(String(last?.reasonClass)) && (UPDATE_REASON_CLASSES as readonly string[]).includes(String(lastConsole?.reasonClass)));

  // A clean update must not fabricate a cause.
  const clean = await fetchUpdateStatus(env, schedulerDouble({ outcome: "applied", at: 1 }, {}));
  ok("a clean update carries NO reasonClass (honest absence, never a fabricated cause)", (clean.last as Record<string, unknown>)?.reasonClass === undefined);

  // ============ settleTrace[].detail carries no free text, AND IT DISCRIMINATES ==================
  // The sibling field to `reason`. No hand-written record is posted anywhere below: the trace is the one the
  // route itself builds (router-updates.ts settleTrace) from the REAL probe over the REAL gate.
  console.log("\nthe settleTrace `detail` carries no free text, and an unmeasured flight is not a pending one:");

  // THE PRODUCER PROOF DRIVES THE GATE THE ROUTE ACTUALLY BUILDS.
  //
  // The real route (router-updates.ts) ALWAYS passes makeHealthGate(...), and makeHealthGate's flyNow CANNOT
  // THROW: it wraps its own scheduler fetch in try/catch, and runCanaryCycle never throws by construction
  // (every stage catches its own I/O and returns a result). A hand-built gate whose flyNow() throws would
  // prove only that the PROJECTOR could carry a class, not that the PRODUCT could put it there. This drives
  // the REAL gate instead, with THE PLATFORM TOTALLY DEAD: every DO round trip throws the hostile Cloudflare
  // error.
  const deadPlatform: DurableObjectStub = {
    async fetch(): Promise<Response> {
      throw new Error(PLATFORM_ERROR);
    },
  } as unknown as DurableObjectStub;
  const realGate = makeHealthGate(env, deadPlatform, "0.1.9");

  // 1. The gate does not throw, which is why "flight-errored" was unreachable.
  let threw = false;
  let realVerdict: string = "";
  try {
    realVerdict = await realGate.flyNow();
  } catch {
    threw = true;
  }
  ok("the REAL production gate does NOT throw on a totally dead platform", !threw);
  ok("...it reports the same 'pending' a legitimately slow post-swap flight reports", realVerdict === "pending");

  // 2. And it now reports the fact the liveness enum cannot carry: NOTHING WAS MEASURED.
  const measuredReport = await realGate.flyNowMeasured?.();
  ok("the REAL gate reports that the flight MEASURED NOTHING (it resolved no destination, so no probe ran)", measuredReport?.measured === false && measuredReport.status === "pending");

  // 3. Driven end to end through the REAL probeSettleVerdict and the REAL projector.
  const probe = await probeSettleVerdict(realGate, { backoffMs: [1], selfCheckBackoffMs: 1, sleep: async () => {} });
  const settleTrace = probe.attempts.slice(-8).map((a) => ({ step: a.step, ok: a.ok, ...(a.detail !== undefined ? { detail: String(a.detail).slice(0, 160) } : {}) }));
  const settled = await fetchUpdateStatus(env, schedulerDouble({ outcome: "rolled-back", at: 1_700_000_000, canaryVerdict: "pending", selfCheckOk: false, settleTrace }, {}));
  const settledText = JSON.stringify(settled);
  const trace = (settled.last as { settleTrace?: Array<Record<string, unknown>> })?.settleTrace ?? [];

  ok("the Cloudflare error text is ABSENT from the projected settleTrace", !settledText.includes("Error 10021"));
  ok("the account id is ABSENT from the projected settleTrace", !settledText.includes("ACCT-9f2c-CUSTOMER"));
  ok("the API URL is ABSENT from the projected settleTrace", !settledText.includes("api.cloudflare.com"));
  ok("the token is ABSENT from the projected settleTrace", !settledText.includes("cf_live_SECRET_TOKEN_VALUE"));
  ok("the free-text `detail` key itself is GONE from every settleTrace entry", trace.length > 0 && trace.every((e) => e.detail === undefined));

  // 4. THE DISCRIMINATION THAT WAS THE WHOLE POINT. An unreachable platform used to project "pending", which is
  // exactly what a legitimately slow post-swap flight projects, so "nothing could be measured" and "wait and
  // settle again" were the same row with opposite remedies. They are now two classes, and this row is produced
  // by the real gate on the real route.
  ok("the unmeasured flight is its OWN class (detailClass = unmeasured), driven through the REAL gate", trace.some((e) => e.detailClass === "unmeasured"));
  ok("...and it is NOT 'pending': the two are distinguishable", trace.every((e) => e.step?.toString().startsWith("canary-flight") !== true || e.detailClass !== "pending"));
  ok("the self-check failure keeps its OWN class (an unmeasured flight is not a failed self-check)", trace.some((e) => e.detailClass === "selfcheck-failed"));

  // 5. THE NOISE HALF, DRIVEN BY THE REAL GATE. A hand-built gate whose flyNowMeasured returns
  // {status:"pending", measured:true} would be a shape makeHealthGate CANNOT return, proving only that the
  // RING could carry "pending", not that the PRODUCT could put it there. "pending" and "disabled" are not in
  // SETTLE_STEP_DETAIL_CLASSES because no production shape produces them; what follows is driven by the real
  // gate instead.
  //
  // A MEASURED flight: the destination BUILDS (an R2 binding is bound) and the write probe FAILS. runCanaryCycle
  // records a real write-probe FAIL aspect, so measured is true and the verdict is "ailing" -- never "unmeasured",
  // which is the class reserved for the flight that resolved no destination and attempted nothing.
  const brokenBucket = {
    async put(): Promise<never> {
      throw new Error(PLATFORM_ERROR);
    },
    async get(): Promise<null> {
      return null;
    },
    async delete(): Promise<void> {},
    async head(): Promise<null> {
      return null;
    },
    async list(): Promise<{ objects: never[]; truncated: false }> {
      return { objects: [], truncated: false };
    },
  };
  const measuringEnv = { DEST_KIND: "r2", DEST_R2: brokenBucket } as unknown as Env;
  const measuringGate = makeHealthGate(measuringEnv, schedulerDouble({}, {}), "0.1.9");
  const measuredFlight = await measuringGate.flyNowMeasured?.();
  ok("a flight whose destination BUILDS and whose write probe FAILS actually MEASURED something", measuredFlight?.measured === true);
  ok("...and a measured flight reports a liveness verdict, not the unmeasured sentinel", measuredFlight?.status === "ailing");

  const measuredProbe = await probeSettleVerdict(measuringGate, { backoffMs: [1], selfCheckBackoffMs: 1, sleep: async () => {} });
  const measuredTrace = (
    (await fetchUpdateStatus(
      env,
      schedulerDouble({ outcome: "applied", at: 1_700_000_000, canaryVerdict: "ailing", selfCheckOk: false, settleTrace: measuredProbe.attempts.slice(-8).map((a) => ({ step: a.step, ok: a.ok, ...(a.detail !== undefined ? { detail: String(a.detail) } : {}) })) }, {}),
    )).last as { settleTrace?: Array<Record<string, unknown>> }
  )?.settleTrace ?? [];
  ok("NOISE: a flight that RAN reads 'ailing' through the REAL projector, never 'unmeasured'", measuredTrace.some((e) => e.detailClass === "ailing") && !measuredTrace.some((e) => e.detailClass === "unmeasured"));
  ok("the raw platform error the broken bucket threw does NOT ride into the measured trace", !JSON.stringify(measuredTrace).includes("cf_live_SECRET_TOKEN_VALUE"));
  ok("'pending' and 'disabled' are not in the closed vocabulary: no production shape produces either", !(SETTLE_STEP_DETAIL_CLASSES as readonly string[]).includes("pending") && !(SETTLE_STEP_DETAIL_CLASSES as readonly string[]).includes("disabled"));
  ok("every projected detailClass is a member of the closed vocabulary", trace.every((e) => (SETTLE_STEP_DETAIL_CLASSES as readonly string[]).includes(String(e.detailClass))));
  ok("the step labels survive (the retry story is still ordered and countable)", trace[0]?.step === "canary-flight" && trace.some((e) => e.step === "canary-flight-retry-1"));

  // A clean settle keeps its verdicts: the closed CanaryLiveness details are engine enums and must still class.
  const aliveGate: HealthGate = { baseline: async () => "alive", flyNow: async () => "alive", selfCheck: async () => true };
  const aliveProbe = await probeSettleVerdict(aliveGate, { sleep: async () => {} });
  const aliveTrace = aliveProbe.attempts.map((a) => ({ step: a.step, ok: a.ok, ...(a.detail !== undefined ? { detail: String(a.detail) } : {}) }));
  const aliveOut = await fetchUpdateStatus(env, schedulerDouble({ outcome: "applied", at: 1, settleTrace: aliveTrace }, {}));
  const aliveRows = (aliveOut.last as { settleTrace?: Array<Record<string, unknown>> })?.settleTrace ?? [];
  ok("a healthy settle projects detailClass alive (a live flight is NOT coalesced with a thrown one)", aliveRows.length === 1 && aliveRows[0]?.detailClass === "alive");

  // A step label the engine never authors is DROPPED, not clamped: a clamp would have admitted it.
  const hostileStep = await fetchUpdateStatus(env, schedulerDouble({ outcome: "rolled-back", at: 1, settleTrace: [{ step: `flight ${SECRET_URL}`, ok: false, detail: "dead" }] }, {}));
  const hostileRows = (hostileStep.last as { settleTrace?: Array<Record<string, unknown>> })?.settleTrace ?? [];
  ok("a step label outside the engine's four shapes is DROPPED", hostileRows[0]?.step === undefined && !JSON.stringify(hostileStep).includes("api.cloudflare.com"));

  // ============= THE SECOND SIBLING LEAK, last.readback.detail =============================
  // The settleTrace fix above left the OTHER free-text field on the SAME pending record standing, behind the
  // SAME 160-char clamp, leaking by the SAME mechanism. readBackUploaded (update-apply.ts) has three detail
  // producers: two author a sentence, and the catch arm is `detail: msg(e)` -- the raw thrown error from
  // driver.fetchVersionModule, which is a fetch to the Cloudflare API.
  //
  // This drives the REAL PRODUCER: readBackUploaded, against a driver whose fetchVersionModule REJECTS, which
  // is exactly what a read-back against a missing script or a refused API call does. The ReadbackResult it
  // returns is handed to fetchUpdateStatus verbatim. Nothing is hand-written.
  console.log("\nthe raw platform error in last.readback.detail NEVER reaches the pack:");

  const input = { artefact: new Uint8Array([1]), expectedSha384: "f".repeat(96), meta: { mainModule: "index.js" }, runningVersion: "2026.07.01", recommendedVersion: "2026.07.02", dryRun: false } as unknown as SafeApplyInput;
  const throwingDriver = {
    fetchVersionModule: async (): Promise<Uint8Array> => {
      throw new Error(PLATFORM_ERROR);
    },
  } as unknown as DeployDriver;

  const thrown = await readBackUploaded(throwingDriver, input, "v1", "warn");
  ok("the REAL read-back produced the leaky detail (the leak exists; it is not hypothetical)", thrown.verdict === "unavailable" && typeof thrown.detail === "string" && thrown.detail.includes(SECRET_URL));

  const rb = await fetchUpdateStatus(env, schedulerDouble({ outcome: "applied", at: 1, readback: thrown }, {}));
  const rbText = JSON.stringify(rb);
  const rbOut = (rb.last as { readback?: Record<string, unknown> })?.readback ?? {};

  ok("the Cloudflare error text is ABSENT from the projected readback", !rbText.includes("Error 10021"));
  ok("the account id is ABSENT from the projected readback", !rbText.includes("ACCT-9f2c-CUSTOMER"));
  ok("the API URL is ABSENT from the projected readback", !rbText.includes("api.cloudflare.com"));
  ok("the token is ABSENT from the projected readback", !rbText.includes("cf_live_SECRET_TOKEN_VALUE"));
  ok("the free-text `detail` key itself is GONE from the readback", rbOut.detail === undefined);

  // ...and the DIAGNOSIS survives, and DISCRIMINATES. The three read-back arms are three different tickets.
  ok("the thrown read-back is still diagnosable (detailClass = readback-errored)", rbOut.detailClass === "readback-errored");

  // A driver with no read-back support at all: an honest non-answer, and NOT the same row as a thrown fetch.
  const noSupport = await readBackUploaded({} as unknown as DeployDriver, input, "v1", "warn");
  const nsOut = ((await fetchUpdateStatus(env, schedulerDouble({ outcome: "applied", at: 1, readback: noSupport }, {}))).last as { readback?: Record<string, unknown> })?.readback ?? {};
  ok("a driver that cannot read back is its OWN class (driver-unsupported), not coalesced with a thrown one", nsOut.detailClass === "driver-unsupported" && nsOut.detailClass !== rbOut.detailClass);

  // The incident-grade arm: the platform's bytes are NOT the signed release. Must keep its own class and its digest.
  const mismatchDriver = { fetchVersionModule: async (): Promise<Uint8Array> => new Uint8Array([9, 9, 9]) } as unknown as DeployDriver;
  const mismatch = await readBackUploaded(mismatchDriver, input, "v1", "enforce");
  const mmOut = ((await fetchUpdateStatus(env, schedulerDouble({ outcome: "refused", at: 1, readback: mismatch }, {}))).last as { readback?: Record<string, unknown> })?.readback ?? {};
  ok("a digest mismatch keeps its OWN class (the deployed artefact is not the signed release)", mmOut.detailClass === "digest-differs" && mmOut.verdict === "mismatch");
  ok("the mismatch still carries the public deployedSha384 (a digest, never a secret)", typeof mmOut.deployedSha384 === "string" && (mmOut.deployedSha384 as string).length > 0);

  ok("every projected readback detailClass is a member of the closed vocabulary", [rbOut, nsOut, mmOut].every((r) => (READBACK_DETAIL_CLASSES as readonly string[]).includes(String(r.detailClass))));

  console.log(failures === 0 ? "\nUPDATE REASON REDACTION: ALL PASS" : `\nUPDATE REASON REDACTION: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
