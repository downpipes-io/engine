// Prove the support pack projects the update lifecycle fields the DO already records.
//
// The updates section carried only pending/last(outcome,versions,canary,selfCheck,settleTrace)/rollbackNeeded.
// The DO update record also holds: last.readback (the apply-time release-digest cross-check; a mismatch is
// incident-grade -- the deployed artefact is not the signed release), last.confirmationPending (applied but
// awaiting the hourly canary), lastConsole (the console component's own self-apply lifecycle, distinct from
// the engine), and a bounded history ring (a rollback that scrolled off `last`). None rode the pack, so
// "my update/rollback failed / half-applied / silently reverted" was undiagnosable. This drives the real
// fetchUpdateStatus through a DO double and asserts the new fields ride and the readback verdict is gated.
//
// Run:  node test/validate-support-update-detail.ts

import { fetchUpdateStatus } from "../src/admin/support-sections-runs.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function scheduler(updateRecord: unknown): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      if (url.pathname === "/update-status") return new Response(JSON.stringify(updateRecord));
      if (url.pathname === "/sources/discovery-config") return new Response(JSON.stringify({ config: null }));
      return new Response("{}");
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  console.log("validate-support-update-detail\n");

  const env = { CF_ACCOUNT_ID: "acct" } as unknown as Env;
  const record = {
    pending: null,
    last: {
      outcome: "rolled-back",
      toVersion: "0.2.0",
      canaryVerdict: "dead",
      at: 1_800_000_000_000,
      confirmationPending: true,
      readback: { verdict: "mismatch", deployedSha384: "a".repeat(96), detail: "deployed digest != signed release", mode: "strict" },
    },
    lastConsole: { outcome: "applied", toVersion: "0.2.0", confirmedLive: false, at: 1_800_000_000_001, component: "console", reason: "awaiting browser confirm" },
    history: [
      { outcome: "applied", toVersion: "0.1.9", at: 1, component: "engine", canaryVerdict: "alive" },
      { outcome: "rolled-back", toVersion: "0.2.0", at: 2, component: "engine", canaryVerdict: "dead" },
    ],
  };

  const u = (await fetchUpdateStatus(env, scheduler(record))) as Record<string, unknown>;
  const last = u.last as Record<string, unknown>;
  const readback = last.readback as Record<string, unknown>;
  const lastConsole = u.lastConsole as Record<string, unknown>;
  const history = u.history as Array<Record<string, unknown>>;

  ok("last.readback carries the closed verdict + the public deployedSha384 (incident-grade mismatch visible)", readback.verdict === "mismatch" && readback.deployedSha384 === "a".repeat(96));
  ok("last.confirmationPending rides (applied but awaiting canary confirmation)", last.confirmationPending === true);
  ok("lastConsole carries the console component's own outcome + confirmedLive", lastConsole.outcome === "applied" && lastConsole.confirmedLive === false && lastConsole.component === "console");
  // `?.` on the indexed read, not a non-null assertion: the length check above is what proves the row exists,
  // and an absent row still fails the equality (undefined never equals "rolled-back"), so the assertion is exact.
  ok("history rides the bounded outcome ring (a rollback that scrolled off last)", Array.isArray(history) && history.length === 2 && history[1]?.outcome === "rolled-back");

  // An out-of-vocab readback verdict is dropped (gate), not echoed.
  const bad = (await fetchUpdateStatus(env, scheduler({ last: { outcome: "applied", readback: { verdict: "totally-made-up" } } }))) as Record<string, unknown>;
  ok("an out-of-vocab readback verdict is dropped, not echoed", (((bad.last as Record<string, unknown>).readback) as Record<string, unknown>).verdict === undefined);

  // =========================================================================================================
  // REDACTION: THE LAST TWO RAW PLATFORM STRINGS IN updates.last.
  //
  // The free-text `reason` field can carry the raw Cloudflare deploy error. Two more raw-string fields exist
  // in the SAME object literal, both behind only a 160-char clamp: settleTrace[].detail
  // (update-gate.ts interpolates the raw canary-flight exception, which embeds the canary URL and hostname)
  // and readback.detail (update-apply.ts returns the raw Cloudflare API message on a thrown read-back, which
  // embeds a URL, an account id and a script name). A CLAMP IS NOT A REDACTION: it bounds the LENGTH of the
  // leak, not its content. Both are now classified into closed members.
  //
  // The single likeliest populator of the settleTrace arm is the very incident this section exists for: a
  // failed rollback with an AILING canary, which is exactly what update-gate.ts's catch branch returns.
  // =========================================================================================================
  const LEAK = "https://canary.acct-9f3c1.example.workers.dev/probe?key=downpipes-prod-bucket/ACME-2026";
  const leaky = {
    last: {
      outcome: "rollback-failed",
      reason: `the rollback failed and the previously-live version is still serving: ${LEAK}`,
      settleTrace: [
        { step: "canary-flight", ok: false, detail: "ailing" },
        // The flight that MEASURED NOTHING (it resolved no destination, so no probe ran). This detail is
        // ENGINE-AUTHORED by probeSettleVerdict against the real gate, and it must be distinguished from a
        // legitimately slow "pending" flight.
        { step: "canary-flight-retry-1", ok: false, detail: "the canary flight measured nothing: it resolved no destination, so no probe was attempted" },
        // A HOSTILE / DRIFTED detail carrying a live platform URL. No production path can author this, so
        // what matters is that it is CLASSIFIED to the residual rather than clamped through. A clamp would
        // bound the length of the leak, not remove it.
        { step: "canary-flight-retry-2", ok: false, detail: `the canary flight errored: fetch to ${LEAK} failed` },
        { step: "self-check", ok: false, detail: "the new version did not pass its self-check" },
      ],
      readback: { verdict: "unavailable", detail: `PUT ${LEAK} returned 403 for account 9f3c1: script downpipes-engine` },
    },
  };
  const clean = (await fetchUpdateStatus(env, scheduler(leaky))) as Record<string, unknown>;
  const cl = clean.last as Record<string, unknown>;
  const trace = cl.settleTrace as Array<Record<string, unknown>>;
  const rb2 = cl.readback as Record<string, unknown>;
  const serialised = JSON.stringify(clean);

  ok("REDACTION: NOT ONE byte of the raw platform error reaches the pack (no URL, host, account id or object key)", !serialised.includes("canary.acct-9f3c1") && !serialised.includes("downpipes-prod-bucket") && !serialised.includes("ACME-2026") && !serialised.includes("9f3c1"));
  ok("REDACTION: the raw `detail` FIELD is gone from settleTrace and from readback (it is not clamped, it is classified)", trace.every((t) => t.detail === undefined) && rb2.detail === undefined);
  // The four rows are asserted positionally, so the length is asserted with them: a trace that lost a row would
  // otherwise slide the classes along and still satisfy three of the four equalities.
  ok("the settleTrace CLASS rides instead: ailing, UNMEASURED, the residual, and a failed self-check", trace.length === 4 && trace[0]?.detailClass === "ailing" && trace[1]?.detailClass === "unmeasured" && trace[2]?.detailClass === "other" && trace[3]?.detailClass === "selfcheck-failed");
  ok("DISCRIMINATION: four different classes (all four were one clamped sentence)", new Set(trace.map((t) => t.detailClass)).size === 4);
  ok("an UNRECOGNISED detail coarsens to the residual `other` -- never passed through, never clamped", trace[2]?.detailClass === "other" && trace[2].detail === undefined);
  ok("the readback CLASS rides: a THROWN read-back is readback-errored, distinct from the driver simply not supporting it", rb2.detailClass === "readback-errored" && rb2.verdict === "unavailable");
  ok("the closed reasonClass still rides, and it tells the truth about the rollback", cl.reasonClass === "rollback-failed" && cl.stillServingBadVersion === true);

  const unsupported = (await fetchUpdateStatus(env, scheduler({ last: { outcome: "applied", readback: { verdict: "unavailable", detail: "the deploy driver does not support version read-back" } } }))) as Record<string, unknown>;
  const ur = ((unsupported.last as Record<string, unknown>).readback) as Record<string, unknown>;
  ok("DISCRIMINATION: 'the driver cannot read back' and 'the read-back threw' are two rows under one verdict", ur.detailClass === "driver-unsupported" && ur.detailClass !== rb2.detailClass);
  ok("NOISE: a healthy apply names no reason class (a clean update HAS no cause; inventing one sends support hunting a fault that is not there)", (unsupported.last as Record<string, unknown>).reasonClass === undefined);

  console.log(failures === 0 ? "\nALL SUPPORT-UPDATE-DETAIL VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
