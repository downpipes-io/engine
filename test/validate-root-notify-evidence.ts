// Validates the SUPPORT-PACK fault evidence the Worker ENTRY and the EMAIL channel now record. Two
// diagnostic gaps are closed here, both undiagnosable remotely because a real fault
// was either swallowed whole or coarsened into a code that named the WRONG owner:
//
//   1. the manual (run-now) dispatch resolves a pre-seal failure by POSTing a FAILED /complete, which frees
//      the in-flight lease and records the cause. That post was `.catch(() => {})`: when the scheduler DO
//      was unavailable (usually the very reason the dispatch failed) the completion vanished silently, the
//      downpipe dangled in flight until the 30-minute lease expired, and the pack showed the STALL with no
//      cause at all -- byte-identical to a genuinely wedged seal. It is now CHECKED: the loss is noted in
//      the isolate-local pending tally and flushed to the DO's bounded droppedWrites aggregate the moment
//      the DO comes back, which is exactly when the pack is generated.
//
//   2. every email non-delivery outside the three named arms collapsed to `email-rejected`, so an ENGINE
//      formatting bug (a subject/body that failed the send primitive's own bounds) read identically to the
//      email PLATFORM refusing the send (an un-onboarded sending domain). Opposite owners, opposite fixes.
//      Worse, a platform error code that did not match the documented E_UPPER_SNAKE shape was DROPPED
//      entirely, so "the platform refused us and told us why" was indistinguishable from "the platform
//      refused us silently".
//
// EVERY field asserted here is a CLOSED ENUM MEMBER, a BOUNDED INT or a clamped timestamp. The second half of
// each block is the REDACTION proof: a customer value / secret / raw exception text is planted at the fault
// site, and the whole RECORDED result (the DO's own persisted storage, not just the return value) is
// serialised and asserted not to contain it. No network. Run:
//   node test/validate-root-notify-evidence.ts

import { postFailedCompletion } from "../src/index.ts";
import { applyDroppedWrites, DROPPED_WRITE_KINDS, DROPPED_WRITES_KEY, type DroppedWrites } from "../src/admin/diag-records.ts";
import { pendingDroppedWrites, resetPendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { deliver as emailDeliver, emailReasonToCode } from "../src/notify/channels/email.ts";
import { DELIVERY_FAIL_CODES, EMAIL_PLATFORM_CODE_OTHER, emailPlatformCodeOf, sanitiseEmailPlatformCode } from "../src/notify/types.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify/types.ts";
import { sendEmail } from "../src/email.ts";
import { makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The planted customer/secret material. A real fault at these sites carries exactly this: a destination
// bucket, a recipient address, an internal hostname and a credential, inside an exception message. If ANY of
// it appears in a RECORDED artefact the no-custody redaction contract is broken.
const SECRET = "r2-SECRET-KEY-must-never-ride";
const CUSTOMER_VALUE = "acme-payroll-prod-bucket";
const RECIPIENT = "oncall@acme-corp.example";
const RAW_ERROR = `PUT https://${CUSTOMER_VALUE}.r2.example/_RECOVERY failed 403 (key=${SECRET}, to=${RECIPIENT})`;
function scanClean(label: string, recorded: unknown): void {
  // Timestamps are STRIPPED before the scan, and are asserted separately as clamped ISO strings. They must be,
  // because the raw-status needle below is the 3-digit string "403", and a recorded lastAt whose milliseconds
  // happen to land on .403 ("...T14:03:22.403Z") contains it. That made this a REDACTION test that failed
  // roughly one run in a thousand, on the clock rather than on the code -- and a redaction gate that cries wolf
  // at random is worse than no gate, because the next person to see it red assumes it is the clock again.
  const s = JSON.stringify(recorded ?? null).replace(/\d{4}-\d{2}-\d{2}T[\d:.]+Z/g, "<ts>");
  const dirty = s.includes(SECRET) || s.includes(CUSTOMER_VALUE) || s.includes(RECIPIENT) || s.includes("403") || s.includes(RAW_ERROR);
  ok(`${label}: carries NO customer value, secret or raw error text`, !dirty);
}

// ---------------------------------------------------------------------------------------------------------
// the dropped run-completion post
// ---------------------------------------------------------------------------------------------------------
async function g224(): Promise<void> {
  console.log("a DROPPED run-completion post is recorded instead of vanishing");
  ok("run-completion is a member of the closed dropped-write vocabulary", (DROPPED_WRITE_KINDS as readonly string[]).includes("run-completion"));

  // --- the fault path: the scheduler DO is UNREACHABLE when the completion is posted -----------------------
  // This is the exact dropped-completion state: the dispatch failed because the DO was flapping, so the post that would
  // record WHY (and free the lease) cannot land either. The tally must hold the loss.
  resetPendingDroppedWrites();
  const down = {
    fetch: async (): Promise<Response> => {
      throw new Error(RAW_ERROR); // the DO is unreachable; the exception carries the customer's bucket + key
    },
  } as unknown as DurableObjectStub;
  await postFailedCompletion(down, { id: "dp-payroll", index: 7, error: "destination configuration unreadable" });
  const pendingThrow = pendingDroppedWrites();
  ok("a THROWN completion post is counted (it used to be .catch(() => {}))", pendingThrow["run-completion"] === 1);
  ok("postFailedCompletion stays FAIL-OPEN (it never throws into the caller's path)", true);
  scanClean("the pending tally", pendingThrow);

  // A NON-2XX is the same loss as a throw: the DO answered, but the completion did not land.
  const refusing = { fetch: async (): Promise<Response> => new Response("no", { status: 500 }) } as unknown as DurableObjectStub;
  await postFailedCompletion(refusing, { id: "dp-payroll", index: 8, error: "all destinations unreachable" });
  ok("a NON-2XX completion post is counted too (the write is CHECKED, not merely awaited)", pendingDroppedWrites()["run-completion"] === 2);

  // --- recovery: the DO comes back, the completion lands, and the earlier LOSS is flushed with it ----------
  // This is the whole point of the protocol: the gap is durably recorded the moment the DO is healthy, which
  // is when the pack is generated. The real SchedulerDO folds the tally through applyDroppedWrites (the
  // redaction chokepoint), so what we assert below is the DO's OWN persisted record.
  const { storage, stub } = makeScheduler();
  const completes: unknown[] = [];
  const healthy = {
    fetch: async (input: string | URL, init?: RequestInit): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      const body = init?.body !== undefined ? JSON.parse(String(init.body)) : undefined;
      if (path === "/complete") {
        completes.push(body); // the completion the DO now receives (the run is resolved, the lease freed)
        return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
      }
      return stubFetch(stub, (init?.method ?? "GET") as string, path, body);
    },
  } as unknown as DurableObjectStub;
  await postFailedCompletion(healthy, { id: "dp-payroll", index: 9, error: "all destinations unreachable" });

  ok("the healthy completion still posts exactly as before (behaviour unchanged)", completes.length === 1);
  ok("the isolate-local tally is drained on the successful write", Object.keys(pendingDroppedWrites()).length === 0);

  const rec = storage.rawGet<DroppedWrites>(DROPPED_WRITES_KEY);
  ok("the DO now holds a DURABLE record of the two lost completions", rec?.["run-completion"]?.count === 2);
  ok("the record carries a clamped timestamp", typeof rec?.["run-completion"]?.lastAt === "string" && !Number.isNaN(Date.parse(String(rec?.["run-completion"]?.lastAt))));
  scanClean("the DO's persisted droppedWrites record", rec);

  // Defence in depth on the DO side: the applier is the single redaction chokepoint. An out-of-vocabulary
  // kind (a drifted or hostile writer trying to smuggle the customer's bucket name in as a KEY) is dropped.
  const forged = applyDroppedWrites(undefined, { [CUSTOMER_VALUE]: 5, "run-completion": 1 }, "2026-07-11T00:00:00.000Z");
  ok("applyDroppedWrites DROPS an out-of-vocabulary kind (no caller-injected key)", forged[CUSTOMER_VALUE] === undefined && forged["run-completion"]?.count === 1);
  scanClean("the applier's output for a forged tally", forged);
}

// ---------------------------------------------------------------------------------------------------------
// the email failure split + the non-conforming platform code
// ---------------------------------------------------------------------------------------------------------

const EMISSION: NotifyEmission = {
  event: "backup-failure",
  severity: "critical",
  downpipeId: "dp1",
  downpipeName: "nightly-d1",
  detail: "nightly-d1 backup failed",
  at: "2026-07-11T00:00:00.000Z",
};
const CHANNEL: NotifyChannel = { id: "c-email", kind: "email", name: "on-call", enabled: true, createdAt: "2026-07-11T00:00:00.000Z", toAddresses: [RECIPIENT] } as NotifyChannel;

// emailEnv builds an env whose send_email binding REJECTS the send with the platform error the ticket
// describes. `code` is what the platform put on the exception (conforming or not).
function emailEnv(code: unknown): Env {
  return {
    EMAIL_FROM: "alerts@downpipes.example",
    EMAIL: {
      send: async (): Promise<void> => {
        const e = new Error(RAW_ERROR) as Error & { code?: unknown };
        e.code = code;
        throw e;
      },
    },
  } as unknown as Env;
}

async function g236(): Promise<void> {
  console.log("an email non-delivery names its OWNER (engine formatting vs platform refusal)");

  for (const c of ["email-subject-invalid", "email-body-invalid", "email-platform-rejected"]) {
    ok(`${c} is a member of the closed delivery-fail vocabulary`, DELIVERY_FAIL_CODES.has(c));
  }

  // The closed reason -> closed code mapping. The engine's OWN reason vocabulary (email.ts EmailResult) is
  // the only input; a platform message is never read here.
  ok("a subject that failed the send primitive's bounds is named (was email-rejected)", emailReasonToCode("email-subject-invalid") === "email-subject-invalid");
  ok("a body that failed the send primitive's bounds is named (was email-rejected)", emailReasonToCode("email-body-invalid") === "email-body-invalid");
  ok("the PLATFORM refusing the send is named (was email-rejected)", emailReasonToCode("email-send-failed") === "email-platform-rejected");
  ok("an unknown reason still falls to the residual class (no reason can escape the vocabulary)", emailReasonToCode("something-new") === "email-rejected");
  ok("every mapped code is in the closed set", ["email-not-configured", "email-from-not-configured", "email-from-invalid", "email-recipients-invalid", "email-subject-invalid", "email-body-invalid", "email-send-failed", undefined].every((r) => DELIVERY_FAIL_CODES.has(emailReasonToCode(r))));

  // The send primitive genuinely produces the two engine-side reasons the split now names, so these arms are
  // reachable rather than decorative: an over-long subject and an over-long body each get their own reason.
  const subjRes = await sendEmail({ EMAIL_FROM: "alerts@downpipes.example", EMAIL: { send: async () => {} } } as unknown as Env, { to: [RECIPIENT], subject: "x".repeat(1200), text: "body" });
  ok("sendEmail reports an over-long SUBJECT distinctly", subjRes.ok === false && subjRes.reason === "email-subject-invalid");
  const bodyRes = await sendEmail({ EMAIL_FROM: "alerts@downpipes.example", EMAIL: { send: async () => {} } } as unknown as Env, { to: [RECIPIENT], subject: "s", text: "" });
  ok("sendEmail reports an invalid BODY distinctly", bodyRes.ok === false && bodyRes.reason === "email-body-invalid");

  // --- the platform-refusal path, end to end through the adapter -------------------------------------------
  // A CONFORMING platform code is carried through unchanged (this is the diagnostic that names an onboarding
  // gap: the sending domain is not onboarded to Email Routing).
  const conforming = await emailDeliver(emailEnv("E_SENDER_DOMAIN_NOT_AVAILABLE"), CHANNEL, EMISSION);
  ok("a platform refusal is coded email-platform-rejected (not the ambiguous email-rejected)", conforming.ok === false && conforming.code === "email-platform-rejected");
  ok("the documented platform code rides (it names the onboarding gap)", conforming.platformCode === "E_SENDER_DOMAIN_NOT_AVAILABLE");
  scanClean("the delivery result for a conforming platform code", conforming);

  // A NON-CONFORMING platform code (here: free text carrying the recipient, an internal host and a secret --
  // exactly why the shape gate exists) must be recorded as the engine-owned placeholder, never dropped and
  // never carried through.
  const nonConforming = await emailDeliver(emailEnv(`rejected: ${RECIPIENT} via ${CUSTOMER_VALUE} (${SECRET})`), CHANNEL, EMISSION);
  ok("a NON-CONFORMING platform code is still recorded as the closed E_OTHER placeholder", nonConforming.platformCode === EMAIL_PLATFORM_CODE_OTHER);
  ok("it is still coded email-platform-rejected", nonConforming.code === "email-platform-rejected");
  scanClean("the delivery result for a NON-CONFORMING platform code", nonConforming);

  // The placeholder is spelled to CONFORM to the shape gate, so it survives every re-gate on the way to the
  // pack (the DO's record path and the pack projection both re-run sanitiseEmailPlatformCode). If this ever
  // regressed, the placeholder would be silently dropped and the gap would quietly re-open.
  ok("E_OTHER survives the shape gate the DO and the pack re-apply", sanitiseEmailPlatformCode(EMAIL_PLATFORM_CODE_OTHER) === EMAIL_PLATFORM_CODE_OTHER);
  ok("a platform that sent NO code records no platformCode at all (absence stays honest)", emailPlatformCodeOf(undefined) === undefined && emailPlatformCodeOf("") === undefined);

  // --- the OTHER durable sink: the operational LOG -----------------------------------------------------------
  // The customer's Workers Logs are durable too, and sendEmail used to write the platform's code there RAW.
  // Nothing bounds that string: a chatty platform puts a whole sentence in it, carrying the recipient address
  // or an internal host. The log now carries the shape-gated token (or the E_OTHER placeholder) only.
  const lines: string[] = [];
  const realError = console.error;
  console.error = (...args: unknown[]) => void lines.push(args.map(String).join(" "));
  await emailDeliver(emailEnv(`rejected: ${RECIPIENT} via ${CUSTOMER_VALUE} (${SECRET})`), CHANNEL, EMISSION);
  await emailDeliver(emailEnv("E_SENDER_NOT_VERIFIED"), CHANNEL, EMISSION);
  console.error = realError;
  ok("the log still names the fault (it is not silenced)", lines.some((l) => l.includes("sendEmail failed")));
  ok("the log carries the E_OTHER placeholder for a non-conforming code", lines.some((l) => l.includes(EMAIL_PLATFORM_CODE_OTHER)));
  ok("the log carries a CONFORMING code verbatim (the onboarding diagnostic survives)", lines.some((l) => l.includes("E_SENDER_NOT_VERIFIED")));
  scanClean("the operational log lines", lines);

  // --- the DURABLE record: the DO's own notify history, which is what the pack projects ---------------------
  const { storage, stub } = makeScheduler();
  const rec = await stub.recordNotify({
    emission: EMISSION,
    records: [{ channelId: CHANNEL.id, channelKind: "email", delivered: false, code: nonConforming.code, platformCode: nonConforming.platformCode }],
  });
  ok("the DO accepted the outcome (the new code passes its closed-set gate)", rec.recorded === 1 && rec.skipped === 0);
  const entry = storage.rawListKeys().filter((k) => k.startsWith("notify-history:")).map((k) => storage.rawGet<{ deliveryCode?: string; platformCode?: string }>(k))[0];
  ok("the persisted history entry carries the closed deliveryCode", entry?.deliveryCode === "email-platform-rejected");
  ok("the persisted history entry carries the E_OTHER placeholder (the code is no longer dropped)", entry?.platformCode === EMAIL_PLATFORM_CODE_OTHER);
  scanClean("the DO's persisted notify-history entry", entry);
}

await g224();
await g236();

console.log(failures === 0 ? "\nnotify/root fault evidence: OK" : `\nnotify/root fault evidence: ${failures} FAILED`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
