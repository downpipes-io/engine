// The CHECKED best-effort writers for the four ADMIN fault aggregates: unwrap faults, binding-safety alarms,
// update-pipeline faults, and admin refusals. Siblings of admin/diag-counters.ts (the admin counters), admin/restore-faults.ts
// (the restore ring) and admin/auth-signals.ts (the auth aggregate), and written to exactly the same contract:
//
//   - the closed vocabularies + the pure appliers live in the LEAF (admin/diag-records.ts), so the Worker edge,
//     the DO recorder and the pack projector agree on ONE vocabulary with no import cycle;
//   - every write goes through recordDiagWrite, so a DROPPED diagnostic write is itself counted in the
//     droppedWrites aggregate rather than vanishing (the audit's meta-finding: absence of evidence must never
//     read as absence of problems);
//   - nothing here ever throws, and nothing here ever changes the caller's path: the response the operator sees
//     was decided before the observation was made.
//
// NO-CUSTODY: the only things that cross the wire are closed enum members, clamped integers, Cloudflare's OWN
// integer error codes, the sha384 of a PUBLIC release artefact, and the operator's own binding labels (the
// sourcesDetached class the pack already ships). Never an error message, a stack, a secret, a token, a key, a
// URL, an endpoint, a bucket, an object key, a header or a customer value. The appliers in the leaf re-validate
// every field DO-side, so even a drifted call site cannot land free text in a record.

import type { AdminRefusalReason, AdminRefusalSurface, BindingAlarmKind, UnwrapFaultCause, UpdateFaultRow } from "./diag-records.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { doURL } from "../do-url.ts";

/**
 * recordUnwrapFault (G028) records ONE destination-credential unwrap failure at the moment of use, so the pack
 * carries a first-failure TIMESTAMP -- the fact the probe-time wrapKeyHealth verdict structurally cannot
 * recover ("your key does not open the envelope" says nothing about when that started, and a rotated key, a
 * corrupt DO record and a dropped env binding all look the same in the run rows).
 *
 * @param scheduler - the scheduler DO stub.
 * @param cause - the closed cause the throw site tagged.
 */
export async function recordUnwrapFault(scheduler: DurableObjectStub, cause: UnwrapFaultCause): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "admin-counter", () =>
      scheduler.fetch(doURL("/diag/unwrap-fault"), {
        method: "POST",
        body: JSON.stringify({ cause }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: observing a failed unwrap must never mask the failure it observed */
  }
}

/**
 * recordBindingAlarm (G099) records ONE post-write binding-safety alarm. The alarm itself is UNCHANGED: the
 * attach pipeline still throws, still refuses, and still tells the operator exactly what happened. This only
 * makes the alarm survive the browser tab it was shown in.
 *
 * @param scheduler - the scheduler DO stub.
 * @param kind - the closed alarm kind.
 * @param bindingNames - the operator's own binding labels (capped + clamped by the DO-side applier).
 */
export async function recordBindingAlarm(scheduler: DurableObjectStub, kind: BindingAlarmKind, bindingNames: string[]): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "admin-counter", () =>
      scheduler.fetch(doURL("/diag/binding-alarm"), {
        method: "POST",
        body: JSON.stringify({ row: { kind, bindingNames } }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort */
  }
}

/**
 * recordUpdateFaults (G050/G054/G101/G159/G162) records the already-classified rows of ONE update-pipeline
 * failure. A CLEAN update records nothing at all (the healthy steady state costs no subrequest).
 *
 * @param scheduler - the scheduler DO stub.
 * @param rows - the classified rows (the DO stamps `at` and re-validates every field).
 */
export async function recordUpdateFaults(scheduler: DurableObjectStub, rows: Array<Omit<UpdateFaultRow, "at">>): Promise<void> {
  if (rows.length === 0) return;
  try {
    await recordDiagWrite(scheduler, "update-settled", () =>
      scheduler.fetch(doURL("/diag/update-faults"), {
        method: "POST",
        body: JSON.stringify({ rows }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: the update's own outcome is already decided */
  }
}

/**
 * recordUpdateFault is the single-row convenience form.
 *
 * @param scheduler - the scheduler DO stub.
 * @param row - the classified row.
 */
export async function recordUpdateFault(scheduler: DurableObjectStub, row: Omit<UpdateFaultRow, "at">): Promise<void> {
  await recordUpdateFaults(scheduler, [row]);
}

/**
 * recordAdminRefusal (G245) records ONE refused admin write as a closed (surface, reason) pair. The refusal
 * RESPONSE is unchanged in every case -- including the fail-closed ones -- so nothing here is oracled back to
 * the caller; the split exists pack-side only.
 *
 * @param scheduler - the scheduler DO stub.
 * @param surface - the closed surface that refused.
 * @param reason - the closed reason class.
 */
export async function recordAdminRefusal(scheduler: DurableObjectStub, surface: AdminRefusalSurface, reason: AdminRefusalReason): Promise<void> {
  try {
    await recordDiagWrite(scheduler, "admin-counter", () =>
      scheduler.fetch(doURL("/diag/admin-refusal"), {
        method: "POST",
        body: JSON.stringify({ surface, reason }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort */
  }
}

// ---------------------------------------------------------------------------------------------------------
// THE GOVERNANCE / PEOPLE / NOTIFY WRITES, RECORDED AT THE HUB
//
// The gap lists nineteen call sites across seven spokes and asks that a refused save stop dying in a dismissed
// toast. Recording at nineteen sites would work exactly until the twentieth route was added, so it is recorded
// at the ONE seam every admin write's answer already passes through: the hub's dispatch loop (router.ts).
//
// WHY THE ENGINE AND NOT THE CONSOLE. The console DOES record a refused write, and its row is sound as far as it
// goes -- it is the only evidence of a write the engine never saw at all. But its ring is in-memory with
// deliberately no sessionStorage and is reset on every pack download, while this ticket is time-displaced BY
// CONSTRUCTION: "I turned dual control on LAST WEEK." A refusal from a prior session, or from before a reload,
// is gone. Three states therefore produced an identical pack -- refused last week, never attempted, applied and
// later turned off -- and the engine is the only side that can remember across a session boundary.
//
// NO-CUSTODY. The surface is a compile-time constant looked up from the frozen table below by route TEMPLATE
// (never by a request value); the reason is a total map from an integer status. The response body, the headers
// and the engine's own refusal prose -- which on these routes can carry a channel URL, a role name or the
// operator's change reference -- are never read.
// ---------------------------------------------------------------------------------------------------------

// ADMIN_WRITE_SURFACES maps a route TEMPLATE ("<METHOD> <sub>") to the closed surface it refuses under. The op
// rides in the surface name wherever the remedy differs: a failed notify-channel CREATE and a failed notify-channel
// DELETE are different tickets, and folding them into one key would recreate, inside the fix, the coalescing this
// gap exists to end.
const ADMIN_WRITE_SURFACES: Readonly<Record<string, AdminRefusalSurface>> = {
  // G245: THE KEY CEREMONY. "The key install failed halfway" is in the gap's own list of tickets and the two
  // surfaces for it were declared and never wired: every refusal on these three routes -- a one-shot scoped
  // token that will not mint, a posture the engine will not switch, a refused Cloudflare secret write -- was a
  // 4xx into a browser and nothing else, and the key ceremony is the one surface where "I tried three times
  // last week and gave up" ends with an account that cannot decrypt its own archives. They belong in the
  // FROZEN TABLE like every other admin write: the hub already sees them (handleKeys returns through the same
  // dispatch loop), so nothing but the row was missing. break-glass-only is the POSTURE SWITCH, which the
  // key-rotate surface names explicitly ("rotating a key, or the break-glass posture switch").
  "POST /keys/install": "key-install",
  "POST /keys/rotate": "key-rotate",
  "POST /keys/break-glass-only": "key-rotate",
  "POST /config/approval-policy": "approval-policy",
  "POST /config/change-number-policy": "change-number-policy",
  "POST /config/signin-context-policy": "signin-context-policy",
  "POST /notify/channels": "notify-channel-set",
  "POST /notify/channels/delete": "notify-channel-delete",
  "POST /notify/rules": "notify-rule-set",
  "POST /notify/rules/delete": "notify-rule-delete",
  "POST /expiry": "expiry-item-set",
  "POST /expiry/delete": "expiry-item-delete",
  "POST /custom-roles": "custom-role-create",
  "POST /custom-roles/delete": "custom-role-delete",
  "POST /posture/accept": "posture-accept",
  "POST /posture/unaccept": "posture-unaccept",
  "POST /auth/recovery-codes/regenerate": "recovery-codes-regenerate",
  "POST /policy/retire-break-glass-token": "break-glass-retire",
};

/**
 * adminRefusalReasonForStatus is the TOTAL, PURE map from ONE integer HTTP status to a closed refusal reason.
 * It reads a number. There is no branch in it that can be reached by a string.
 *
 * A 401 is deliberately NOT recorded by the caller below (it is the step-up ceremony's opening handshake, not a
 * refusal), so it never arrives here.
 *
 * @param status - the response status the route answered with.
 * @returns the closed reason.
 */
export function adminRefusalReasonForStatus(status: number): AdminRefusalReason {
  if (status === 403) return "forbidden";
  if (status === 409 || status === 412) return "conflict";
  if (status === 429) return "rate-limited";
  if (status >= 500) return "do-fault";
  if (status === 400 || status === 404 || status === 422) return "validation";
  return "other";
}

/**
 * noteAdminWriteRefusal records ONE refused governance / people / notify write, from the hub, by route template.
 *
 * NOISE DISCIPLINE, and it is the whole reason this is not simply "every non-2xx":
 *   - a 2xx records NOTHING. A save that worked is not a fault, and a row for it would drown the ones that are.
 *   - a 401 records NOTHING. On a gatedFetch route the 401 { stepUpRequired } is the OPENING MOVE of a
 *     successful step-up ceremony, not a refusal. Recording it would file every dual-controlled save that then
 *     SUCCEEDED as a permissions denial -- the exact phantom-auth-fault trap the console's own recorder defers
 *     around, and a far worse place to fall into it.
 *   - a route not in the frozen table records nothing.
 *
 * Never throws and never alters the response, which was decided before it was observed.
 *
 * @param scheduler - the scheduler DO stub.
 * @param method - the request method.
 * @param sub - the /admin-relative path.
 * @param status - the status the route answered with.
 */
export async function noteAdminWriteRefusal(scheduler: DurableObjectStub, method: string, sub: string, status: number): Promise<void> {
  if (status < 400 || status === 401) return;
  const surface = ADMIN_WRITE_SURFACES[`${method} ${sub}`];
  if (surface === undefined) return;
  await recordAdminRefusal(scheduler, surface, adminRefusalReasonForStatus(status));
}
