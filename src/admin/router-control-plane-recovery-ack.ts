// The ACKNOWLEDGE-ONLY control-plane recovery latch clear: /control-plane/restore and /control-plane/apply-
// staged (router-identity.ts) both refuse forever once a latched plane organically un-empties, because both
// require an EMPTY plane AND an empty role table. This route is the narrow escape: gated on access.policy
// (never the bare break-glass token -- an owner who can authenticate at all means the role table is already
// non-empty, so there is always a real owner to ask), it forwards to the DO's acknowledgeControlPlaneRecovery
// (scheduler-do-control-plane.ts), which clears ONLY the latch fields, never imports, never touches
// bootstrapConsumed, and independently refuses over an empty role table -- see that method's own comment for
// the full rationale and the rejected alternatives (a dual-control reconcile-over-live route; an export-
// equality check; an unconditional clear, which risks the silent G061 empty-table/spent-bootstrap deadlock).

// This route is wired to the console's recovery banner: the refusal carries a CLOSED refusalClass, so the
// console codes the branch by set membership rather than classifying a sentence it does not own, and the two
// refusals reach different stable codes on screen. The refusal is also RECORDED on its own surface, so a
// customer who cannot clear their own banner leaves a durable trace instead of a screenshot. The DO remains
// the enforcement point and re-asserts both guards itself.

import { recordRecoveryRefusal } from "./diag-counters.ts";
import type { RecoveryRefusalClass } from "./diag-records.ts";
import { callerHeaders, gate, jsonRefusal } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";

// classifyAckRefusal reads the DO's own refusal to its closed class. It matches on the two SUBSTRINGS this
// repo owns on both sides (the DO throws them in acknowledgeControlPlaneRecovery, a few lines apart, and both
// are pinned by the guard-mutation spec beside this file), and it falls back to the deadlock class ONLY when
// it recognises the deadlock wording. Anything unrecognised is the benign no-latch class rather than a
// fabricated deadlock, because inventing the scarier of two diagnoses from an unmatched string is how a
// classifier over prose earns its bad name.
function classifyAckRefusal(detail: string): RecoveryRefusalClass {
  if (detail.includes("the role table is empty")) return "ack-role-table-empty";
  return "ack-no-latch";
}

export async function handleControlPlaneRecoveryAck(ctx: RouterCtx): Promise<Response | null> {
  const { req, caller, scheduler, sub } = ctx;
  if (`${req.method} ${sub}` !== "POST /control-plane/acknowledge-recovery") return null;
  const denied = gate(caller, "access.policy");
  if (denied) return denied;
  const resp = await scheduler.fetch(doURL("/control-plane/acknowledge-recovery"), { method: "POST", headers: callerHeaders(caller) });
  if (!resp.ok) {
    const detail = await resp.text();
    const cls = resp.status === 403 ? "reconcile-refused" : classifyAckRefusal(detail);
    await recordRecoveryRefusal(scheduler, { surface: "acknowledge", cls });
    return jsonRefusal(`could not acknowledge the control-plane recovery: ${detail.slice(0, 300)}`, resp.status === 403 ? 403 : 400, cls);
  }
  return new Response(resp.body, { status: resp.status, headers: { "content-type": "application/json" } });
}
