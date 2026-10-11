// dest-refusal-audit.ts -- the scheduler's write of the audit row for a REFUSED destination save or clear
// (POST /diag/dest-refusal-audit). The router sends the actor and a closed detail; this re-validates the detail
// (sanitiseDestRefusal), so a drifted caller cannot land free text on the chain, and caps the rows a retry loop can
// write (dest-refusal-gate.ts: one per refusal class a minute, DEST_REFUSAL_ROWS_PER_HOUR an hour). The attempts
// the gate does not admit are still counted by the admin-refusal aggregate the router writes beside this row.

import type { AuditActorMethod, AuditDraft, AuditEvent } from "../admin/audit.ts";
import { sanitiseDestRefusal } from "../admin/dest-save-refusal.ts";
import { admitDestRefusalRow, DEST_REFUSAL_GATE_KEY, type DestRefusalGateState } from "./dest-refusal-gate.ts";

export interface DestRefusalAuditBody {
  actorSubject?: unknown;
  actorEmail?: unknown;
  actorMethod?: unknown;
  sourceIp?: unknown;
  detail?: unknown;
}

/**
 * appendDestRefusalAudit writes the failed dest-config-set or dest-config-cleared row for one refusal, when the gate
 * admits it.
 *
 * @param storage - the scheduler's storage (the gate state lives in it).
 * @param append - the scheduler's audit append.
 * @param body - the router's request body (untrusted shape).
 * @param now - the clock, in milliseconds.
 * @returns whether a row was written.
 */
export async function appendDestRefusalAudit(
  storage: { get<T>(key: string): Promise<T | undefined>; put(key: string, value: unknown): Promise<void> },
  append: (draft: AuditDraft) => Promise<AuditEvent>,
  body: DestRefusalAuditBody,
  now: number,
): Promise<{ recorded: boolean }> {
  const detail = sanitiseDestRefusal(body.detail);
  if (detail === null) return { recorded: false };
  const verdict = admitDestRefusalRow(await storage.get<DestRefusalGateState>(DEST_REFUSAL_GATE_KEY), detail.refusal, now);
  await storage.put(DEST_REFUSAL_GATE_KEY, verdict.state);
  if (!verdict.admit) return { recorded: false };
  await append({
    actorSubject: typeof body.actorSubject === "string" ? body.actorSubject : null,
    actorEmail: typeof body.actorEmail === "string" ? body.actorEmail : null,
    actorMethod: (typeof body.actorMethod === "string" ? body.actorMethod : "token") as AuditActorMethod,
    sourceIp: typeof body.sourceIp === "string" ? body.sourceIp : null,
    action: detail.op === "clear" ? "dest-config-cleared" : "dest-config-set",
    outcome: "failed",
    target: {
      kind: "dest-change",
      op: detail.op,
      refusal: detail.refusal,
      ...(detail.id !== undefined ? { id: detail.id } : {}),
      ...(detail.provider !== undefined ? { provider: detail.provider } : {}),
      ...(detail.probeClass !== undefined ? { probeClass: detail.probeClass } : {}),
      ...(detail.probeStatus !== undefined ? { probeStatus: detail.probeStatus } : {}),
      ...(detail.regionHint !== undefined ? { regionHint: detail.regionHint } : {}),
    },
  });
  return { recorded: true };
}
