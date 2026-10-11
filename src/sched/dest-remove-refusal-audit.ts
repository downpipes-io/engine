// dest-remove-refusal-audit.ts -- the scheduler's own audit row for a destination clear or remove that its guards
// REFUSED, with the facts that blocked it. The scheduler holds those facts at the moment of refusal (the removal
// scan: the downpipes that name the destination, and the runs whose only proven copy is there), so the row is
// written here and not by the router, which sees only the 400.
//
// The row is a failed dest-config-cleared row on the same dest-change target the refused save uses. It adds, to
// the closed refusal class and the destination id: the count of pinned downpipes, their ids (the ids the pack
// already carries for runs), and the count of runs that would lose their only proven copy. It carries no
// downpipe name, bucket, endpoint or sentence. The same per-class gate caps the rows a retry loop can write.

import type { AuditDraft, AuditEvent } from "../admin/audit.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { admitDestRefusalRow, DEST_REFUSAL_GATE_KEY, type DestRefusalGateState } from "./dest-refusal-gate.ts";

/** The refusals this row records: the singular clear of the default, and the plural remove. */
export type DestBlockerRefusal = "clear-in-use" | "clear-orphan-guard" | "remove-in-use" | "remove-orphan-guard";

/** The most downpipe ids one row lists; the count still states the whole. */
export const DEST_BLOCKER_IDS_CAP = 10;

const ID_SLUG = /^[A-Za-z0-9_-]{1,64}$/;

type DestChangeTarget = Extract<AuditDraft["target"], { kind: "dest-change" }>;

export interface DestBlockerFacts {
  refusal: DestBlockerRefusal;
  /** The destination the clear or remove targeted. */
  destinationId: string;
  /** The ids of the downpipes that name the destination, as primary or replica. */
  pinnedDownpipeIds: readonly string[];
  /** The runs whose only proven copy is the destination. */
  atRiskRunCount: number;
  /** The plural remove only: whether the request carried force. */
  forced?: boolean;
}

export interface DestBlockerCaller {
  method: AuthMethod;
  email: string | null;
  sourceIp?: string | null;
}

/**
 * destBlockerTarget builds the closed dest-change target for one refusal.
 *
 * @param facts - what blocked the clear or remove.
 * @returns the audit target: counts, closed classes and ids only.
 */
export function destBlockerTarget(facts: DestBlockerFacts): DestChangeTarget {
  const ids = [...facts.pinnedDownpipeIds].map((x) => (ID_SLUG.test(x) ? x : "unminted")).sort();
  return {
    kind: "dest-change",
    op: facts.refusal.startsWith("remove-") ? "remove" : "clear",
    refusal: facts.refusal,
    id: facts.destinationId,
    pinnedDownpipeCount: facts.pinnedDownpipeIds.length,
    ...(ids.length > 0 ? { pinnedDownpipeIds: ids.slice(0, DEST_BLOCKER_IDS_CAP) } : {}),
    atRiskRunCount: Math.max(0, Math.floor(facts.atRiskRunCount)),
    ...(facts.forced !== undefined ? { force: facts.forced } : {}),
  };
}

/**
 * appendDestBlockerRefusalAudit writes the failed dest-config-cleared row for one refused clear or remove, when
 * the per-class gate admits it.
 *
 * @param storage - the scheduler's storage (the gate state lives in it).
 * @param append - the scheduler's audit append.
 * @param caller - who asked.
 * @param facts - what blocked the request.
 * @param now - the clock, in milliseconds.
 * @returns whether a row was written.
 */
export async function appendDestBlockerRefusalAudit(
  storage: { get<T>(key: string): Promise<T | undefined>; put(key: string, value: unknown): Promise<void> },
  append: (draft: AuditDraft) => Promise<AuditEvent>,
  caller: DestBlockerCaller | null,
  facts: DestBlockerFacts,
  now: number,
): Promise<{ recorded: boolean }> {
  const verdict = admitDestRefusalRow(await storage.get<DestRefusalGateState>(DEST_REFUSAL_GATE_KEY), facts.refusal, now);
  await storage.put(DEST_REFUSAL_GATE_KEY, verdict.state);
  if (!verdict.admit) return { recorded: false };
  await append({
    actorEmail: caller?.email ? caller.email : null,
    actorMethod: caller ? caller.method : "access",
    sourceIp: caller?.sourceIp ?? null,
    action: "dest-config-cleared",
    outcome: "failed",
    target: destBlockerTarget(facts),
  });
  return { recorded: true };
}
