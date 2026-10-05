// The replication pass's per-target fault reason: the typed fault a site throws, and the read of the closed
// reason off whatever reached the pass's per-target catch. Kept beside replicate.ts so that file stays within
// its line budget.
//
// The reason is set at the site that knows it, never parsed out of a message. Two sites besides the explicit
// throws have their own reason:
//   - a RUNLOG the engine refuses to modify (RunlogIntegrityError: no valid signature, a chain anomaly, a
//     rollback below the floor, or a body that does not parse) is runlog-corrupt. An Owner repairs it through
//     the attended route; a retry never clears it, so it must not read as unreachable;
//   - an object copy (a seg/ segment or a run-tree object) that throws is copy-failed. The target's RUNLOG
//     was read this pass, so the target answered; the copy is what failed.

import { RunlogIntegrityError } from "./pipeline.ts";
import { REPLICA_FAULT_REASONS, type ReplicaFaultReason } from "./seal-faults.ts";

/**
 * ReplicaFaultError tags a per-target fault with its closed reason at the site that knows it. The original
 * error rides as the message for the Workers Logs line only; the reason is the only thing recorded.
 */
export class ReplicaFaultError extends Error {
  readonly replicaReason: ReplicaFaultReason;
  constructor(reason: ReplicaFaultReason, message: string) {
    super(message);
    this.name = "ReplicaFaultError";
    this.replicaReason = reason;
  }
}

const REPLICA_REASONS: readonly ReplicaFaultReason[] = REPLICA_FAULT_REASONS;

/**
 * replicaReasonOf reads the closed reason off a fault that reached the per-target catch. An untagged throw is
 * unreachable (the honest default for a transport or HTTP fault). It never reads an untagged error's message.
 *
 * @param e - the thrown value.
 * @returns the closed reason.
 */
export function replicaReasonOf(e: unknown): ReplicaFaultReason {
  if (e instanceof RunlogIntegrityError) return "runlog-corrupt";
  const r = (e as { replicaReason?: unknown } | null)?.replicaReason;
  return typeof r === "string" && (REPLICA_REASONS as readonly string[]).includes(r) ? (r as ReplicaFaultReason) : "unreachable";
}

/**
 * copyStep runs one object copy step (a get from the source or a put to the target) and tags a throw
 * copy-failed. A fault that already carries a reason keeps it.
 *
 * @param key - the object key, for the log line.
 * @param step - the get or put.
 * @returns what the step returned.
 */
export async function copyStep<T>(key: string, step: () => Promise<T>): Promise<T> {
  try {
    return await step();
  } catch (e) {
    if (e instanceof ReplicaFaultError || e instanceof RunlogIntegrityError) throw e;
    throw new ReplicaFaultError("copy-failed", `replica copy of ${key} failed: ${e instanceof Error ? e.message : String(e)}`);
  }
}
