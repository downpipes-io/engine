// The seal-fault ring writer: the storage half of the scheduler DO's recordSealFault. It stamps the writing
// engine version on a sanitised fault, appends it to the bounded ring and folds it into the per-reason span.
// Kept apart from ./scheduler-do-observability.ts so the DO mixin holds only the sanitise and drop decision.

import { ENGINE_VERSION } from "../format/version.ts";
import type { SealFault } from "../seal/seal-faults.ts";
import { foldSealFaultSpan, SEAL_FAULT_SPANS_KEY, type SealFaultSpans } from "../seal/seal-fault-spans.ts";

// The seal-fault observation ring (support-pack seal-integrity modes shard-list-truncated /
// shard-truncation-stalekeys / lease-lost-abandon / orphan-root-worm-leak / signer-rotation-strands-runs)
// lives under ONE key as a newest-last SealFault[] bounded to the freshest SEAL_FAULT_MAX. Like the
// reconcile signal it is pure diagnostic REFERENCE data (a closed kind + the customer's own ids + ints /
// a boolean), structurally distinct from every dp:/hist:/repl:/signal:reconcile key and never read by any
// seal / restore path. Bounded so a pathological run of faults cannot grow it unbounded.
export const SEAL_FAULT_KEY = "signal:seal-faults";
const SEAL_FAULT_MAX = 64;

/**
 * storeSealFault appends one sanitised seal fault to the bounded ring under SEAL_FAULT_KEY and folds it into
 * the span record under SEAL_FAULT_SPANS_KEY. The fault must already have passed sanitiseSealFault.
 */
export async function storeSealFault(storage: DurableObjectStorage, sanitised: Omit<SealFault, "engineVersion">): Promise<void> {
  // The writing engine version rides on the row and its span so the pack can mark a row from another version stale.
  const fault: SealFault = { ...sanitised, engineVersion: ENGINE_VERSION };
  const ring = (await storage.get<SealFault[]>(SEAL_FAULT_KEY)) ?? [];
  ring.push(fault);
  // Keep only the freshest SEAL_FAULT_MAX (drop the oldest head): the ring is newest-last.
  const bounded = ring.length > SEAL_FAULT_MAX ? ring.slice(ring.length - SEAL_FAULT_MAX) : ring;
  await storage.put(SEAL_FAULT_KEY, bounded);
  // The ring forgets the START of a fault within a day; the span beside it keeps first and last seen per reason.
  await storage.put(SEAL_FAULT_SPANS_KEY, foldSealFaultSpan(await storage.get<SealFaultSpans>(SEAL_FAULT_SPANS_KEY), fault));
}
