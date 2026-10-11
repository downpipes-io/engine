// Support-pack facts for the recovery section: what the Owner must still do after a recovery, and which
// imported destinations cannot be used yet. Closed facts only: an enum, a count and destination ids. No
// credential, key, envelope byte, URL or error text is read into the result.

import { doURL } from "../do-url.ts";
import { canOpenConfigSecret, isWrappedSecret, loadConfigWrapKey } from "./config-secret.ts";

/** The actions the pack can say an Owner still has to do. Closed: nothing outside this set is emitted. */
export const PENDING_OWNER_ACTIONS = ["resign-runlog", "reenter-destination-keys"] as const;
export type PendingOwnerAction = (typeof PENDING_OWNER_ACTIONS)[number];

const UNREADABLE_IDS_CAP = 64;
const ID_MAX = 128;

export interface DestinationsUnreadable {
  count: number;
  ids: string[];
}

/**
 * destinationsUnreadable names the destinations whose credential cannot be used with the configured wrap key:
 * a credential the export left out, or an envelope the key does not open (a key that is missing, malformed or
 * different from the one that wrapped it). It opens each envelope for a verdict only; no plaintext is held.
 *
 * @param scheduler - the scheduler DO stub, read through its no-custody export.
 * @param wrapKeyRaw - the configured CONFIG_WRAP_KEY text, or undefined when none is set.
 * @returns the count and the first ids, or null when the destinations could not be read.
 */
export async function destinationsUnreadable(scheduler: DurableObjectStub, wrapKeyRaw: string | undefined): Promise<DestinationsUnreadable | null> {
  const r = await scheduler.fetch(doURL("/control-plane/export"), { method: "GET" });
  if (!r.ok) return null;
  const j = (await r.json()) as { destinations?: unknown };
  if (!Array.isArray(j.destinations)) return null;
  let key: Uint8Array | undefined;
  let keyUsable = true;
  try {
    key = loadConfigWrapKey(wrapKeyRaw);
  } catch {
    // site-fault-waiver: src/admin/support-recovery-owner-actions.ts:destinationsUnreadable:catch:1 -- a malformed wrap key is a fact the pack reports, since it makes every wrapped credential unreadable here, and the key health section already records the malformed-key class
    keyUsable = false;
  }
  const ids: string[] = [];
  let count = 0;
  for (const d of j.destinations as Array<{ id?: unknown; secret?: unknown }>) {
    const secret = typeof d.secret === "object" && d.secret !== null ? (d.secret as { wrapped?: unknown }) : null;
    const wrapped = secret !== null && isWrappedSecret(secret.wrapped) ? secret.wrapped : null;
    const unreadable = wrapped === null || !keyUsable || key === undefined || !(await canOpenConfigSecret(key, wrapped));
    if (!unreadable) continue;
    count++;
    if (typeof d.id === "string" && ids.length < UNREADABLE_IDS_CAP) ids.push(d.id.slice(0, ID_MAX));
  }
  return { count, ids };
}

/**
 * pendingOwnerActions lists what the engine knows the Owner still has to do: re-sign the RUNLOG when the
 * bucket's RUNLOG has no signature, and re-enter destination keys when an imported destination is unreadable.
 *
 * @param noSeed - the closed reason the RUNLOG read gave no seed, when it gave none.
 * @param unreadableCount - the imported destinations that cannot be used, when an import ran.
 * @returns the actions, in a fixed order; empty when none is pending.
 */
export function pendingOwnerActions(noSeed: string | undefined, unreadableCount: number): PendingOwnerAction[] {
  const out: PendingOwnerAction[] = [];
  if (noSeed === "sig-absent") out.push("resign-runlog");
  if (unreadableCount > 0) out.push("reenter-destination-keys");
  return out;
}
