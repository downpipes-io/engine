// The engine version stamp on stored diagnostic records, and the stale mark the support pack derives from it.
//
// The scheduler stamps ENGINE_VERSION on each seal-fault ring row, each span and each per-destination
// replication state when it writes them. A record written before the stamp existed has no version and reads as
// absent. The pack compares the stored version with the running one at read time; stale is never stored.

import { ENGINE_VERSION } from "./version.ts";

const ENGINE_VERSION_MAX = 32;
const ENGINE_VERSION_SHAPE = /^\d{1,9}\.\d{1,9}\.\d{1,9}$/;

/**
 * cleanEngineVersion gates a stored version string: at most 32 characters in the plain X.Y.Z shape.
 *
 * @param v - the stored value, of any type.
 * @returns the version, or undefined when the value is missing or malformed.
 */
export function cleanEngineVersion(v: unknown): string | undefined {
  return typeof v === "string" && v.length <= ENGINE_VERSION_MAX && ENGINE_VERSION_SHAPE.test(v) ? v : undefined;
}

/**
 * stampFields projects a stored version onto a pack row: the clean version under `key` when it holds one, and
 * stale: true when that version is not the running engine version or is missing. A current row gets no stale key.
 *
 * @param stored - the version held on the stored record.
 * @param key - the pack key that carries the version.
 * @returns the fields to spread into the projected row.
 */
export function stampFields(stored: unknown, key: "engineVersion" | "lastEngineVersion"): Record<string, unknown> {
  const v = cleanEngineVersion(stored);
  return { ...(v !== undefined ? { [key]: v } : {}), ...(v !== ENGINE_VERSION ? { stale: true } : {}) };
}
