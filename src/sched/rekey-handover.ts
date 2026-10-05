// The RUNLOG hand-over of a signer re-key, as the scheduler DO keeps it.
//
// WHAT IT IS. A re-key replaces SIGNER_PRIVATE. Each destination's _RECOVERY/RUNLOG is signed under the OLD
// key, and the engine refuses to modify a RUNLOG it cannot verify under its own key. So the re-key route hands
// each RUNLOG over: it verifies the stored bytes under the old public key and signs the same bytes under the
// new key (admin/rekey-runlog-handover.ts). A destination it cannot hand over in that request (a seal on the
// old Worker version wrote to it late, or it could not be read) stays PENDING.
//
// WHAT IT HOLDS. The OLD PUBLIC KEY only (the two public halves, never a private key or a seed), the time the
// re-key began, the pending destination ids, and holdUntil: run allocation is held until then, so new seals do
// not start while the secrets roll out. A pending destination can later be verified under the held key and
// handed over by the attended route. When no destination is pending the record is deleted, and the caller
// records that the held key was discarded.

import { noteSiteFault } from "../admin/site-faults.ts";
import { b64urlDecode, b64urlEncode } from "../crypto/bytes.ts";
import type { HybridVerifier } from "../crypto/sign.ts";

const REKEY_HANDOVER_KEY = "rekeyRunlogHandover";
// How long a re-key holds new run allocations: long enough for the secret writes to roll out a new Worker
// version, short enough that a re-key request that died mid-way does not hold backups for long.
export const REKEY_HOLD_MS = 15 * 60 * 1000;
const PENDING_MAX = 256;

export interface RekeyHandoverRecord {
  oldVerifier: { ed: string; mldsa: string }; // b64url public halves of the outgoing signer
  startedAt: number;
  holdUntil: number; // epoch ms; 0 once the hand-over pass has run
  pending: string[]; // destination ids not yet handed over ("" = the env-backed destination)
}

interface HandoverStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
}

function isRecord(v: unknown): v is RekeyHandoverRecord {
  if (typeof v !== "object" || v === null) return false;
  const r = v as Partial<RekeyHandoverRecord>;
  return typeof r.oldVerifier?.ed === "string" && typeof r.oldVerifier.mldsa === "string" && typeof r.startedAt === "number" && typeof r.holdUntil === "number" && Array.isArray(r.pending);
}

/** encodeVerifier turns a verifier into the stored public form. */
export function encodeVerifier(v: HybridVerifier): { ed: string; mldsa: string } {
  return { ed: b64urlEncode(v.ed), mldsa: b64urlEncode(v.mldsa) };
}

/** decodeVerifier turns the stored public form back into a verifier, or null when it does not decode. */
export function decodeVerifier(v: unknown): HybridVerifier | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as { ed?: unknown; mldsa?: unknown };
  if (typeof o.ed !== "string" || typeof o.mldsa !== "string") return null;
  try {
    const ed = b64urlDecode(o.ed);
    const mldsa = b64urlDecode(o.mldsa);
    return ed.length === 32 && mldsa.length === 2592 ? { ed, mldsa } : null;
  } catch (e) {
    noteSiteFault("rekey.verifier-decode", e);
    return null;
  }
}

/** readRekeyHandover returns the held record, or null when no hand-over is open. */
export async function readRekeyHandover(storage: HandoverStorage): Promise<RekeyHandoverRecord | null> {
  const r = await storage.get<unknown>(REKEY_HANDOVER_KEY);
  return isRecord(r) ? r : null;
}

/**
 * beginRekeyHandover opens a hand-over: it holds the old public key and holds run allocation until
 * now + REKEY_HOLD_MS. An open record from an earlier re-key keeps its pending ids, because those RUNLOGs are
 * still signed under the key it holds. A second re-key over an unfinished one is refused by the caller.
 */
export async function beginRekeyHandover(storage: HandoverStorage, oldVerifier: { ed: string; mldsa: string }, now: number): Promise<void> {
  await storage.put(REKEY_HANDOVER_KEY, { oldVerifier, startedAt: now, holdUntil: now + REKEY_HOLD_MS, pending: [] } satisfies RekeyHandoverRecord);
}

/**
 * settleRekeyHandover records the outcome of a hand-over pass. With no pending destination it deletes the
 * record (the held public key is discarded) and returns discarded:true. Otherwise it keeps the key and the
 * pending ids, and ends the allocation hold.
 */
export async function settleRekeyHandover(storage: HandoverStorage, pending: readonly string[]): Promise<{ discarded: boolean; pending: string[] }> {
  const rec = await readRekeyHandover(storage);
  if (rec === null) return { discarded: false, pending: [] };
  const ids = [...new Set(pending.filter((p) => typeof p === "string"))].slice(0, PENDING_MAX);
  if (ids.length === 0) {
    await storage.delete(REKEY_HANDOVER_KEY);
    return { discarded: true, pending: [] };
  }
  await storage.put(REKEY_HANDOVER_KEY, { ...rec, holdUntil: 0, pending: ids } satisfies RekeyHandoverRecord);
  return { discarded: false, pending: ids };
}

/** abortRekeyHandover drops an open hand-over whose re-key did not install a signer. */
export async function abortRekeyHandover(storage: HandoverStorage): Promise<void> {
  await storage.delete(REKEY_HANDOVER_KEY);
}

/** rekeyHold is the allocation check trigger() makes: true while a re-key holds new runs. */
export async function rekeyHold(storage: HandoverStorage, now: number): Promise<boolean> {
  const rec = await readRekeyHandover(storage);
  return rec !== null && now < rec.holdUntil;
}
