import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { integrityError } from "../format/integrity-error.ts";
import { type ObjectStore, openRun, openRunWithMaster, readRunCapsule, type Run, type RunCapsule } from "../format/reader.ts";
import { loadIdentity, loadSigner, verifierFrom } from "../keys-env.ts";

// reqEnv asserts a required env string is present, throwing the coarse "missing required configuration"
// message the restore reason-mappers key off. Shared by the run-open and the keyless-attest paths.
export function reqEnv(v: string | undefined, name: string): string {
  if (!v) throw new Error(`missing required configuration: ${name}`);
  return v;
}

// openVerifiedRun loads the keys, builds the configured destination as a read-only
// ObjectStore (the same closure the drill uses) and opens+verifies the run. Freshness is
// advisory for restore (allowStale:true) so an older run can be restored on purpose; the
// result surfaces isLatest so the operator knows.
//
// minRunlogIndex is an OPTIONAL out-of-band account-global RUNLOG high-water mark (e.g. the
// scheduler DO's own runlogCounter, fetched by the caller exactly as runKeylessAttest's
// fetchMinRunlogIndex does): supplying it lets the underlying checkRunlogFreshness catch a
// whole-document replay of an older, internally-consistent, validly-signed RUNLOG that the chain-anomaly
// check alone cannot see (openRun's rollbackDetected gate is unconditional regardless of allowStale, see
// format/freshness.ts). Omitted (as runRestore's call below does), behaviour is byte-for-byte unchanged
// from before this pin existed -- this function stays the single shared chokepoint, so a caller opts in
// by passing the pin rather than the pin being forced on every consumer.
export async function openVerifiedRun(env: Env, runId: string, destOverride?: RuntimeDestConfig | null, minRunlogIndex?: number): Promise<Run> {
  const signer = await loadSigner(reqEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
  const verifier = verifierFrom(signer);
  const identity = loadIdentity(env.OPERATIONAL_PRIVATE!); // presence checked by the caller
  const dest = await buildDestination(env, undefined, destOverride ?? null);
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) {
        // Distinguish a missing SEGMENT (the run's content-addressed bulk data, which the signed
        // root commits to) from a missing run-tree object (root/shard under run/...). A gone `seg/` object
        // is a COMPLETENESS shortfall of a present, signed run -- a tamper-equivalent integrity signal that
        // must surface LOUD and never fall through to a 3-2-1 replica -- so it is typed as a structured
        // integrity failure here, at the source, exactly mirroring the deleted-shard completeness class. A
        // missing run/<id>/... object means the run is absent at THIS destination (the genuine availability
        // / DR case), so it stays the plain "is missing" error the classifier routes to the replica fallback.
        if (k.startsWith("seg/")) throw integrityError(`object ${k} is missing`);
        throw new Error(`object ${k} is missing`);
      }
      return r.body;
    },
  };
  return openRun(store, runId, identity, verifier, { verifyFreshness: true, allowStale: true, ...(minRunlogIndex !== undefined ? { minRunlogIndex } : {}) });
}

// openRunFromMaster opens and verifies a run for RESTORE from a BROWSER-SUPPLIED 32-byte per-run master,
// instead of unwrapping the run's master capsule with the engine's held OPERATIONAL_PRIVATE. It is the
// write-back twin of the attended-verify path's verifyRunWithMaster: the console decapsulated this one run's
// master capsule in the operator's browser (openCapsule) and hands the engine only the single-archive master;
// the break-glass PRIVATE never leaves the browser. So a break-glass-only estate, which holds no operational
// read-back key at all, can still open a run here when the operator supplies a valid master.
//
// It mirrors openVerifiedRun EXACTLY (same signer/verifier, same destination, the SAME read-only ObjectStore
// including the seg/ completeness distinction, and the same freshness options), differing in ONLY two
// respects: it does NOT read OPERATIONAL_PRIVATE (it needs just SIGNER_PRIVATE, present in break-glass-only),
// and the per-run master is supplied through openRunWithMaster rather than derived from a held identity. The
// store is kept byte-for-byte identical to openVerifiedRun's on purpose, so a missing SEGMENT of a signed run
// surfaces as the same LOUD integrity failure (never a fall-through to a 3-2-1 replica) whether the restore
// used the operational key or a browser master: only the SOURCE of the decrypt key differs between the two,
// never the integrity handling downstream. The shared key-commitment check inside openRunWith validates the
// master against the signed run (reader.ts openRunWith), so a WRONG or CROSS-RUN master fails closed before a
// single record is read, exactly as a bad in-account decap would. The master is per-run (a fresh 32 random
// bytes bound to its own runId by the commitment), so it opens THIS run and nothing else. minRunlogIndex is
// the same OPTIONAL out-of-band anti-rollback pin openVerifiedRun accepts; omitted, behaviour matches the
// operational open.
export async function openRunFromMaster(env: Env, runId: string, master: Uint8Array, destOverride?: RuntimeDestConfig | null, minRunlogIndex?: number): Promise<Run> {
  const signer = await loadSigner(reqEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
  const verifier = verifierFrom(signer);
  // No loadIdentity(OPERATIONAL_PRIVATE): the master IS the whole decrypt key for this run, so the operational
  // key is never needed or read here (this is the path a break-glass-only estate reaches).
  const dest = await buildDestination(env, undefined, destOverride ?? null);
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) {
        // A gone SEGMENT (`seg/`) is a completeness shortfall of a present, signed run -- a tamper-
        // equivalent integrity failure that must surface LOUD and never fall through to a 3-2-1 replica -- so
        // it is typed as a structured integrity failure at the source, identically to openVerifiedRun above. A
        // missing run-tree object means the run is absent at THIS destination (the genuine availability / DR
        // case), so it stays the plain "is missing" error the classifier routes to the replica fallback.
        if (k.startsWith("seg/")) throw integrityError(`object ${k} is missing`);
        throw new Error(`object ${k} is missing`);
      }
      return r.body;
    },
  };
  return openRunWithMaster(store, runId, master, verifier, { verifyFreshness: true, allowStale: true, ...(minRunlogIndex !== undefined ? { minRunlogIndex } : {}) });
}

// readRestoreCapsule serves the NON-SECRET material the operator's browser needs to recover a chosen run's
// per-run master locally (openCapsule) for the in-console break-glass restore: the run's master-capsule wraps
// and its key commitment. It mirrors the attend path's readCapsuleFromDest (router-attest.ts): readRunCapsule
// SIGNATURE-VERIFIES the run's root manifest before returning anything (so a tampered or forged manifest is
// refused, and the route cannot be driven to emit attacker-shaped bytes) and rejects a non-ULID runId. The
// capsule is already sitting encrypted in the customer's own destination bucket and is undecryptable without
// the break-glass PRIVATE (which stays in the browser), so serving it to the authenticated owner discloses
// nothing new. It requires only SIGNER_PRIVATE, so it works in break-glass-only exactly as it does elsewhere.
export async function readRestoreCapsule(env: Env, runId: string, destOverride?: RuntimeDestConfig | null): Promise<RunCapsule> {
  const signer = await loadSigner(reqEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
  const verifier = verifierFrom(signer);
  const dest = await buildDestination(env, undefined, destOverride ?? null);
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  return readRunCapsule(store, runId, verifier);
}
