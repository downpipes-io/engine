// The run counter is per engine and a RUNLOG is per destination. These helpers read every configured
// destination's verified RUNLOG so the counter can be set past the highest index any of them holds.
//
// Two callers:
//   - the recovery seed (seedAcrossArchives): the default destination's read decides whether allocation holds;
//     the other archives only ever raise the seed, so a default RUNLOG with no signature does not leave the
//     counter behind an archive whose RUNLOG is intact;
//   - a refused index (reseedAfterIndexHeld): a RUNLOG append met an index its archive already holds, the
//     scheduler holds allocation, and this moves the counter past the highest index in every archive and
//     records which archive held it.

import { loadConfigWrapKey } from "../admin/config-secret.ts";
import { reportRunlogAnomaly } from "../admin/integrity-fault-report.ts";
import { noteSiteFault } from "../admin/site-faults.ts";
import type { ControlPlaneExport } from "../admin/control-plane.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import { buildDestination, resolveDefaultDestConfig, resolveDestination } from "../dest/factory.ts";
import { doURL } from "../do-url.ts";
import type { Env } from "../env.d.ts";
import { readVerifiedRunlogSeed, type RunlogSeedResult } from "../format/freshness.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";

/** One configured destination, read through its object getter. */
export interface RunlogReader {
  readonly id: string;
  get(key: string): Promise<Uint8Array | null>;
}

/** The refused run that asks for the counter to be advanced. */
export interface IndexHeld {
  readonly index: number;
  readonly downpipeId: string;
}

// highestAcross reads each archive's verified RUNLOG and returns the highest index and the archive that held
// it. An archive that does not verify, does not parse or cannot be read adds nothing: only a verified document
// can raise the counter.
async function highestAcross(readers: readonly RunlogReader[], verifier: HybridVerifier): Promise<{ max: number; archiveId: string | null }> {
  let max = 0;
  let archiveId: string | null = null;
  for (const r of readers) {
    // readVerifiedRunlogSeed returns a closed outcome and does not throw. An archive it could not read may hold a
    // higher index than the pass saw, so the fault is counted into the pack; a repeated index there is refused
    // again by the append.
    const res = await readVerifiedRunlogSeed((key) => r.get(key), verifier);
    if ("noSeed" in res && res.noSeed === "unreadable") noteSiteFault("runlog.advance-archive-read", new Error("archive RUNLOG unreadable"));
    if ("seed" in res && res.seed > max) {
      max = res.seed;
      archiveId = r.id;
    }
  }
  return { max, archiveId };
}

/**
 * seedAcrossArchives widens the recovery seed to every other archive. The default destination's outcome decides
 * whether allocation holds: a hold reason (unreadable, no-signer) is returned unchanged. Otherwise the seed is the
 * highest verified index across the default and the other archives, and a default with no usable RUNLOG
 * (absent, sig-absent, sig-invalid, unparsable) takes the highest index the other archives hold.
 *
 * @param primary - the default destination's outcome (format/freshness.ts readVerifiedRunlogSeed).
 * @param others - the other configured destinations.
 * @param verifier - the operator's pinned signer.
 * @returns the outcome to record.
 */
export async function seedAcrossArchives(primary: RunlogSeedResult, others: readonly RunlogReader[], verifier: HybridVerifier): Promise<RunlogSeedResult> {
  if ("noSeed" in primary && (primary.noSeed === "unreadable" || primary.noSeed === "no-signer")) return primary;
  const { max } = await highestAcross(others, verifier);
  const own = "seed" in primary ? primary.seed : 0;
  if (max === 0 && !("seed" in primary)) return primary;
  return { seed: Math.max(own, max) };
}

/**
 * reseedAfterIndexHeld reads every archive, posts the highest verified index to the scheduler so the counter
 * moves past it and the hold clears, and records a counter-advanced-after-recovery row against the refused
 * downpipe. The counter always moves past the refused index itself, so a pass that reads nothing still releases
 * the hold.
 *
 * @param scheduler - the scheduler DO stub.
 * @param readers - every configured destination.
 * @param verifier - the operator's pinned signer.
 * @param held - the refused index and its downpipe.
 */
export async function reseedAfterIndexHeld(scheduler: DurableObjectStub, readers: readonly RunlogReader[], verifier: HybridVerifier, held: IndexHeld): Promise<void> {
  const { max, archiveId } = await highestAcross(readers, verifier);
  const r = await scheduler.fetch(doURL("/control-plane/runlog-advance"), { method: "POST", body: JSON.stringify({ to: Math.max(max, held.index) }), headers: { "content-type": "application/json" } });
  const j = (await r.json()) as { moved?: { from?: number; to?: number; downpipeId?: string } | null };
  const moved = j.moved;
  if (!moved || typeof moved.from !== "number" || typeof moved.to !== "number" || typeof moved.downpipeId !== "string") return;
  await reportRunlogAnomaly(scheduler, moved.downpipeId, {
    kind: "counter-advanced-after-recovery",
    indexA: moved.from,
    indexB: moved.to,
    ...(archiveId !== null && max >= held.index ? { archiveId } : {}),
  });
}

/**
 * pinnedVerifier is the operator's pinned signer as a verifier.
 *
 * @param env - the Worker environment.
 * @returns the verifier, or null when SIGNER_PRIVATE is absent or unusable.
 */
export async function pinnedVerifier(env: Env): Promise<HybridVerifier | null> {
  if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) return null;
  try {
    return verifierFrom(await loadSigner(env.SIGNER_PRIVATE));
  } catch (e) {
    noteSiteFault("runlog.advance-signer", e);
    return null;
  }
}

/**
 * configuredArchiveReaders lists every destination the scheduler's configuration names, as RUNLOG readers keyed
 * by the customer's own destination id. A destination that does not resolve or build is left out: only a
 * verified RUNLOG can raise the counter, so a missing archive never invents an index. Never throws.
 *
 * @param env - the Worker environment.
 * @param scheduler - the scheduler DO stub.
 * @returns the readers.
 */
export async function configuredArchiveReaders(env: Env, scheduler: DurableObjectStub): Promise<RunlogReader[]> {
  const readers: RunlogReader[] = [];
  try {
    const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
    const exp = (await (await scheduler.fetch(doURL("/control-plane/export"), { method: "GET" })).json()) as ControlPlaneExport;
    for (const ed of Array.isArray(exp.destinations) ? exp.destinations : []) {
      try {
        const res = await resolveDestination(env, scheduler, ed.id, wrapKey);
        if (!res.ok) continue;
        const d = await buildDestination(env, undefined, res.config, ed.id);
        readers.push({ id: ed.id, get: (key) => d.get(key).then((r) => r?.body ?? null) });
      } catch (e) {
        noteSiteFault("runlog.advance-archive-list", e);
      }
    }
  } catch (e) {
    noteSiteFault("runlog.advance-archive-list", e);
  }
  return readers;
}

/**
 * advanceAfterIndexHeld answers a refused RUNLOG index: it reads every archive (the default included) and moves
 * the counter past the highest index any holds, which releases the allocation hold. Fail-open: a pass that
 * cannot read an archive still moves the counter past the refused index itself.
 *
 * @param env - the Worker environment.
 * @param scheduler - the scheduler DO stub.
 * @param held - the pending report from the recovery status.
 */
export async function advanceAfterIndexHeld(env: Env, scheduler: DurableObjectStub, held: IndexHeld): Promise<void> {
  try {
    const verifier = await pinnedVerifier(env);
    if (verifier === null) {
      // No signer, so no document can be verified: move past the refused index only.
      await scheduler.fetch(doURL("/control-plane/runlog-advance"), { method: "POST", body: JSON.stringify({ to: held.index }) });
      return;
    }
    const readers = await configuredArchiveReaders(env, scheduler);
    try {
      const dest = await buildDestination(env, undefined, await resolveDefaultDestConfig(env, scheduler, loadConfigWrapKey(env.CONFIG_WRAP_KEY)));
      readers.push({ id: "default", get: (key) => dest.get(key).then((r) => r?.body ?? null) });
    } catch (e) {
      noteSiteFault("runlog.advance-failed", e);
    }
    await reseedAfterIndexHeld(scheduler, readers, verifier, held);
  } catch (e) {
    noteSiteFault("runlog.advance-failed", e);
    log("error", `control-plane health pass could not advance the run counter this tick: ${(e as Error).message}`);
  }
}
