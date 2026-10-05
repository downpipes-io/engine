// The cron passes that keep the control plane RECOVERABLE and detect amnesia.
//
// These run in the WORKER (drive.ts), because the SchedulerDO holds no env: the signer key
// (SIGNER_PRIVATE), the config wrap key (CONFIG_WRAP_KEY) and the destination handles all live here.
// The DO PRODUCES the no-custody export slice and CONSUMES a verified one; the signing + the bucket I/O
// are here.
//
//   runControlPlaneExportPass -- CHANGE-GATED: when the head config posture differs from the last export,
//     it pulls the no-custody slice from the DO, signs it with the engine signer (the SAME hybrid signer
//     that signs archives), and writes a NEW timestamped, immutable `_RECOVERY/CONTROL-PLANE/<v>-<iso>.json`
//     (+ `.json.sig`) to EVERY destination, then records the export so the next tick skips an unchanged
//     slice. Budget-yielded + fail-open: a per-destination fault degrades to "export next tick".
//
//   runControlPlaneHealthPass -- KILLS THE SILENCE: when the DO control plane is EMPTY but a resolvable
//     destination bucket still holds runs (a SchedulerDO storage loss / amnesia), it SETS the
//     recovery-required latch in the DO (which blocks the silent Access/passkey re-bootstrap and writes a
//     critical audit event) AND fires a critical notification, so a wiped control plane is LOUD, never a
//     silent stop.

import { loadConfigWrapKey } from "../admin/config-secret.ts";
import {
  type AutoHealRefusalCode,
  type AutoHealSubCause,
  assertNoPlaintextSecretInExport,
  type CandidateScan,
  CONTROL_PLANE_PREFIX,
  type ControlPlaneExport,
  type ControlPlaneExportState,
  candidateVersionMatchesExport, type ExportSkipReason,
  controlPlaneArtefactKey,
  controlPlaneDestCredFingerprint,
  controlPlaneRecipientPinHash,
  isControlPlaneExport,
  plaintextGenerationKeysToPurge,
  sameVersionGenerationKeysToPurge,
  type StagedControlPlane,
  scanControlPlaneCandidates,
  selectLatestControlPlaneExport,
  selectLatestSealedControlPlaneExport,
  serialiseControlPlaneExport,
  verifyControlPlaneSignature,
} from "../admin/control-plane.ts";
import { envRecipientFingerprint } from "../admin/key-vintages.ts";
import { buildControlPlaneArtefactToWrite, isSealedControlPlaneExport, sealedArtefactKey, serialiseSealedControlPlaneExport, unsealAndResignForAutoHeal, verifySealedControlPlaneSignature } from "../admin/control-plane-seal.ts";
import { doURL, type schedulerStub } from "../admin/router.ts";
import { b64urlDecode, utf8 } from "../crypto/bytes.ts";
import { type HybridVerifier, hybridVerifyDetailed } from "../crypto/sign.ts";
import { buildDestination, DestResolutionError, resolveDefaultDestConfig, resolveDestination } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { readVerifiedRunlogSeed, type RunlogSeedResult } from "../format/freshness.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { loadControlPlaneExportRecipients, loadIdentity, loadSigner, operationalSealPublic, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import type { budgetFromEnv } from "../seal/budget.ts";
import {
  type CpExportFailClass,
  classifyCpExportFail, classifyCpExportPassFault,
  noteAutoHealAttempt,
  noteAutoHealDeferral,
  noteCpExportAttempt,
  noteCpExportDestFail,
  noteCpExportPassThrew,
  noteCpExportRecordWriteFailure,
  noteCpExportTruncated,
  noteCpPlaintextPurgePending,
  noteCronPass,
  noteResumeApplyRefusal,
  noteUndeliveredCriticalAlert,
} from "./cron-fault-ledger.ts";
import { routeNotification } from "./notify-passes.ts";

// CONTROL_PLANE_AUTOHEAL_RESERVE is the conservative subrequest headroom the auto-heal needs before it
// scans the recovery namespace (one list + two gets to fetch the latest export + its .sig). It runs LAST,
// after backups/replication, so this only spends when there is ample headroom; otherwise it retries next tick.
const CONTROL_PLANE_AUTOHEAL_RESERVE = 8;

// RecoveryStatus is the cron's view of the DO control-plane recovery state (the /control-plane/recovery-status
// shape): is recovery required, is the plane empty, has the no-authority resume slice already been applied,
// has the auto-heal refused (stepped back to manual), and a redaction-safe summary of any staged export.
interface RecoveryStatus {
  recoveryRequired: boolean;
  reason: string | null;
  configEmpty: boolean;
  resumeApplied: boolean;
  refused: { reason: string; at: string } | null;
  staged: { sourceKey: string; version: number; stagedAt: string; downpipes: number; resumeApplied: boolean } | null;
  runlogSeed?: { seed?: number; noSeed?: string } | null;
}

// readRecoveryRunlogSeed reads the destination's own RUNLOG for the recovery path and returns the closed
// outcome (format/freshness.ts readVerifiedRunlogSeed). An absent or unloadable SIGNER_PRIVATE is "no-signer",
// the same as the export pass's own guard: without it the document cannot be verified.
async function readRecoveryRunlogSeed(env: Env, dest: Awaited<ReturnType<typeof buildDestination>>): Promise<RunlogSeedResult> {
  if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) return { noSeed: "no-signer" };
  let verifier: HybridVerifier;
  try {
    verifier = verifierFrom(await loadSigner(env.SIGNER_PRIVATE));
  } catch {
    return { noSeed: "no-signer" };
  }
  return readVerifiedRunlogSeed((key) => dest.get(key).then((r) => r?.body ?? null), verifier);
}

// retryRunlogSeed re-reads the RUNLOG on a tick after the recovery latch recorded no seed, and posts the
// outcome. A seed raises the counter and releases any allocation hold (sched/runlog-seed.ts). A destination
// that does not resolve this tick leaves the record as it is, and the next tick tries again.
async function retryRunlogSeed(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<void> {
  try {
    const dest = await buildDestination(env, undefined, await resolveDefaultDestConfig(env, scheduler, loadConfigWrapKey(env.CONFIG_WRAP_KEY)));
    const runlogSeed = await readRecoveryRunlogSeed(env, dest);
    await scheduler.fetch(doURL("/control-plane/runlog-seed"), { method: "POST", body: JSON.stringify({ runlogSeed }) });
  } catch (e) {
    log("error", `control-plane health pass could not retry the RUNLOG seed read this tick: ${(e as Error).message}`);
  }
}

// CONTROL_PLANE_EXPORT_PER_DEST is the conservative per-destination subrequest estimate the export pass
// charges to the shared budget (a couple of writes: the .json + the .json.sig). It keeps the pass from
// overdrawing the platform cap on a many-destination fleet.
const CONTROL_PLANE_EXPORT_PER_DEST = 4;

// AmnesiaProbeClass is the CLOSED outcome vocabulary of the health pass's amnesia-detection attempt (kept in
// sync with the DO's ControlPlaneAmnesiaProbe). recordAmnesiaProbe posts it best-effort so the support pack
// can see WHY the latch did or did not fire (the recovery latch's own blind spots).
type AmnesiaProbeClass = "not-empty" | "runs-present" | "runlog-absent" | "probe-error" | "no-resolvable-dest";
async function recordAmnesiaProbe(scheduler: ReturnType<typeof schedulerStub>, probe: AmnesiaProbeClass): Promise<void> {
  try {
    await scheduler.fetch(doURL("/control-plane/amnesia-probe"), { method: "POST", body: JSON.stringify({ probe }) });
  } catch {
    // An empty catch here would let the amnesia-probe field go silently STALE -- the pack would show a
    // weeks-old probe class as if it were this tick's verdict, which on the disaster-recovery path is a lie by
    // omission. Record the transport loss as a closed deferral so a stale probe field is attributable.
    // The probe record is observability; a failed record must never affect detection or the auto-heal.
    noteAutoHealDeferral("probe-transport");
  }
}

// runControlPlaneExportPass writes the signed, no-custody control-plane export to every destination when
// the head config posture has changed since the last export. Fully fail-open (a fault degrades to "export
// next tick"); cheap when nothing changed (one state read + one slice read, then a hash compare).
// recordExportHealth posts the export pass's outcome (skip reason + per-dest write outcome) best-effort so a
// stale recovery generation (budget-starved) or a partial write (a dest rejected the recovery artefact) is
// explained in the support pack. A failed record never affects the export itself.
async function recordExportHealth(
  scheduler: ReturnType<typeof schedulerStub>,
  health: { skipped?: ExportSkipReason; wroteAny: boolean; configVersion?: number; perDest: Array<{ id: string; ok: boolean; reason?: CpExportFailClass }>; recipientPinDrift?: { matches: boolean; added: number; removed: number } },
): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/control-plane/export-health"), {
      method: "POST",
      body: JSON.stringify({ at: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"), ...health }),
    });
    // An unread response would let a non-2xx pass for a write. When THIS record is lost the pack
    // shows a STALE export health as if it were this tick's verdict -- on the recovery path, a lie by omission.
    if (!resp.ok) noteCpExportRecordWriteFailure();
  } catch {
    // observability only -- but the LOSS itself is now recorded (the pack must never read a stale record as fresh).
    noteCpExportRecordWriteFailure();
  }
}

// CONTROL_PLANE_PURGE_PER_GENERATION is what removing one superseded generation costs: read its body and its
// .sig to prove this engine wrote it (2), then delete both (2).
const CONTROL_PLANE_PURGE_PER_GENERATION = 4;

// generationProvenance says whether THIS engine wrote a superseded generation: its detached signature verifies
// under this engine's signer, and its account id is this engine's. Only "own" is ever deleted.
//
// Why read it at all. The auto-heal refuses two artefacts at the top version because a second one signals an
// injected sibling, or a second engine writing the same bucket (control-plane.ts, selectLatest*). Deleting on
// the version alone would erase that signal, and in a shared bucket it would delete the other engine's
// genuine recovery artefact whenever the two config versions coincide.
async function generationProvenance(dest: Awaited<ReturnType<typeof buildDestination>>, gen: { key: string; sigKey: string | null }, verifier: HybridVerifier, accountId: string | null): Promise<"own" | "foreign" | "unsigned"> {
  if (gen.sigKey === null) return "unsigned";
  const body = await dest.get(gen.key);
  const sigObj = await dest.get(gen.sigKey);
  if (body === null || sigObj === null) return "unsigned";
  const sig = new TextDecoder().decode(sigObj.body).trim();
  try {
    const parsed = JSON.parse(new TextDecoder().decode(body.body)) as unknown;
    if (isSealedControlPlaneExport(parsed)) return parsed.engineAccountId === accountId && (await verifySealedControlPlaneSignature(parsed, sig, verifier)) ? "own" : "foreign";
    if (isControlPlaneExport(parsed)) return parsed.engineAccountId === accountId && (await verifyControlPlaneSignature(parsed, sig, verifier)) ? "own" : "foreign";
  } catch {
    // An unparseable body or signature is not provably this engine's, so it stays.
  }
  return "foreign";
}

// purgeSupersededGenerations removes from ONE destination what its current generation supersedes: the other
// generations at the same config version that this engine wrote, and, when the current generation is sealed,
// every readable plaintext generation. Both run after the current generation is in place, so a destination
// never loses its only recovery artefact.
//
// It stops before it would spend `reserve`, the writes later destinations still need. Before, the purge ran
// the budget to zero and the destinations after it were cut off in the same tick. A budget stop returns
// budgetStop, and the caller records the destination as purge debt, so later ticks finish the purge. Any
// other fault is logged and is not debt: an object lock that refuses a delete refuses it again next tick.
async function purgeSupersededGenerations(
  dest: Awaited<ReturnType<typeof buildDestination>>,
  destId: string,
  currentKey: string,
  exp: ControlPlaneExport,
  sealed: boolean,
  verifier: HybridVerifier,
  budget: ReturnType<typeof budgetFromEnv>,
  reserve: number,
): Promise<{ budgetStop: boolean }> {
  const affordable = (cost: number): boolean => budget.remaining() >= reserve + cost && !budget.shouldYield();
  if (!affordable(1)) return { budgetStop: true };
  let keys: string[];
  try {
    budget.spend(1);
    keys = await dest.list(CONTROL_PLANE_PREFIX);
  } catch (le) {
    log("error", `control-plane export: could not list the recovery namespace of destination ${destId} to purge superseded generations: ${(le as Error).message}`);
    return { budgetStop: false };
  }
  let budgetStop = false;
  const v = exp.configVersion;
  const candidates = sameVersionGenerationKeysToPurge(keys, currentKey, v, sealed);
  let removed = 0;
  let foreign = 0;
  let unsigned = 0;
  try {
    for (const gen of candidates) {
      if (!affordable(CONTROL_PLANE_PURGE_PER_GENERATION)) {
        budgetStop = true;
        break;
      }
      budget.spend(2);
      const who = await generationProvenance(dest, gen, verifier, exp.engineAccountId);
      if (who === "foreign") foreign++;
      if (who === "unsigned") unsigned++;
      if (who !== "own") continue;
      await dest.delete(gen.key);
      if (gen.sigKey !== null) await dest.delete(gen.sigKey);
      budget.spend(2);
      removed++;
    }
  } catch (se) {
    log("error", `control-plane export: could not remove superseded recovery generations at version ${v} in destination ${destId} (object-lock, or a transient error): ${(se as Error).message}`);
  }
  if (removed > 0) log("info", `control-plane export: removed ${removed} superseded recovery generation(s) at version ${v} from destination ${destId}`);
  if (budgetStop) log("info", `control-plane export: superseded recovery generations at version ${v} remain in destination ${destId} (budget stop); the next tick continues the purge`);
  // Kept on purpose. The auto-heal refuses this version as ambiguous until a configuration change writes a
  // higher one, and the refusal is the signal an operator needs to see.
  if (foreign + unsigned > 0) log("error", `control-plane export: kept ${foreign} generation(s) at version ${v} in destination ${destId} that this engine did not sign or that name another account, and ${unsigned} with no signature; the auto-heal refuses this version as ambiguous until a configuration change writes a higher one`);
  // The sealed export is now in THIS destination, so purge its readable plaintext generations (best effort).
  // A WORM/object-lock denial leaves the plaintext (the off-account floor guards it).
  if (sealed) {
    try {
      const purge = plaintextGenerationKeysToPurge(keys);
      let purged = 0;
      for (const pk of purge) {
        if (!affordable(1)) {
          budgetStop = true;
          break;
        }
        await dest.delete(pk);
        budget.spend(1);
        purged++;
      }
      if (purged > 0) log("info", `control-plane sealing: purged ${purged} plaintext recovery key(s) from destination ${destId}`);
      // Whatever is LEFT is readable plaintext control-plane state (the roster + topology) sitting
      // in a bucket the customer believes is sealed -- a WORM/object-lock denial, or a budget stop.
      // Record the debt as a count only; never a key.
      noteCpPlaintextPurgePending(purge.length - purged);
    } catch (pe) {
      // The purge threw: the plaintext generations are still there, and how many is unknown -- record at
      // least one outstanding, so the debt is never silently zero.
      noteCpPlaintextPurgePending(1);
      log("error", `control-plane sealing: could not purge plaintext recovery generations in destination ${destId} (object-lock, or a transient error): ${(pe as Error).message}`);
    }
  }
  return { budgetStop };
}

export async function runControlPlaneExportPass(env: Env, scheduler: ReturnType<typeof schedulerStub>, budget: ReturnType<typeof budgetFromEnv>): Promise<void> {
  // The pass RAN. Every bail below is honest, but the record it writes is indistinguishable from the one
  // a healthier tick left behind, so "export health is all-ok but this destination's artefact is generations
  // old" would have no thread to pull without it. lastAttemptAt is that thread.
  noteCpExportAttempt();
  try {
    // Without a signer we cannot produce a verifiable artefact; the recovery layer is signature-gated by
    // design (a forged export must never reconcile), so skip honestly rather than write an unsigned slice.
    if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) {
      await recordExportHealth(scheduler, { skipped: "no-signer", wroteAny: false, perDest: [] });
      return;
    }
    // Leave ample headroom: the export is recovery hygiene, never ahead of backups/replication. A
    // budget-yield here leaves the last generation stale, which the export-health record now explains.
    if (budget.shouldYield()) {
      await recordExportHealth(scheduler, { skipped: "budget-yield", wroteAny: false, perDest: [] });
      return;
    }

    const lastState = (await (await scheduler.fetch(doURL("/control-plane/export-state"), { method: "GET" })).json()) as ControlPlaneExportState | null;
    const exp = (await (await scheduler.fetch(doURL("/control-plane/export"), { method: "GET" })).json()) as ControlPlaneExport;
    // Nowhere to write (no destination configured) => nothing to do.
    if (exp.destinations.length === 0) {
      await recordExportHealth(scheduler, { skipped: "no-destination", wroteAny: false, perDest: [] });
      return;
    }
    // CHANGE-GATE: skip re-signing an unchanged slice. The key is the head config content hash AND a
    // destination-credential fingerprint, so a dest CREDENTIAL rotation (which does not bump the config
    // content hash) still re-fires the export (otherwise the recovery artefact keeps a stale credential).
    const destCredHash = await controlPlaneDestCredFingerprint(exp);
    // The recipient pin is computed BEFORE the change gate and forms part of it. Adding a recipient changes
    // neither the config content hash nor the credential fingerprint, so without this the gate would call a
    // recipient swap "unchanged", skip the export, and leave the last signed artefact recording the OLD set
    // forever. An attacker adding their own public key would be shielded by the very record meant to catch
    // them, which is the failure mode this whole pin exists to prevent.
    const recipientPin = {
      breakGlass: await envRecipientFingerprint(env.BREAK_GLASS_PUBLIC),
      // What the NEXT seal wraps to, so the OPERATIONAL_RETIRED marker drops operational here as it does there.
      operational: await envRecipientFingerprint(operationalSealPublic(env)),
      config: await envRecipientFingerprint(env.CONFIG_RECIPIENT_PUBLIC),
    };
    const recipientPinHash = await controlPlaneRecipientPinHash(recipientPin);
    const pinMoved = lastState !== null && (lastState.recipientPinHash ?? "") !== recipientPinHash;
    // prior is the last recorded export when this tick's slice is the one it covered, else null (a full export).
    //
    // An unchanged slice can still leave work. A destination with no destKeys entry holds no copy of the
    // current generation: its write failed, or the budget cut it off. A destination in purgeDebt still holds
    // superseded generations a budget stop left behind. The gate stays open for both, and this tick writes to
    // the laggards only and resumes the purge. Before, one good write closed the gate. A laggard then kept a
    // stale artefact, and an upgraded bucket kept its backlog of same-version generations, until the next
    // configuration change.
    const prior = lastState !== null && lastState.configContentHash === exp.configContentHash && (lastState.destCredHash ?? "") === destCredHash && !pinMoved ? lastState : null;
    const liveIds = new Set(exp.destinations.map((d) => d.id));
    const held: Record<string, string> = {};
    for (const [id, k] of Object.entries(prior?.destKeys ?? {})) if (liveIds.has(id)) held[id] = k;
    const debtIn = new Set((prior?.purgeDebt ?? []).filter((id) => held[id] !== undefined));
    const toWrite = exp.destinations.filter((d) => held[d.id] === undefined);
    if (prior !== null && toWrite.length === 0 && debtIn.size === 0) {
      await recordExportHealth(scheduler, { skipped: "unchanged", wroteAny: false, configVersion: exp.configVersion, perDest: [] });
      return;
    }

    const signer = await loadSigner(env.SIGNER_PRIVATE);
    // Seal the export body whenever the engine holds ANY recipient public key: the break-glass recipient,
    // the config recipient, or both. A destination-bucket reader then never sees the roster or topology.
    //
    // The seal condition was once "break-glass is installed and CONTROL_PLANE_EXPORT_SEALING_DISABLED is
    // not set". Both halves wrote cleartext when a key was there to seal to. An engine with only a config
    // recipient wrote cleartext. The opt-out flag existed so a break-glass-only engine could auto-heal, and
    // the config recipient removed that reason: a sealed export opens with the CONFIG recipient key
    // (below, and control-plane-seal.ts), and the break-glass-only switch does not remove it. The flag
    // is gone, and nothing reads it.
    //
    // The export stays cleartext only when no recipient key exists at all. Nothing could open a sealed
    // export on such an engine, and a signed cleartext export is still a recovery artefact. The export
    // state records the choice, and the environment-self-backup posture check says so.
    //
    // The second recipient is the CONFIG recipient, and nothing else: the export carries no operational-key
    // fallback, as the paragraph below already says in as many words. Sealing to the ARCHIVE recipient set
    // instead would couple config recovery to a key that also opens customer archives, so a break-glass-only
    // engine could not open its own configuration and would need to be rebuilt offline. A dedicated recipient
    // breaks that coupling, and the engine holds a key that opens its own configuration and nothing else.
    //
    // Break-glass stays recipient #0 when installed, so the offline reader's unseal-export is unaffected and
    // an operator holding only their offline key still recovers their configuration.
    //
    // There is deliberately NO fallback to OPERATIONAL_PUBLIC here. The key ceremony generates the config
    // recipient unconditionally, in both postures, so an engine without one is an engine that was never
    // keyed rather than an older engine to be accommodated. A fallback would quietly re-couple config
    // recovery to the archive key for exactly the estates that chose to remove it.
    //
    // An empty set => the signed cleartext. The sealed artefact goes under a distinct `.sealed.json` key.
    // buildControlPlaneArtefactToWrite is the single seal-or-cleartext decision.
    const recipients = loadControlPlaneExportRecipients(env.BREAK_GLASS_PUBLIC, env.CONFIG_RECIPIENT_PUBLIC);
    // Stamp the recipient pin HERE rather than in the DO, because the DO holds no env and the recipient
    // publics are env bindings. This is the last point before the export is signed, so the pin travels
    // inside the signature rather than beside it.
    //
    // What this buys: the structural gates permit extra recipients, so an added public key produces
    // archives that still verify and attest clean. Pinning the expected set in DO storage would be theatre,
    // since whoever can add a recipient controls the deployed code and therefore the DO. Recording it in a
    // SIGNED artefact that lands on the destination, and can sit under object lock, puts the record where
    // the engine cannot retroactively rewrite it and where the offline reader can see it.
    exp.recipientPin = recipientPin;
    // The drift verdict for the posture surface. Computed HERE because the comparison needs the recipient
    // publics, which are env bindings the Durable Object cannot read. Counts only: the pin values are
    // already in the signed export, and the check only needs to know that the set moved. A catch-up tick
    // (prior !== null) re-uses the recorded set, so it reports no drift, and the DO keeps the last verdict.
    const priorPinKnown = lastState !== null && typeof lastState.recipientPinHash === "string";
    const drift = prior === null && priorPinKnown ? { matches: !pinMoved, added: pinMoved ? 1 : 0, removed: 0 } : undefined;
    // The artefact is built only when a destination needs a copy. A purge-only tick writes nothing.
    const artefact = toWrite.length > 0 ? await buildControlPlaneArtefactToWrite(exp, signer, recipients, () => crypto.getRandomValues(new Uint8Array(16))) : null;
    const baseKey = controlPlaneArtefactKey(exp.configVersion, exp.exportedAt);
    const key = artefact?.sealed === true ? sealedArtefactKey(baseKey) : baseKey;
    // The form of the current generation: the artefact just built, or the recorded one on a purge-only tick.
    const sealedForm = artefact !== null ? artefact.sealed : prior?.sealed === true;
    const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
    const verifier = verifierFrom(signer);

    // Write to EVERY destination that holds no copy of this generation (each is a self-contained archive
    // store, so the recovery artefact must live alongside the runs in each). A per-destination fault is
    // logged, RECORDED (per-dest ok:false) and skipped. The export state names the destinations that hold
    // the generation, so the next tick retries the others.
    const destKeys: Record<string, string> = { ...held };
    const debtOut = new Set<string>();
    let wroteNow = 0;
    let truncated = 0;
    // perDest carries ok:false plus a closed reason class, so the posture check's "some copies of your
    // configuration are stale or missing" can name WHICH destination and WHY. The class is
    // selected from the fault by the same classifier the aggregate counter already uses (classifyCpExportFail);
    // the store's message, the endpoint, the bucket and the object key never leave that function.
    const perDest: Array<{ id: string; ok: boolean; reason?: CpExportFailClass }> = [];
    for (const [i, ed] of exp.destinations.entries()) {
      const writing = held[ed.id] === undefined;
      if (!writing && !debtIn.has(ed.id)) {
        perDest.push({ id: ed.id, ok: true }); // it already holds this generation, and owes no purge
        continue;
      }
      // The writes every later destination still needs. A purge here stops before it would spend them.
      const reserve = CONTROL_PLANE_EXPORT_PER_DEST * exp.destinations.slice(i + 1).filter((d) => held[d.id] === undefined).length;
      if (writing && budget.remaining() < CONTROL_PLANE_EXPORT_PER_DEST) {
        // A destination the budget cut off gets an ok:false row with no reason class (the truncation
        // counter names the budget). Before, it got NO row, so allDestinationsWrote read true while the
        // destination held no current export.
        perDest.push({ id: ed.id, ok: false });
        truncated++;
        continue;
      }
      if (!writing) {
        perDest.push({ id: ed.id, ok: true });
        if (budget.remaining() < reserve + 1 + CONTROL_PLANE_PURGE_PER_GENERATION) {
          debtOut.add(ed.id);
          continue;
        }
      }
      let dest: Awaited<ReturnType<typeof buildDestination>>;
      try {
        // The export goes to the destination this id names and no other: a refused id is a per-destination
        // fault below, never a write to the env default in its place. The deploy-time id is the env one.
        const res = await resolveDestination(env, scheduler, ed.id, wrapKey);
        if (!res.ok) throw new DestResolutionError(res.reason, ed.id);
        dest = await buildDestination(env, undefined, res.config, ed.id);
        if (writing && artefact !== null) {
          await dest.put(key, artefact.bodyBytes);
          try {
            await dest.put(`${key}.sig`, utf8(artefact.sigText));
          } catch (se) {
            // A body with no signature beside it is an unsigned generation at this version, and the auto-heal
            // refuses such a bucket. Remove it (best effort) before the fault is recorded below.
            await dest.delete(key).catch(() => undefined);
            throw se;
          }
          budget.spend(CONTROL_PLANE_EXPORT_PER_DEST);
          destKeys[ed.id] = key;
          wroteNow++;
          perDest.push({ id: ed.id, ok: true });
        } else {
          budget.spend(1); // the destination-config read of a purge-only destination
        }
      } catch (e) {
        if (writing) {
          perDest.push({ id: ed.id, ok: false, reason: classifyCpExportFail(e) });
          // A WORM policy refusing the overwrite (permanent; needs a new key scheme), a rotated
          // CONFIG_WRAP_KEY (the credential cannot be opened at all) and a network blip (self-healing) are
          // different faults the reason class distinguishes; the message is discarded here.
          noteCpExportDestFail(e);
          log("error", `control-plane export to destination ${ed.id} skipped this tick: ${(e as Error).message}`);
        } else {
          log("error", `control-plane export: could not open destination ${ed.id} to finish its purge: ${(e as Error).message}`);
        }
        continue;
      }
      const current = destKeys[ed.id];
      if (current === undefined) continue;
      const r = await purgeSupersededGenerations(dest, ed.id, current, exp, sealedForm, verifier, budget, reserve);
      if (r.budgetStop) debtOut.add(ed.id);
    }
    if (truncated > 0) noteCpExportTruncated(truncated);
    // The export is recorded while at least one destination holds the current generation. destKeys and
    // purgeDebt then tell the next tick what is left. With no copy anywhere, nothing is recorded, and the
    // next tick is a full export again.
    const holdsAny = Object.keys(destKeys).length > 0;
    if (holdsAny) {
      await scheduler.fetch(doURL("/control-plane/export-recorded"), {
        method: "POST",
        body: JSON.stringify({
          configVersion: exp.configVersion,
          configContentHash: exp.configContentHash,
          exportedAt: wroteNow > 0 ? exp.exportedAt : (prior?.exportedAt ?? exp.exportedAt),
          destCredHash,
          recipientPinHash,
          sealed: sealedForm,
          destKeys,
          purgeDebt: [...debtOut],
          // wrote:false (a purge-only tick) updates the pointer without an audit row: no export was written.
          wrote: wroteNow > 0,
        }),
      });
      if (wroteNow > 0) log("info", `control-plane export written (version ${exp.configVersion}) to ${wroteNow} of ${exp.destinations.length} destination(s)`);
    }
    if (toWrite.length > 0) {
      // Record the per-destination outcome of every tick that owed a write, whether or not it wrote (a total
      // per-dest failure is the loudest signal: the export ran but every destination rejected the recovery
      // artefact). wroteAny means the current generation is in at least one destination, and perDest has a
      // row for every destination, so a laggard retried here and still failing keeps the check red.
      await recordExportHealth(scheduler, { wroteAny: holdsAny, configVersion: exp.configVersion, perDest, ...(drift !== undefined ? { recipientPinDrift: drift } : {}) });
    } else {
      // A purge-only tick: the export itself is unchanged, so the DO keeps the last write outcome.
      await recordExportHealth(scheduler, { skipped: "unchanged", wroteAny: false, configVersion: exp.configVersion, perDest: [] });
    }
  } catch (e) {
    // No generation is written, and an unsignable value repeats the throw every tick. The closed class goes to the cron ledger and to the export-health skip reason, which fails the environment-self-backup check.
    const fault = classifyCpExportPassFault(e);
    noteCpExportPassThrew(fault);
    log("error", `control-plane export pass skipped this tick (${fault}): ${(e as Error).message}`);
    await recordExportHealth(scheduler, { skipped: fault, wroteAny: false, perDest: [] });
  }
}

// runDeployObservePass drives the deterministic per-tick deploy-identity observation. Unlike the GET
// /admin/status diff (which only records a deploy when someone polls status), this runs EVERY cron
// tick, so a deploy that silently dropped a live source binding is recorded even on an unattended
// account. The Worker holds env.CF_VERSION_METADATA, so the deploy id changes on every `wrangler deploy`;
// when the binding is absent (env-fallback/local) the DO records `cfVersionIdAbsent` and falls back to the
// engine version. Cheap (one DO write) and fully fail-open. Runs LAST, so it never delays a backup.
export async function runDeployObservePass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<void> {
  try {
    const cfVersionId = env.CF_VERSION_METADATA?.id;
    await scheduler.fetch(doURL("/control-plane/deploy-observe"), {
      method: "POST",
      body: JSON.stringify({ engineVersion: ENGINE_VERSION, ...(typeof cfVersionId === "string" && cfVersionId.length > 0 ? { cfVersionId } : {}) }),
    });
  } catch (e) {
    log("error", `control-plane deploy-observe pass skipped this tick: ${(e as Error).message}`);
  }
}

// runControlPlaneHealthPass detects control-plane amnesia (the DO is empty but a resolvable destination
// bucket still holds runs), KILLS THE SILENCE (latches recovery-required, blocking the silent re-bootstrap
// + writing a critical audit event + firing a critical notification), and then drives the SAFE AUTO-HEAL:
// it auto-applies ONLY the no-authority resume slice (downpipes/schedules/dest) so backups RESUME, and
// stages the rest for a break-glass confirm. Fail-open.
//
// LIMITATION (documented): the destination config lives in the DO too, so after a FULL wipe with only
// console-set destinations there is no destination to probe and detection (and the auto-heal) falls back to
// the operator (who runs the break-glass reconcile). This pass catches the env/IaC-destination case and any
// partial/cleared-config state, where a destination IS resolvable.
export async function runControlPlaneHealthPass(env: Env, scheduler: ReturnType<typeof schedulerStub>, budget: ReturnType<typeof budgetFromEnv>): Promise<void> {
  try {
    const status = (await (await scheduler.fetch(doURL("/control-plane/recovery-status"), { method: "GET" })).json()) as RecoveryStatus;
    // A recovery that latched with no RUNLOG seed re-reads the RUNLOG on every later tick, whatever the latch
    // and the plane now say, until a seed is recorded.
    if (status.runlogSeed != null && status.runlogSeed.seed === undefined) await retryRunlogSeed(env, scheduler);

    if (!status.recoveryRequired) {
      // The plane is not empty => healthy, nothing to do (the cheap common case: one DO read).
      if (!status.configEmpty) {
        await recordAmnesiaProbe(scheduler, "not-empty");
        return;
      }

      // DETECT: resolve a destination to probe (the default DO-stored one, else the env destination). A
      // full wipe with only console-set destinations resolves none => we cannot detect via the bucket. That
      // blind spot would otherwise leave NO signal; record it as `no-resolvable-dest` (un-probeable amnesia) so the
      // support pack sees "plane empty but nothing to probe", never a false "healthy".
      let dest: Awaited<ReturnType<typeof buildDestination>>;
      try {
        const destCfg = await resolveDefaultDestConfig(env, scheduler, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
        dest = await buildDestination(env, undefined, destCfg);
      } catch (e) {
        await recordAmnesiaProbe(scheduler, "no-resolvable-dest");
        log("error", `control-plane health pass could not probe a destination (no resolvable bucket): ${(e as Error).message}`);
        return;
      }
      // The account-global RUNLOG is the single self-describing proof that runs exist in this bucket. An
      // absent RUNLOG reads as a brand-new account; a probe THAT THREW (an unreadable bucket) is UNDETERMINED,
      // NOT a new account. Record which so a wipe misread as "new account" (the false-negative) is visible.
      let bucketHasRuns: boolean;
      try {
        bucketHasRuns = await dest.exists("_RECOVERY/RUNLOG");
      } catch (e) {
        await recordAmnesiaProbe(scheduler, "probe-error");
        log("error", `control-plane health pass RUNLOG existence probe threw (undetermined, not a new account): ${(e as Error).message}`);
        return;
      }
      if (!bucketHasRuns) {
        await recordAmnesiaProbe(scheduler, "runlog-absent");
        return; // an empty plane with an empty bucket is a brand-new account, not amnesia.
      }
      await recordAmnesiaProbe(scheduler, "runs-present"); // config empty + the bucket has runs => amnesia CONFIRMED.

      // Without a seed, the rebuilt DO would hold no runlogCounter, so the very next trigger would allocate
      // index 1 into a bucket the exists() probe above just proved already holds a RUNLOG: the writer appends
      // a duplicate index and re-signs, and every later freshness check of this destination reports a
      // rollback. Read the bucket's own RUNLOG now, verified under the operator's pinned signer, and carry the
      // outcome into the latch: a seed anchors the counter before any trigger allocates, and a no-seed outcome
      // carries its closed reason (format/freshness.ts), which the DO records and, for a failed read or a
      // missing signer, holds allocation on until a later tick's re-read establishes a seed (sched/runlog-seed.ts).
      const runlogSeed = await readRecoveryRunlogSeed(env, dest);

      const reason = "the control plane is empty but the destination bucket still holds backups -- the scheduler control plane appears to have been lost; backups have STOPPED until it is recovered";
      // Latch recovery-required in the DO (blocks the silent re-bootstrap; writes the critical audit event;
      // records the RUNLOG seed outcome, and seeds runlogCounter when a seed was established).
      await scheduler.fetch(doURL("/control-plane/recovery-required"), { method: "POST", body: JSON.stringify({ reason, runlogSeed }) });
      // Fire a CRITICAL notification (reuse the posture-regression event with an explicit critical severity:
      // a lost control plane IS a posture regression, and this avoids a new event type). Account-level, so
      // downpipeId/downpipeName are null; the detail is redaction-safe (no secret, no config value).
      const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
      // The recovery-required LATCH is already set above, so this pass will not re-enter the detection
      // branch on the next tick -- which means an undelivered alert here is the ONE page the customer ever gets
      // about a WIPED control plane. Latch the loss instead of discarding the delivered boolean.
      const delivered = await routeNotification(env, scheduler, {
        event: "posture-regression",
        severity: "critical",
        downpipeId: null,
        downpipeName: null,
        detail: "control plane empty but the destination has backups: recovering automatically (break-glass confirm needed for operator access)",
        at,
      });
      if (!delivered) noteUndeliveredCriticalAlert("posture-regression", true);
      log("error", "control-plane amnesia detected: config empty but the destination bucket has runs; recovery-required latched + critical alert fired");
      // Fall through to the auto-heal THIS tick (status reflects the pre-latch read, so resumeApplied/refused
      // are still false/null -- correct: nothing has been staged yet).
    }

    // AUTO-HEAL. We are in recovery (latched this tick or earlier). Once the auto-heal has refused
    // (stepped back to manual) or the no-authority resume slice has been applied (backups resumed), there
    // is nothing more to do here -- authority restore waits on the break-glass confirm, not the cron.
    if (status.refused !== null) return;
    if (status.resumeApplied) return;
    // The auto-heal is one of the CLOSED cron passes; it runs INSIDE the cp-health pass, so without its own
    // record it would be attributed only to that pass's name. A throw here (the recovery scan, the stage, the
    // resume-apply round trip) is swallowed by the catch below, which is deliberately fail-open, so
    // "backups stopped after a wipe and never resumed" could not otherwise be attributed to the one pass
    // whose whole job is to make them resume. It is recorded ONLY when the auto-heal ACTUALLY RUNS (an
    // engine that is not in recovery never reaches this line), so a healthy account records nothing and the
    // pass's absence in the pack means "we were never in recovery", not "it did not run". The throw is
    // re-raised, so the pass's behaviour and the tick's outcome stay unchanged.
    try {
      await runControlPlaneAutoHeal(env, scheduler, budget, status);
      noteCronPass("auto-heal", true);
    } catch (e) {
      noteCronPass("auto-heal", false, e);
      throw e;
    }
  } catch (e) {
    log("error", `control-plane health pass skipped this tick: ${(e as Error).message}`);
  }
}

// notifyAutoHeal fires the redaction-safe AUTO-HEAL notification (account-level, no secret/config value).
// severity "warning" for the success notice (recovery happened; a confirm is owed) and for a refusal that is
// security-relevant (ambiguous/unsigned/unverifiable). The critical "control plane empty" alert already
// fired at detection, so this is the follow-up state, never a duplicate of the critical.
async function notifyAutoHeal(env: Env, scheduler: ReturnType<typeof schedulerStub>, detail: string): Promise<void> {
  const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
  await routeNotification(env, scheduler, {
    event: "posture-regression",
    severity: "warning",
    downpipeId: null,
    downpipeName: null,
    detail,
    at,
  });
}

// AutoHealRefusalCode is imported (not locally duplicated) from control-plane.ts, avoiding the drift risk of
// a hand-copied literal union kept in sync "by comment" with the canonical type -- exactly the kind of gap
// this module's own recovery logic exists to close. It is the ONE source.

// refuseAutoHeal records the unsafe-to-auto-apply verdict in the DO (stops the cron re-probing/re-alerting
// every tick) and, for a security-relevant refusal, fires one warning. The operator's manual break-glass
// reconcile (POST /admin/control-plane/restore) remains available regardless. `code` is the closed reason
// class stored alongside the free-text reason so the pack can diagnose signer-rotation vs a missing export.
async function refuseAutoHeal(
  env: Env,
  scheduler: ReturnType<typeof schedulerStub>,
  reason: string,
  alert: boolean,
  code: AutoHealRefusalCode,
  // The closed SUB-CAUSE (why, within the code) and the candidate SCAN (what the bucket actually held).
  // Both optional so a refusal with nothing to add is byte-compatible with the previous record.
  extra?: { subCause?: AutoHealSubCause; scan?: CandidateScan },
): Promise<void> {
  await scheduler.fetch(doURL("/control-plane/recovery-refused"), {
    method: "POST",
    body: JSON.stringify({ reason, code, ...(extra?.subCause !== undefined ? { subCause: extra.subCause } : {}), ...(extra?.scan !== undefined ? { scan: extra.scan } : {}) }),
  });
  if (alert) await notifyAutoHeal(env, scheduler, `control-plane auto-heal refused: ${reason}; run the manual break-glass reconcile`);
  log("error", `control-plane auto-heal refused [${code}${extra?.subCause !== undefined ? `/${extra.subCause}` : ""}]: ${reason}`);
}

// classifyUnsealFailure maps an openSealedControlPlaneExport throw onto the closed sub-cause. Without it,
// every one of these would land as refusedCode "shape-check", which erases the actual cause: an engine that
// is not a recipient at all (recovery must go OFFLINE with the break-glass identity, and no retry will EVER
// work) reads identically to a corrupt body. It reads the message ONLY to select an enum member and returns it.
function classifyUnsealFailure(e: unknown): AutoHealSubCause {
  const m = e instanceof Error ? e.message : typeof e === "string" ? e : "";
  if (/no wrap|not a recipient|no capsule|fingerprint/i.test(m)) return "not-recipient";
  if (/decapsulat|\bkem\b|ml-kem|x25519/i.test(m)) return "kem-fail";
  if (/not valid JSON|JSON/i.test(m)) return "body-corrupt";
  if (/not a control-plane export/i.test(m)) return "body-corrupt";
  // The AEAD is the residual: openStream / openCapsule failing to authenticate is what is left once the
  // capsule and the body have been excluded, and it is the "the ciphertext is corrupt, or the wrong key
  // opened it" arm.
  return "aead-fail";
}

// signatureSubCause turns a FAILED control-plane signature verification into its closed sub-cause,
// which is the split the "signature" refusal code has never been able to express: a truncated .sig file (take
// another copy), the wrong / rotated signer, a MIXED signer rotation (the classical half verifies and the
// post-quantum half does not, which cannot be random corruption), and this engine's own signer key failing to
// load (the key is broken, not the artefact). hybridVerifyDetailed is total and never throws.
async function signatureSubCause(bytes: Uint8Array, sig: string, verifier: HybridVerifier): Promise<AutoHealSubCause> {
  let raw: Uint8Array;
  try {
    raw = b64urlDecode(sig);
  } catch {
    return "sig-decode"; // the .sig text is not even base64url: a damaged file
  }
  const verdict = await hybridVerifyDetailed(verifier, bytes, raw);
  return verdict === "ok" ? "ed25519-mismatch" : verdict; // "ok" is unreachable here (the caller only calls on a failure)
}

// runControlPlaneAutoHeal is the SAFE auto-reconcile. After amnesia is latched, it scans the destination
// bucket's _RECOVERY/CONTROL-PLANE/ namespace, picks the latest signed export, VERIFIES it (signature
// against the engine's pinned signer + the no-custody assertion), STAGES it for the break-glass confirm,
// and auto-applies ONLY the no-authority RESUME slice (downpipes/schedules/dest) so backups resume. It NEVER
// restores RBAC, clears the latch or re-arms the first-Owner bootstrap -- authority stays gated. It REFUSES
// (steps back to manual) on any ambiguity, a missing/forged signature, or an older-generation-only bucket.
async function runControlPlaneAutoHeal(env: Env, scheduler: ReturnType<typeof schedulerStub>, budget: ReturnType<typeof budgetFromEnv>, status: RecoveryStatus): Promise<void> {
  // Record that the auto-heal RAN at all this tick. "Backups stopped after a wipe and never resumed"
  // is a pass that is latched and making NO progress, and every non-refusal exit below is a bare
  // `return` whose reason is swallowed or Workers-Logs-only: the pack shows staged + resumeApplied:false (or
  // nothing) with zero explanation.
  noteAutoHealAttempt();

  // FINISH-RESUME: if a verified export was already staged but the resume slice did not complete (e.g. the
  // Worker died between stage and resume-apply), just finish the resume -- no re-scan, no re-verify needed.
  if (status.staged !== null && !status.resumeApplied) {
    const resp = (await (await scheduler.fetch(doURL("/control-plane/resume-apply"), { method: "POST" })).json()) as { ok: boolean; downpipes?: number; reason?: string };
    if (resp.ok) await notifyAutoHeal(env, scheduler, `control-plane auto-recovered (config v${status.staged.version}): ${resp.downpipes ?? status.staged.downpipes} downpipe(s) restored, backups resumed; a break-glass confirm is required to restore operator access`);
    // The staged export is verified and the resume slice STILL refuses: the wedge that leaves a customer
    // permanently un-resumed. The DO's `reason` is FREE TEXT that can embed storage paths, so it is projected
    // through a closed code set at this boundary and the text is discarded.
    else noteResumeApplyRefusal(resp.reason);
    return;
  }

  // Without a signer we cannot VERIFY a candidate, and an unverified authority artefact must never be
  // auto-applied -- refuse to the manual path (where the operator can verify out of band).
  if (typeof env.SIGNER_PRIVATE !== "string" || env.SIGNER_PRIVATE.length === 0) {
    await refuseAutoHeal(env, scheduler, "the engine has no SIGNER_PRIVATE to verify a recovery export", true, "no-signer");
    return;
  }
  // Leave ample headroom: auto-heal is recovery hygiene that runs last; retry next tick if the budget is low.
  // On a crowded fleet this bail can fire EVERY tick, so the auto-heal literally never runs and the
  // recovery stays latched forever with no refusal, no marker and no explanation. Record the deferral.
  if (budget.remaining() < CONTROL_PLANE_AUTOHEAL_RESERVE) {
    noteAutoHealDeferral("budget-reserve");
    return;
  }

  // Resolve the same destination the health pass probed (default DO-stored, else env). A scan fault degrades
  // to "retry next tick" (we leave NO refusal marker, so a transient bucket blip is retried, not abandoned).
  let dest: Awaited<ReturnType<typeof buildDestination>>;
  try {
    const destCfg = await resolveDefaultDestConfig(env, scheduler, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
    dest = await buildDestination(env, undefined, destCfg);
  } catch (e) {
    // A destination that never resolves defers the auto-heal on EVERY tick with no durable marker (the
    // deliberate choice not to leave a refusal, so a transient blip is retried) -- which means a PERMANENT
    // fault is also invisible. The deferral class is the difference.
    noteAutoHealDeferral("dest-unresolvable");
    log("error", `control-plane auto-heal could not resolve a destination this tick: ${(e as Error).message}`);
    return;
  }

  // Scan + pick the latest signed export, REFUSING on any ambiguity (the engine cannot disambiguate after a
  // wipe), a missing signature, or a missing export. Each refusal is terminal (steps back to manual).
  budget.spend(CONTROL_PLANE_AUTOHEAL_RESERVE);
  const keys = await dest.list(CONTROL_PLANE_PREFIX);
  // The CENSUS of what is actually in the recovery namespace, computed ONCE and attached to every
  // refusal below. It turns "no signed control-plane export was found" from an unfalsifiable claim
  // into a checkable one: artefactsSeen > 0 with malformedNames == artefactsSeen means the bucket is FULL of
  // recovery artefacts and not one of them parses as a generation (a hand-renamed artefact, silently ignored),
  // which is a completely different problem from an empty bucket even though both land on the same refusal.
  const scan = scanControlPlaneCandidates(keys);

  // The SEALED regime SUPERSEDES plaintext: if any sealed generation exists, use it and ignore the (soon
  // purged) plaintext ones -- this also sidesteps a plaintext-vs-sealed version collision during the enable
  // transition. Unsealing needs the OPERATIONAL private (the break-glass private is never in-account); in the
  // break-glass-only posture the engine cannot open a sealed export, so the auto-heal refuses with a clear
  // offline-reader steer (the operator opens it with `downpipe unseal-export` and reconciles by hand). The DO
  // cannot unseal (no key in the DO), so the cron verifies + unseals here, then RE-SIGNS the recovered inner
  // with the engine signer for staging (the DO's apply-staged re-verifies a PLAINTEXT-export signature).
  const sealedCandidate = selectLatestSealedControlPlaneExport(keys);
  if (sealedCandidate.kind !== "none") {
    if (sealedCandidate.kind === "ambiguous") {
      await refuseAutoHeal(env, scheduler, `multiple conflicting SEALED recovery exports claim the latest generation (config v${sealedCandidate.version}); cannot disambiguate safely after a wipe`, true, "ambiguous", { scan });
      return;
    }
    if (sealedCandidate.kind === "unsigned") {
      await refuseAutoHeal(env, scheduler, `the latest SEALED recovery export (config v${sealedCandidate.version}) has no detached signature`, true, "unsigned", { scan });
      return;
    }
    // The CONFIG recipient private, with no operational fallback. This is the whole point of the change: a
    // break-glass-only engine auto-heals its own configuration, because opening the config export no longer
    // requires a key that opens archives.
    const configPrivate = typeof env.CONFIG_RECIPIENT_PRIVATE === "string" && env.CONFIG_RECIPIENT_PRIVATE.length > 0 ? env.CONFIG_RECIPIENT_PRIVATE : null;
    if (configPrivate === null) {
      // The export is sealed to the break-glass and config publics the engine held when it sealed it
      // (loadControlPlaneExportRecipients). A key install now puts in a NEW config key (attach.ts keeps only
      // a key the engine holds), which cannot open this export, so the remedy named is the offline one.
      await refuseAutoHeal(env, scheduler, "the latest recovery export is sealed and this engine holds no config recipient key to open it. Recover this export offline with your break-glass identity.key and the downpipe reader's unseal-export, then reconcile. A configuration key that you add now opens only the exports that this engine seals after you add it", true, "sealed-no-op-key", { scan });
      return;
    }
    const sJson = await dest.get(sealedCandidate.jsonKey);
    const sSig = await dest.get(sealedCandidate.sigKey);
    if (sJson === null || sSig === null) {
      await refuseAutoHeal(env, scheduler, "the latest sealed recovery export or its signature could not be read back", true, "unreadable", { scan });
      return;
    }
    const signer = await loadSigner(env.SIGNER_PRIVATE);
    let exp: ControlPlaneExport;
    let innerSig: string;
    try {
      const parsedSealed = JSON.parse(new TextDecoder().decode(sJson.body)) as unknown;
      if (!isSealedControlPlaneExport(parsedSealed)) {
        await refuseAutoHeal(env, scheduler, "the latest sealed recovery export is not a sealed control-plane export artefact", true, "shape-check", { subCause: "shape-field", scan });
        return;
      }
      const sealedSig = new TextDecoder().decode(sSig.body).trim();
      // VERIFY the sealed signature (over the sealed object) BEFORE unsealing -- verify precedes decrypt.
      if (!(await verifySealedControlPlaneSignature(parsedSealed, sealedSig, verifierFrom(signer)))) {
        // A truncated .sig, a rotated signer and a genuine tamper would all land on this ONE code without a
        // sub-cause. The sub-cause separates "re-copy the signature file" from "you are checking against the
        // wrong key" from "someone modified your recovery artefact".
        const subCause = await signatureSubCause(serialiseSealedControlPlaneExport(parsedSealed), sealedSig, verifierFrom(signer));
        await refuseAutoHeal(env, scheduler, `the latest sealed recovery export (config v${sealedCandidate.version}) failed signature verification`, true, "signature", { subCause, scan });
        return;
      }
      // UNSEAL with the CONFIG recipient key + RE-SIGN the inner for the DO's plaintext-verify apply-staged.
      const resolved = await unsealAndResignForAutoHeal(parsedSealed, signer, loadIdentity(configPrivate));
      exp = resolved.exp;
      innerSig = resolved.innerSig;
    } catch (e) {
      // The UNSEAL failure. Without classification, every one of these would land as a bare "shape-check",
      // erasing the fact that the engine may simply NOT BE A RECIPIENT of the capsule -- a state in which no
      // retry can ever succeed and recovery must go offline with the break-glass identity. The classifier reads the throw
      // only to select the closed member and returns it; the message never persists.
      await refuseAutoHeal(env, scheduler, `the latest sealed recovery export failed to open: ${(e as Error).message}`, true, "shape-check", { subCause: classifyUnsealFailure(e), scan });
      return;
    }
    if (!candidateVersionMatchesExport(sealedCandidate, exp)) {
      await refuseAutoHeal(env, scheduler, `the latest sealed recovery export's filename version (v${sealedCandidate.version}) does not match its signed configVersion (v${exp.configVersion}); refusing a possible stale-export replay`, true, "version-mismatch", { subCause: "version-pin", scan });
      return;
    }
    const staged: StagedControlPlane = { export: exp, signature: innerSig, sourceKey: sealedCandidate.jsonKey, version: sealedCandidate.version, stagedAt: new Date().toISOString(), resumeApplied: false };
    await scheduler.fetch(doURL("/control-plane/stage"), { method: "POST", body: JSON.stringify({ staged }) });
    const resp = (await (await scheduler.fetch(doURL("/control-plane/resume-apply"), { method: "POST" })).json()) as { ok: boolean; downpipes?: number; reason?: string };
    if (!resp.ok) {
      noteResumeApplyRefusal(resp.reason);
      log("error", `control-plane auto-heal staged the sealed export but the resume slice did not apply this tick: ${resp.reason ?? "unknown"}; it will be retried next tick`);
      return;
    }
    await notifyAutoHeal(env, scheduler, `control-plane auto-recovered from a SEALED signed export (config v${sealedCandidate.version}): ${resp.downpipes ?? exp.downpipes.length} downpipe(s) restored, backups resumed; a break-glass confirm is required to restore operator access`);
    log("info", `control-plane auto-heal: staged + resumed from sealed ${sealedCandidate.jsonKey} (config v${sealedCandidate.version}); authority gated behind break-glass confirm`);
    return;
  }

  const candidate = selectLatestControlPlaneExport(keys);
  if (candidate.kind === "none") {
    // The scan rides here above all: "no export was found" and "the bucket is full of artefacts and not one of
    // them parses as a generation" (a hand-renamed artefact -- an operator tidying a bucket disarming their own
    // recovery) were the SAME refusal, and the second one is a fault the customer can fix in a minute.
    await refuseAutoHeal(env, scheduler, "no signed control-plane export was found in the destination bucket", false, "no-export", { scan });
    return;
  }
  if (candidate.kind === "ambiguous") {
    await refuseAutoHeal(env, scheduler, `multiple conflicting recovery exports claim the latest generation (config v${candidate.version}); cannot disambiguate safely after a wipe`, true, "ambiguous", { scan });
    return;
  }
  if (candidate.kind === "unsigned") {
    await refuseAutoHeal(env, scheduler, `the latest recovery export (config v${candidate.version}) has no detached signature`, true, "unsigned", { scan });
    return;
  }

  // Fetch + VERIFY: parse the body, shape-gate it, re-assert no-custody (never import an artefact carrying a
  // plaintext secret), and verify the detached signature against the engine's PINNED signer. Any failure is
  // a refusal -- the auto-heal never falls back to an older generation (a downgrade vector).
  const jsonObj = await dest.get(candidate.jsonKey);
  const sigObj = await dest.get(candidate.sigKey);
  if (jsonObj === null || sigObj === null) {
    await refuseAutoHeal(env, scheduler, "the latest recovery export or its signature could not be read back", true, "unreadable", { scan });
    return;
  }
  let exp: ControlPlaneExport;
  try {
    const parsed = JSON.parse(new TextDecoder().decode(jsonObj.body)) as unknown;
    if (!isControlPlaneExport(parsed)) {
      // shape-field says a structural field failed; it never says WHICH (the free-text reason that names
      // it can embed a JSON path into the artefact's own content, and stays unprojected).
      await refuseAutoHeal(env, scheduler, "the latest recovery export is not a control-plane export artefact", true, "shape-check", { subCause: "shape-field", scan });
      return;
    }
    assertNoPlaintextSecretInExport(parsed);
    exp = parsed;
  } catch (e) {
    // A JSON parse fault is a TRUNCATED object (a half-written PUT), which is a different remedy from a
    // producer/consumer shape drift; both were "shape-check" and nothing else.
    const subCause: AutoHealSubCause = e instanceof SyntaxError ? "json-parse" : "shape-field";
    await refuseAutoHeal(env, scheduler, `the latest recovery export failed the no-custody/shape check: ${(e as Error).message}`, true, "shape-check", { subCause, scan });
    return;
  }
  const signature = new TextDecoder().decode(sigObj.body).trim();
  const signer = await loadSigner(env.SIGNER_PRIVATE);
  const sigOk = await verifyControlPlaneSignature(exp, signature, verifierFrom(signer));
  if (!sigOk) {
    const subCause = await signatureSubCause(serialiseControlPlaneExport(exp), signature, verifierFrom(signer));
    await refuseAutoHeal(env, scheduler, `the latest recovery export (config v${candidate.version}) failed signature verification`, true, "signature", { subCause, scan });
    return;
  }
  // VERSION-CONSISTENCY: candidate.version came from the UNAUTHENTICATED bucket-key filename (selection
  // input a bucket-write attacker controls); exp.configVersion is inside the signed body. A real signature
  // over real bytes still verifies when an old, genuine export is copied to a NEW key with a fabricated
  // higher version -- selection and signature verification alone cannot tell "latest" from "relabelled
  // replay". Refuse rather than stage a generation whose own signed content disagrees with the name it was
  // picked by.
  if (!candidateVersionMatchesExport(candidate, exp)) {
    await refuseAutoHeal(env, scheduler, `the latest recovery export's filename version (v${candidate.version}) does not match its signed configVersion (v${exp.configVersion}); refusing a possible stale-export replay`, true, "version-mismatch", { subCause: "version-pin", scan });
    return;
  }

  // STAGE the verified export for the break-glass confirm, then auto-apply the NO-AUTHORITY resume slice.
  const staged: StagedControlPlane = { export: exp, signature, sourceKey: candidate.jsonKey, version: candidate.version, stagedAt: new Date().toISOString(), resumeApplied: false };
  await scheduler.fetch(doURL("/control-plane/stage"), { method: "POST", body: JSON.stringify({ staged }) });
  const resp = (await (await scheduler.fetch(doURL("/control-plane/resume-apply"), { method: "POST" })).json()) as { ok: boolean; downpipes?: number; destinations?: number; reason?: string };
  if (!resp.ok) {
    // The plaintext-export resume refusal, projected through the same closed code set as the sealed one.
    noteResumeApplyRefusal(resp.reason);
    log("error", `control-plane auto-heal staged the export but the resume slice did not apply this tick: ${resp.reason ?? "unknown"}; it will be retried next tick`);
    return;
  }
  await notifyAutoHeal(env, scheduler, `control-plane auto-recovered from a signed export (config v${candidate.version}): ${resp.downpipes ?? exp.downpipes.length} downpipe(s) restored, backups resumed; a break-glass confirm is required to restore operator access`);
  log("info", `control-plane auto-heal: staged + resumed from ${candidate.jsonKey} (config v${candidate.version}); ${resp.downpipes ?? exp.downpipes.length} downpipe(s) restored, authority gated behind break-glass confirm`);
}
