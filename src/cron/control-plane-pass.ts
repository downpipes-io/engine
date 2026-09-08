// INFRA-1 (FIX-PLAN §4) -- the cron passes that keep the control plane RECOVERABLE and detect amnesia.
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

import { envFlagEnabled } from "../admin/auth.ts";
import { loadConfigWrapKey } from "../admin/config-secret.ts";
import {
  type AutoHealRefusalCode,
  type AutoHealSubCause,
  assertNoPlaintextSecretInExport,
  type CandidateScan,
  CONTROL_PLANE_PREFIX,
  type ControlPlaneExport,
  type ControlPlaneExportState,
  candidateVersionMatchesExport,
  controlPlaneArtefactKey,
  controlPlaneDestCredFingerprint,
  controlPlaneRecipientPinHash,
  isControlPlaneExport,
  plaintextGenerationKeysToPurge,
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
import { buildDestination, fetchDestConfig } from "../dest/factory.ts";
import type { Env } from "../env.d.ts";
import { readVerifiedRunlogMaxIndex } from "../format/freshness.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { loadIdentity, loadRecipients, loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import type { budgetFromEnv } from "../seal/budget.ts";
import {
  type CpExportFailClass,
  classifyCpExportFail,
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
    // G220: this empty catch meant the amnesia-probe field could go silently STALE -- the pack would show a
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
  health: { skipped?: "no-signer" | "budget-yield" | "no-destination" | "unchanged" | "empty-recipient-set"; wroteAny: boolean; configVersion?: number; perDest: Array<{ id: string; ok: boolean; reason?: CpExportFailClass }>; recipientPinDrift?: { matches: boolean; added: number; removed: number } },
): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/control-plane/export-health"), {
      method: "POST",
      body: JSON.stringify({ at: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"), ...health }),
    });
    // G292: the response was never READ, so a non-2xx passed for a write. When THIS record is lost the pack
    // shows a STALE export health as if it were this tick's verdict -- on the recovery path, a lie by omission.
    if (!resp.ok) noteCpExportRecordWriteFailure();
  } catch {
    // observability only -- but the LOSS itself is now recorded (the pack must never read a stale record as fresh).
    noteCpExportRecordWriteFailure();
  }
}

export async function runControlPlaneExportPass(env: Env, scheduler: ReturnType<typeof schedulerStub>, budget: ReturnType<typeof budgetFromEnv>): Promise<void> {
  // G292: the pass RAN. Every bail below is honest, but the record it writes is indistinguishable from the one
  // a healthier tick left behind, so "export health is all-ok but this destination's artefact is generations
  // old" had no thread to pull. lastAttemptAt is that thread.
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
      operational: await envRecipientFingerprint(env.OPERATIONAL_PUBLIC),
      config: await envRecipientFingerprint(env.CONFIG_RECIPIENT_PUBLIC),
    };
    const recipientPinHash = await controlPlaneRecipientPinHash(recipientPin);
    const pinMoved = lastState !== null && (lastState.recipientPinHash ?? "") !== recipientPinHash;
    if (lastState !== null && lastState.configContentHash === exp.configContentHash && (lastState.destCredHash ?? "") === destCredHash && !pinMoved) {
      await recordExportHealth(scheduler, { skipped: "unchanged", wroteAny: false, configVersion: exp.configVersion, perDest: [] });
      return;
    }

    const signer = await loadSigner(env.SIGNER_PRIVATE);
    // S5: seal the export body BY DEFAULT whenever a break-glass recipient is configured (always true on a
    // ready engine), so a destination-bucket reader never sees the roster/topology. Opt out with
    // CONTROL_PLANE_EXPORT_SEALING_DISABLED=1, which is a narrow escape hatch and no longer the
    // break-glass-only workaround it once was: a sealed export is opened with the CONFIG recipient key
    // (below, and control-plane-seal.ts), which the break-glass-only switch does not remove, so auto-heal
    // runs in EITHER posture and this flag is not the way to get it.
    // recipients undefined => the signed plaintext. The sealed artefact goes under
    // a distinct `.sealed.json` key. buildControlPlaneArtefactToWrite is the single seal-or-plaintext decision.
    const sealing = typeof env.BREAK_GLASS_PUBLIC === "string" && env.BREAK_GLASS_PUBLIC.length > 0 && !envFlagEnabled(env.CONTROL_PLANE_EXPORT_SEALING_DISABLED);
    // The second recipient is the CONFIG recipient, and nothing else: the "operational key as a legacy
    // fallback" this comment used to describe was removed, as the paragraph four lines down already says in
    // as many words. The export was sealed to the ARCHIVE recipient set by accident of history rather
    // than by design, which coupled config recovery to a key that also opens customer archives: a
    // break-glass-only engine could not open its own configuration and had to be rebuilt offline. A
    // dedicated recipient breaks that coupling, and the engine then holds a key that opens its own
    // configuration and nothing else.
    //
    // Break-glass stays recipient #0, so the offline reader's unseal-export is unaffected and an operator
    // holding only their offline key still recovers their configuration.
    //
    // There is deliberately NO fallback to OPERATIONAL_PUBLIC here. The key ceremony generates the config
    // recipient unconditionally, in both postures, so an engine without one is an engine that was never
    // keyed rather than an older engine to be accommodated. A fallback would quietly re-couple config
    // recovery to the archive key for exactly the estates that chose to remove it.
    const recipients = sealing ? loadRecipients(env.BREAK_GLASS_PUBLIC as string, env.CONFIG_RECIPIENT_PUBLIC, "config") : undefined;
    // G218: the EMPTY-RECIPIENT-SET skip. sealControlPlaneExport THROWS on zero recipients ("cannot seal a
    // control-plane export to zero recipients"), and that throw escapes into the pass-level catch, which
    // records a generic pass fault -- so an engine that is sealing-enabled and has no usable recipient writes
    // NO recovery artefact at all, every tick, forever, and the export-health record simply never advances.
    // "No signed export of your configuration has been written yet" is what the posture check says, and the
    // reason it will never be written is not anywhere. Named as its own skip code: a closed, actionable state
    // (run the key ceremony) rather than an unexplained absence.
    if (sealing && (recipients === undefined || recipients.length === 0)) {
      await recordExportHealth(scheduler, { skipped: "empty-recipient-set", wroteAny: false, configVersion: exp.configVersion, perDest: [] });
      log("error", "control-plane export skipped: sealing is enabled and no recipient public key resolved, so no recovery artefact can be written");
      return;
    }
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
    // already in the signed export, and the check only needs to know that the set moved.
    const priorPinKnown = lastState !== null && typeof lastState.recipientPinHash === "string";
    const drift = priorPinKnown ? { matches: !pinMoved, added: pinMoved ? 1 : 0, removed: 0 } : undefined;
    const artefact = await buildControlPlaneArtefactToWrite(exp, signer, recipients, () => crypto.getRandomValues(new Uint8Array(16)));
    const body = artefact.bodyBytes;
    const sig = artefact.sigText;
    const baseKey = controlPlaneArtefactKey(exp.configVersion, exp.exportedAt);
    const key = artefact.sealed ? sealedArtefactKey(baseKey) : baseKey;
    const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);

    // Write to EVERY destination (each is a self-contained archive store, so the recovery artefact must
    // live alongside the runs in each). A per-destination fault is logged, RECORDED (per-dest ok:false) and
    // skipped; one good write is enough to record the export (the next change re-attempts the laggards).
    let wroteAny = false;
    // G202: perDest carried ok:false and NOTHING ELSE, so the posture check's "some copies of your
    // configuration are stale or missing" could not name WHICH destination, let alone WHY. The class is
    // selected from the fault by the same classifier the aggregate counter already uses (classifyCpExportFail);
    // the store's message, the endpoint, the bucket and the object key never leave that function.
    const perDest: Array<{ id: string; ok: boolean; reason?: CpExportFailClass }> = [];
    for (const [i, ed] of exp.destinations.entries()) {
      if (budget.remaining() < CONTROL_PLANE_EXPORT_PER_DEST) {
        // G292: the budget BREAK leaves every remaining destination with NO perDest row at all, so the record
        // reads COMPLETE while some destinations keep a generations-old recovery artefact. Record the
        // truncation and how many destinations never got their turn.
        noteCpExportTruncated(exp.destinations.length - i);
        break;
      }
      try {
        const destCfg = await fetchDestConfig(scheduler, ed.id, wrapKey);
        const dest = await buildDestination(env, undefined, destCfg);
        await dest.put(key, body);
        await dest.put(`${key}.sig`, utf8(sig));
        budget.spend(CONTROL_PLANE_EXPORT_PER_DEST);
        wroteAny = true;
        perDest.push({ id: ed.id, ok: true });
        // S5.3: the sealed export is now in THIS destination, so purge its readable plaintext generations
        // (best effort). Ordered after the successful sealed put, so a destination never loses its only
        // recovery artefact; a WORM/object-lock denial leaves the plaintext (the off-account floor guards it).
        if (artefact.sealed) {
          try {
            const purge = plaintextGenerationKeysToPurge(await dest.list(CONTROL_PLANE_PREFIX));
            let purged = 0;
            for (const pk of purge) {
              if (budget.remaining() < 1) break;
              await dest.delete(pk);
              budget.spend(1);
              purged++;
            }
            if (purged > 0) log("info", `control-plane sealing: purged ${purged} plaintext recovery key(s) from destination ${ed.id}`);
            // G292: whatever is LEFT is readable plaintext control-plane state (the roster + topology) sitting
            // in a bucket the customer believes is sealed -- a WORM/object-lock denial, or a budget stop. The
            // debt was recorded NOWHERE. A count only; never a key.
            noteCpPlaintextPurgePending(purge.length - purged);
          } catch (pe) {
            // The purge threw: the plaintext generations are still there, and how many is unknown -- record at
            // least one outstanding, so the debt is never silently zero.
            noteCpPlaintextPurgePending(1);
            log("error", `control-plane sealing: could not purge plaintext recovery generations in destination ${ed.id} (object-lock, or a transient error): ${(pe as Error).message}`);
          }
        }
      } catch (e) {
        perDest.push({ id: ed.id, ok: false, reason: classifyCpExportFail(e) });
        // G292: ok:false with no WHY. A WORM policy refusing the overwrite (permanent; needs a new key scheme),
        // a rotated CONFIG_WRAP_KEY (the credential cannot be opened at all) and a network blip (self-healing)
        // were one signal. The class is selected from the fault and the message is discarded here.
        noteCpExportDestFail(e);
        log("error", `control-plane export to destination ${ed.id} skipped this tick: ${(e as Error).message}`);
      }
    }
    if (wroteAny) {
      await scheduler.fetch(doURL("/control-plane/export-recorded"), {
        method: "POST",
        body: JSON.stringify({ configVersion: exp.configVersion, configContentHash: exp.configContentHash, exportedAt: exp.exportedAt, destCredHash, recipientPinHash }),
      });
      log("info", `control-plane export written (version ${exp.configVersion}) to ${exp.destinations.length} destination(s)`);
    }
    // Record the per-destination outcome regardless of wroteAny (a total per-dest failure is the loudest
    // signal: the export ran but every destination rejected the recovery artefact).
    await recordExportHealth(scheduler, { wroteAny, configVersion: exp.configVersion, perDest, ...(drift !== undefined ? { recipientPinDrift: drift } : {}) });
  } catch (e) {
    // G292: a pass-level throw BYPASSES recordExportHealth entirely, so the last-written record is a previous,
    // healthier tick's and the pack reads it as current. Record the throw itself (the health record cannot be
    // written from here without inventing a per-dest view the pass never reached).
    noteCpExportPassThrew();
    log("error", `control-plane export pass skipped this tick: ${(e as Error).message}`);
  }
}

// runDeployObservePass drives the DETERMINISTIC per-tick deploy-identity observation (CPR needs-logging:
// version-change-observation-gated / -first-poll-baseline / cfversionid-absent-redeploy-invisible). Unlike
// the GET /admin/status diff (which only records a deploy when someone polls status), this runs EVERY cron
// tick, so a deploy that silently dropped a live source binding (owner-#1) is recorded even on an unattended
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

    if (!status.recoveryRequired) {
      // The plane is not empty => healthy, nothing to do (the cheap common case: one DO read).
      if (!status.configEmpty) {
        await recordAmnesiaProbe(scheduler, "not-empty");
        return;
      }

      // DETECT: resolve a destination to probe (the default DO-stored one, else the env destination). A
      // full wipe with only console-set destinations resolves none => we cannot detect via the bucket. That
      // blind spot previously left NO signal; record it as `no-resolvable-dest` (un-probeable amnesia) so the
      // support pack sees "plane empty but nothing to probe", never a false "healthy".
      let dest: Awaited<ReturnType<typeof buildDestination>>;
      try {
        const destCfg = await fetchDestConfig(scheduler, null, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
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

      // RUNLOG-FORKS-ON-THE-RECOVERY-PATH: the rebuilt DO holds no runlogCounter, so
      // the very next trigger would allocate index 1 into a bucket the exists() probe above just proved
      // already holds a RUNLOG -- forking the log on the first post-recovery run and disarming the
      // anti-rollback pin every attest call reads (both source the same counter). Read the bucket's own
      // RUNLOG now, verified under the operator's pinned signer, and carry its high-water mark into the
      // latch so the DO can anchor the counter before any trigger allocates. Signature-gated + fail-soft:
      // an unreadable or unsigned document yields no seed, and recovery proceeds exactly as it did before
      // this change (never worse than today; only ever a floor raised on the evidence just read). No signer
      // configured => no seed, same as any other unverifiable case (mirrors the export pass's own guard).
      const runlogSeed =
        typeof env.SIGNER_PRIVATE === "string" && env.SIGNER_PRIVATE.length > 0
          ? await readVerifiedRunlogMaxIndex((key) => dest.get(key).then((r) => r?.body ?? null), verifierFrom(await loadSigner(env.SIGNER_PRIVATE)))
          : null;

      const reason = "the control plane is empty but the destination bucket still holds backups -- the scheduler control plane appears to have been lost; backups have STOPPED until it is recovered";
      // Latch recovery-required in the DO (blocks the silent re-bootstrap; writes the critical audit event;
      // seeds runlogCounter from runlogSeed when one was established).
      await scheduler.fetch(doURL("/control-plane/recovery-required"), { method: "POST", body: JSON.stringify({ reason, ...(runlogSeed !== null ? { runlogSeed } : {}) }) });
      // Fire a CRITICAL notification (reuse the posture-regression event with an explicit critical severity:
      // a lost control plane IS a posture regression, and this avoids a new event type). Account-level, so
      // downpipeId/downpipeName are null; the detail is redaction-safe (no secret, no config value).
      const at = new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
      // G184: the recovery-required LATCH is already set above, so this pass will not re-enter the detection
      // branch on the next tick -- which means an undelivered alert here is the ONE page the customer ever gets
      // about a WIPED control plane, lost. The delivered boolean was discarded; latch the loss instead.
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
    // G132: the auto-heal is one of the CLOSED cron passes and it had no producer, because it runs INSIDE the
    // cp-health pass and so was only ever attributed to that pass's name. A throw here (the recovery scan, the
    // stage, the resume-apply round trip) is swallowed by the catch below, which is deliberately fail-open --
    // and the result is that "backups stopped after a wipe and never resumed" could not be attributed to the
    // one pass whose whole job is to make them resume. Recorded ONLY when the auto-heal ACTUALLY RUNS (an
    // engine that is not in recovery never reaches this line), so a healthy account records nothing and the
    // pass's absence in the pack means "we were never in recovery", not "it did not run". The throw is
    // re-raised, so the pass's behaviour and the tick's outcome are byte-for-byte what they were.
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

// AutoHealRefusalCode is imported (not locally duplicated) from control-plane.ts -- it used to be a
// hand-copied literal union here, kept in sync "by comment" with the canonical type; that drift risk is
// exactly the kind of gap this module's own recovery logic exists to close, so it is now the ONE source.

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
  // G218: the closed SUB-CAUSE (why, within the code) and the candidate SCAN (what the bucket actually held).
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

// classifyUnsealFailure (G218) maps an openSealedControlPlaneExport throw onto the closed sub-cause. Today
// EVERY one of these lands as refusedCode "shape-check", which erases the actual cause: an engine that is not
// a recipient at all (recovery must go OFFLINE with the break-glass identity, and no retry will EVER work)
// reads identically to a corrupt body. It reads the message ONLY to select an enum member and returns it.
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

// signatureSubCause (G218) turns a FAILED control-plane signature verification into its closed sub-cause,
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
  // G220: record that the auto-heal RAN at all this tick. "Backups stopped after a wipe and never resumed"
  // is a pass that is latched and making NO progress, and today every non-refusal exit below is a bare
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
  // G220: on a crowded fleet this bail can fire EVERY tick, so the auto-heal literally never runs and the
  // recovery stays latched forever with no refusal, no marker and no explanation. Record the deferral.
  if (budget.remaining() < CONTROL_PLANE_AUTOHEAL_RESERVE) {
    noteAutoHealDeferral("budget-reserve");
    return;
  }

  // Resolve the same destination the health pass probed (default DO-stored, else env). A scan fault degrades
  // to "retry next tick" (we leave NO refusal marker, so a transient bucket blip is retried, not abandoned).
  let dest: Awaited<ReturnType<typeof buildDestination>>;
  try {
    const destCfg = await fetchDestConfig(scheduler, null, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
    dest = await buildDestination(env, undefined, destCfg);
  } catch (e) {
    // G220: a destination that never resolves defers the auto-heal on EVERY tick with no durable marker (the
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
  // G218: the CENSUS of what is actually in the recovery namespace, computed ONCE and attached to every
  // refusal below. It is what turns "no signed control-plane export was found" from an unfalsifiable claim
  // into a checkable one: artefactsSeen > 0 with malformedNames == artefactsSeen means the bucket is FULL of
  // recovery artefacts and not one of them parses as a generation (a hand-renamed artefact, silently ignored),
  // which is a completely different ticket from an empty bucket -- and they were the same refusal.
  const scan = scanControlPlaneCandidates(keys);

  // SEALED regime SUPERSEDES plaintext (S5): if any sealed generation exists, use it and ignore the (soon
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
      await refuseAutoHeal(env, scheduler, "the latest recovery export is sealed and this engine holds no config recipient key to open it; re-run the key ceremony, or recover offline with the downpipe reader's unseal-export and reconcile", true, "sealed-no-op-key", { scan });
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
        // G218: a truncated .sig, a rotated signer and a genuine tamper all landed on this ONE code. The
        // sub-cause is what separates "re-copy the signature file" from "you are checking against the wrong
        // key" from "someone modified your recovery artefact".
        const subCause = await signatureSubCause(serialiseSealedControlPlaneExport(parsedSealed), sealedSig, verifierFrom(signer));
        await refuseAutoHeal(env, scheduler, `the latest sealed recovery export (config v${sealedCandidate.version}) failed signature verification`, true, "signature", { subCause, scan });
        return;
      }
      // UNSEAL with the CONFIG recipient key + RE-SIGN the inner for the DO's plaintext-verify apply-staged.
      const resolved = await unsealAndResignForAutoHeal(parsedSealed, signer, loadIdentity(configPrivate));
      exp = resolved.exp;
      innerSig = resolved.innerSig;
    } catch (e) {
      // G218: the UNSEAL failure. Every one of these landed as a bare "shape-check", which erased the fact
      // that the engine may simply NOT BE A RECIPIENT of the capsule -- a state in which no retry can ever
      // succeed and recovery must go offline with the break-glass identity. The classifier reads the throw
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
      // G218: shape-field says a structural field failed; it never says WHICH (the free-text reason that names
      // it can embed a JSON path into the artefact's own content, and stays unprojected, as it always has).
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
    // G220: the plaintext-export resume refusal, projected through the same closed code set as the sealed one.
    noteResumeApplyRefusal(resp.reason);
    log("error", `control-plane auto-heal staged the export but the resume slice did not apply this tick: ${resp.reason ?? "unknown"}; it will be retried next tick`);
    return;
  }
  await notifyAutoHeal(env, scheduler, `control-plane auto-recovered from a signed export (config v${candidate.version}): ${resp.downpipes ?? exp.downpipes.length} downpipe(s) restored, backups resumed; a break-glass confirm is required to restore operator access`);
  log("info", `control-plane auto-heal: staged + resumed from ${candidate.jsonKey} (config v${candidate.version}); ${resp.downpipes ?? exp.downpipes.length} downpipe(s) restored, authority gated behind break-glass confirm`);
}
