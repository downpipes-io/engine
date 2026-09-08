// Support-pack section gatherers: the control-plane RECOVERY / EXPORT domain (the recovery/amnesia
// latch with its manual-refusal sibling, the estate-import outcome, the deploy-identity marker, the
// export pass's per-destination health, and the export-lag pointer). Moved verbatim out of
// support-sections-audit.ts, comments intact; support.ts assembles the bundle from these
// gatherers and each keeps its original redaction contract (see the per-function comments). Behaviour
// is unchanged.

import { CP_EXPORT_FAIL_CLASSES } from "../cron/cron-fault-ledger.ts";
import { doURL } from "../do-url.ts";
import { AUTO_HEAL_REFUSAL_CODES, AUTO_HEAL_SUB_CAUSES, EXPORT_SKIP_REASONS } from "./control-plane.ts";
import { RECOVERY_REFUSAL_CLASSES, RECOVERY_REFUSAL_SURFACES } from "./diag-records.ts";
import { clampInt, clampTs, gateClosed, UNKNOWN_CODE } from "./support-shared.ts";

// fetchRecoveryStatus pulls the control-plane RECOVERY / AMNESIA latch into the pack: whether recovery is
// required (a wiped scheduler DO while live archives remain, the loudest fault there is), the coarse
// reason, whether the stored plane is empty, and the staged-recovery generation. Booleans / counts / a
// version / a coarse reason only, redaction-safe. Without it the entire amnesia + auto-heal + staged-resume
// lifecycle was invisible in the bundle (catalogue: audit/control-plane/recovery domain). Best-effort: {} on failure.
// The CLOSED vocabularies the recovery projection forwards (defence-in-depth: anything outside the set is
// dropped, never propagated, so a future DO change cannot leak a free-text value into the pack).
const AMNESIA_PROBE_CODES: ReadonlySet<string> = new Set(["not-empty", "runs-present", "runlog-absent", "probe-error", "no-resolvable-dest"]);
// Bound to the canonical AUTO_HEAL_REFUSAL_CODES tuple in control-plane.ts, NOT re-listed here: a new
// refusal reason added there rides into the pack automatically instead of being silently dropped (as
// "sealed-no-op-key" was before this binding). validate-support-autoheal-codes pins the two together.
const AUTOHEAL_REFUSAL_CODES: ReadonlySet<string> = new Set(AUTO_HEAL_REFUSAL_CODES);
// G218: the sub-cause + skip vocabularies, bound to their canonical tuples for the SAME reason the refusal
// codes are -- a hand-listed copy is exactly how "empty-recipient-set" (an engine that can NEVER write a
// recovery artefact) would be silently dropped at this boundary while the recorder happily wrote it. The
// hand-listed EXPORT_SKIP_CODES set had already gone stale relative to its own type; it is now bound too.
const AUTOHEAL_SUB_CAUSES: ReadonlySet<string> = new Set(AUTO_HEAL_SUB_CAUSES);
const EXPORT_SKIP_CODES: ReadonlySet<string> = new Set(EXPORT_SKIP_REASONS);
// G202: the per-destination export-fault classes, and the recovery-refusal vocabularies, taken from the
// modules that CLASSIFY, so the pack's gate and the classifier cannot drift apart.
const CP_EXPORT_FAIL_CLASS_SET: ReadonlySet<string> = new Set(CP_EXPORT_FAIL_CLASSES);
const RECOVERY_REFUSAL_KEY_SET: ReadonlySet<string> = new Set(
  RECOVERY_REFUSAL_SURFACES.flatMap((surface) => RECOVERY_REFUSAL_CLASSES.map((cls) => `${surface}|${cls}`)),
);
const RECOVERY_REFUSAL_SURFACE_SET: ReadonlySet<string> = new Set(RECOVERY_REFUSAL_SURFACES);
const RECOVERY_REFUSAL_CLASS_SET: ReadonlySet<string> = new Set(RECOVERY_REFUSAL_CLASSES);

// fetchRecoveryRefusals (G202) reads the bounded manual-recovery refusal aggregate. It is fetched as a
// SIBLING of the recovery status (below) and folded into the same section, because it answers the same
// question from the other side: recovery-status says what the AUTOMATIC heal did, and this says what happened
// every time a human tried to do it by hand -- which, on the disaster-recovery path, is the half that was
// invisible. Best-effort: {} when no manual recovery has ever been refused (honest absence, and the good state).
async function fetchRecoveryRefusals(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  try {
    const j = (await (await scheduler.fetch(doURL("/recovery-refusals"), { method: "GET" })).json()) as { refusals?: unknown };
    const r = (typeof j.refusals === "object" && j.refusals !== null ? j.refusals : null) as Record<string, unknown> | null;
    if (r === null) return {};
    const bySurfaceClass: Record<string, number> = {};
    for (const [k, v] of Object.entries((typeof r.bySurfaceClass === "object" && r.bySurfaceClass !== null ? r.bySurfaceClass : {}) as Record<string, unknown>)) {
      if (!RECOVERY_REFUSAL_KEY_SET.has(k)) continue;
      const n = clampInt(v, 1_000_000) ?? 0;
      if (n > 0) bySurfaceClass[k] = n;
    }
    const total = clampInt(r.total, 1_000_000) ?? 0;
    if (total === 0 && Object.keys(bySurfaceClass).length === 0 && r.stagedMalformed !== true) return {};
    return {
      ...(Object.keys(bySurfaceClass).length > 0 ? { bySurfaceClass } : {}),
      total,
      ...(gateClosed(r.lastSurface, RECOVERY_REFUSAL_SURFACE_SET) !== undefined ? { lastSurface: gateClosed(r.lastSurface, RECOVERY_REFUSAL_SURFACE_SET) } : {}),
      // lastClass is the field this gap turns on: "verify-threw" (the recovery KIT is damaged; take another
      // copy) against "signature" (the EXPORT does not match the key; wrong kit, or someone altered it). Those
      // are opposite diagnoses and they used to be the same refusal.
      ...(gateClosed(r.lastClass, RECOVERY_REFUSAL_CLASS_SET) !== undefined ? { lastClass: gateClosed(r.lastClass, RECOVERY_REFUSAL_CLASS_SET) } : {}),
      ...(clampTs(r.lastAt) !== undefined ? { lastAt: clampTs(r.lastAt) } : {}),
      // stagedMalformed is a STANDING condition, not a history: the export the auto-heal parked is corrupt, so
      // the break-glass confirm 409s FOREVER until it is re-staged. No number of retries will change it, and
      // the operator has no way to know that from the 409 alone.
      ...(r.stagedMalformed === true ? { stagedMalformed: true } : {}),
    };
  } catch {
    return {}; // the refusal record is best-effort: it must never break the recovery section it rides in
  }
}

export async function fetchRecoveryStatus(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    // G202: the MANUAL-path refusals ride in this same section (see fetchRecoveryRefusals). They are gathered
    // first, so an unreadable recovery-status still carries them: on the disaster-recovery path the manual
    // refusals may be the only evidence there is, and losing them to a fault in the AUTOMATIC record's read
    // would be the exact inversion of what this pack is for.
    const recoveryRefusals = await fetchRecoveryRefusals(scheduler);
    const r = await scheduler.fetch(doURL("/control-plane/recovery-status"), { method: "GET" });
    const j = (await r.json()) as {
      recoveryRequired?: boolean; reason?: string; configEmpty?: boolean; resumeApplied?: boolean; refused?: unknown; refusedCode?: unknown; refusedSubCause?: unknown; refusedScan?: unknown;
      lastImport?: { at?: unknown; crossAccount?: unknown; accountIdAbsent?: unknown; downpipesDisabled?: unknown; downpipes?: unknown; destinations?: unknown } | null;
      amnesiaProbe?: { probe?: unknown; at?: unknown } | null;
      deploy?: { engineVersion?: unknown; cfVersionId?: unknown; cfVersionIdAbsent?: unknown; baselineEstablished?: unknown; changesObserved?: unknown; firstSeenAt?: unknown; lastSeenAt?: unknown; lastChangeAt?: unknown } | null;
      exportHealth?: { at?: unknown; skipped?: unknown; wroteAny?: unknown; configVersion?: unknown; perDest?: unknown; perDestTotal?: unknown; perDestTruncated?: unknown } | null;
      staged?: { version?: number; stagedAt?: string; downpipes?: number; resumeApplied?: boolean; resumeSkipped?: number; appliedVersion?: number; appliedAt?: string } | null;
    };
    // `refused` is projected to a COARSE BOOLEAN, never forwarded whole. The DO's refused object carries a
    // free-text `reason` that, on the no-custody/shape-check refusal path, can embed a secret FIELD NAME and
    // a storage JSON-path (or a JSON parse-error snippet). The top-level `reason` above is the STATIC latch
    // reason (safe); the refusal reason is not, so we surface only its presence PLUS the CLOSED refusedCode
    // (redaction-safe classifier) so the diagnosis can tell a signer-rotation refusal from a missing export.
    // amnesiaProbe = the recovery latch's own self-diagnosis (the two blind spots: no bucket to probe; a
    // bucket whose RUNLOG is absent/unreadable). deploy = the deterministic per-tick deploy-identity marker
    // (baseline vs change vs cfVersionId-absent). exportHealth = the export pass's skip reason + per-dest
    // write outcome. All closed enums / ints / flags / clamped timestamps.
    // G317: an out-of-vocabulary probe class no longer drops the WHOLE amnesiaProbe block (which made a real
    // self-diagnosis -- "the plane was wiped and here is how I know" -- vanish on a class rename). The block
    // rides with its timestamp and the drift placeholder in place of the unrecognised class; the raw value is
    // discarded, never carried.
    const probe = j.amnesiaProbe && typeof j.amnesiaProbe.probe === "string" && j.amnesiaProbe.probe !== ""
      ? { probe: gateClosed(j.amnesiaProbe.probe, AMNESIA_PROBE_CODES) ?? UNKNOWN_CODE, ...(clampTs(j.amnesiaProbe.at) !== undefined ? { at: clampTs(j.amnesiaProbe.at) } : {}) }
      : null;
    const dep = j.deploy && typeof j.deploy.engineVersion === "string"
      ? {
          engineVersion: j.deploy.engineVersion.slice(0, 128),
          ...(typeof j.deploy.cfVersionId === "string" ? { cfVersionId: j.deploy.cfVersionId.slice(0, 128) } : {}),
          cfVersionIdAbsent: j.deploy.cfVersionIdAbsent === true,
          baselineEstablished: j.deploy.baselineEstablished === true,
          changesObserved: clampInt(j.deploy.changesObserved) ?? 0,
          ...(clampTs(j.deploy.firstSeenAt) !== undefined ? { firstSeenAt: clampTs(j.deploy.firstSeenAt) } : {}),
          ...(clampTs(j.deploy.lastSeenAt) !== undefined ? { lastSeenAt: clampTs(j.deploy.lastSeenAt) } : {}),
          ...(clampTs(j.deploy.lastChangeAt) !== undefined ? { lastChangeAt: clampTs(j.deploy.lastChangeAt) } : {}),
        }
      : null;
    // G218: the candidate-scan census, clamped at the pack boundary too (defence in depth: a DO record written
    // by a drifted build cannot widen the shape). Four non-negative counts; nothing derived from a bucket key.
    const rawScan = (typeof j.refusedScan === "object" && j.refusedScan !== null ? j.refusedScan : null) as Record<string, unknown> | null;
    const recoveryScan =
      rawScan === null
        ? null
        : {
            artefactsSeen: clampInt(rawScan.artefactsSeen, 1_000_000) ?? 0,
            malformedNames: clampInt(rawScan.malformedNames, 1_000_000) ?? 0,
            unsignedCandidates: clampInt(rawScan.unsignedCandidates, 1_000_000) ?? 0,
            conflictingAtLatestGen: clampInt(rawScan.conflictingAtLatestGen, 1_000_000) ?? 0,
          };
    // G218: the ESTATE-IMPORT OUTCOME. The recorder and the caller for accountIdAbsent existed and it reached
    // no bundle at all: it rode the import's one-shot HTTP response, which is gone by the time a pack is built.
    // Two states with the same disabled roster, the same audit trail and (until now) the same pack:
    //
    //   crossAccount:true, accountIdAbsent:false   a real cross-account rebuild. RE-POINT EVERY SOURCE.
    //   accountIdAbsent:true                       neither side could name an account, sameControlPlaneAccount
    //                                              failed SAFE on the null, crossAccount came back true anyway,
    //                                              and every downpipe landed disabled. There is NOTHING to
    //                                              re-point: set the account id and re-import. Sending this
    //                                              customer to re-point every source is a day that fixes nothing.
    //
    // downpipesDisabled states the consequence outright, so the pack says "nothing is running" as a fact.
    // Booleans, counts, a clamped timestamp: no account id, no downpipe id, no export content.
    const imp = j.lastImport && typeof j.lastImport === "object"
      ? {
          ...(clampTs(j.lastImport.at) !== undefined ? { at: clampTs(j.lastImport.at) } : {}),
          crossAccount: j.lastImport.crossAccount === true,
          accountIdAbsent: j.lastImport.accountIdAbsent === true,
          downpipesDisabled: j.lastImport.downpipesDisabled === true,
          downpipes: clampInt(j.lastImport.downpipes, 1_000_000) ?? 0,
          destinations: clampInt(j.lastImport.destinations, 1_000_000) ?? 0,
        }
      : null;
    const exp = j.exportHealth && typeof j.exportHealth === "object"
      ? {
          ...(clampTs(j.exportHealth.at) !== undefined ? { at: clampTs(j.exportHealth.at) } : {}),
          ...(gateClosed(j.exportHealth.skipped, EXPORT_SKIP_CODES) !== undefined ? { skipped: gateClosed(j.exportHealth.skipped, EXPORT_SKIP_CODES) } : {}),
          wroteAny: j.exportHealth.wroteAny === true,
          ...(clampInt(j.exportHealth.configVersion) !== undefined ? { configVersion: clampInt(j.exportHealth.configVersion) } : {}),
          // G202: the per-destination REASON. "Some copies of your configuration are stale or missing -- but
          // WHICH destination, and why?" ok:false said neither. A WORM lock (permanent, needs a new key
          // scheme), a rotated CONFIG_WRAP_KEY (the credential cannot be opened at all) and a network blip
          // (self-healing) were one undifferentiated boolean, and this record is what the self-backup posture
          // check reads to decide whether the customer's environment is recoverable at all.
          perDest: (Array.isArray(j.exportHealth.perDest) ? j.exportHealth.perDest : []).slice(0, 64).map((d) => {
            const row = d as { id?: unknown; ok?: unknown; reason?: unknown };
            const ok = row.ok === true;
            const reason = gateClosed(row.reason, CP_EXPORT_FAIL_CLASS_SET);
            return { id: String(row.id).slice(0, 128), ok, ...(!ok && reason !== undefined ? { reason } : {}) };
          }),
          // perDestTotal / perDestTruncated (G325): the TRUE uncapped destination count, and whether the record
          // dropped rows. This is not cosmetic. This record decides the self-backup posture check's
          // allDestinationsWrote, so a truncated-away FAILED destination read as fully covered -- a MISSING
          // RECOVERY COPY, invisible, on the one artefact that exists to survive losing everything else.
          ...(clampInt(j.exportHealth.perDestTotal) !== undefined ? { perDestTotal: clampInt(j.exportHealth.perDestTotal) } : {}),
          ...(j.exportHealth.perDestTruncated === true ? { perDestTruncated: true } : {}),
        }
      : null;
    return {
      recoveryRequired: j.recoveryRequired === true,
      ...(typeof j.reason === "string" ? { reason: j.reason } : {}),
      configEmpty: j.configEmpty === true,
      resumeApplied: j.resumeApplied === true,
      ...(j.refused != null ? { refused: true } : {}),
      // G317: a refusal whose CODE is not (yet) in the pack's allowlist used to lose the code entirely, leaving
      // `refused: true` with no cause -- indistinguishable from a refusal the pack simply had no code for. The
      // placeholder keeps the refusal legible AND makes the writer/pack drift visible; the raw code never rides.
      ...(gateClosed(j.refusedCode, AUTOHEAL_REFUSAL_CODES) !== undefined ? { refusedCode: gateClosed(j.refusedCode, AUTOHEAL_REFUSAL_CODES) } : {}),
      // G218: the SUB-CAUSE. refusedCode "signature" is a truncated .sig, a rotated signer, a MIXED signer
      // rotation and a genuine tamper -- four incidents, one code, four different responses. refusedCode
      // "unreadable" is a JSON parse fault, a shape drift and a version pin. The sealed-open failure was filed
      // as "shape-check", which erased even "this engine is not a recipient of the capsule" -- a state in which
      // no retry can EVER work and recovery must go offline with the break-glass identity.
      ...(gateClosed(j.refusedSubCause, AUTOHEAL_SUB_CAUSES) !== undefined ? { refusedSubCause: gateClosed(j.refusedSubCause, AUTOHEAL_SUB_CAUSES) } : {}),
      // refusedScan: what the auto-heal SAW in the bucket. artefactsSeen > 0 with malformedNames == artefactsSeen
      // and a "no-export" refusal is the HAND-RENAMED ARTEFACT: the bucket is full of recovery artefacts and not
      // one of them parses as a generation, so an operator tidying a bucket disarmed their own recovery, and the
      // engine reported the same "nothing found" as a genuinely empty bucket. conflictingAtLatestGen is the whole
      // content of the "ambiguous" refusal, which could not say that two artefacts claim the latest generation.
      ...(recoveryScan !== null ? { refusedScan: recoveryScan } : {}),
      ...(Object.keys(recoveryRefusals).length > 0 ? { recoveryRefusals } : {}),
      ...(imp !== null ? { lastImport: imp } : {}),
      ...(probe ? { amnesiaProbe: probe } : {}),
      ...(dep ? { deploy: dep } : {}),
      ...(exp ? { exportHealth: exp } : {}),
      staged: j.staged
        ? {
            ...(j.staged.version ? { version: j.staged.version } : {}),
            ...(j.staged.stagedAt ? { stagedAt: j.staged.stagedAt } : {}),
            downpipes: j.staged.downpipes ?? 0,
            resumeApplied: j.staged.resumeApplied === true,
            ...(clampInt(j.staged.resumeSkipped) !== undefined ? { resumeSkipped: clampInt(j.staged.resumeSkipped) } : {}),
            ...(clampInt(j.staged.appliedVersion) !== undefined ? { appliedVersion: clampInt(j.staged.appliedVersion) } : {}),
            ...(clampTs(j.staged.appliedAt) !== undefined ? { appliedAt: clampTs(j.staged.appliedAt) } : {}),
          }
        : null,
    };
  }
}

// fetchExportState (B4) pulls the control-plane EXPORT-LAG pointer: the config version the LAST signed
// control-plane export to the destination covered, and WHEN it was written. It complements the recovery
// latch (fetchRecoveryStatus), the latch answers "was the plane wiped?", this answers "how STALE is the
// no-custody backup we'd recover FROM?" (recovery readiness). Redaction-safe by construction: an integer
// version + a timestamp only; the configContentHash is DROPPED (not needed for the pack). The DO returns
// the pointer, or NULL when nothing has been exported yet, treated as honest absence ({}), same as a
// failing fetch. Best-effort: {} on failure, so a missing pointer is simply omitted from the bundle.
export async function fetchExportState(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/control-plane/export-state"), { method: "GET" });
    const j = (await r.json()) as { configVersion?: unknown; exportedAt?: unknown } | null;
    if (j === null || typeof j !== "object") return {};
    return {
      ...(typeof j.configVersion === "number" && Number.isFinite(j.configVersion) ? { configVersion: j.configVersion } : {}),
      ...(typeof j.exportedAt === "string" ? { exportedAt: j.exportedAt } : {}),
    };
  }
}
