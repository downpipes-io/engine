// The control-plane RECOVERY half of the SchedulerDO's RPC dispatch, a sibling sub-mixin of the four
// routing sub-mixins (RoutingMixin chains it through `this`). It owns the internal routes the Worker
// (cron pass + the break-glass reconcile admin route) uses to drive control-plane recovery: produce the
// no-custody export slice, read/record the export change-gate pointer, read the recovery-required latch
// + emptiness, set the latch (the cron health pass), and run the break-glass-gated reconcile. Each
// method is a switch over `${method} ${pathname}` returning the handler Response for a key it owns or
// null ("not my route") so route() tries the next link. `this` is SchedulerDOSurface, so it reaches
// buildControlPlaneExport / reconcileControlPlane / setControlPlaneRecoveryRequired through `this`.

import { AUTO_HEAL_REFUSAL_CODES, AUTO_HEAL_SUB_CAUSES, type AutoHealRefusalCode, type AutoHealSubCause, type CandidateScan, type ControlPlaneExport, EXPORT_SKIP_REASONS, type ExportSkipReason, type StagedControlPlane } from "../admin/control-plane.ts";
import { CALLER_HEADER, decodeCaller } from "../admin/identity.ts";

const AUTO_HEAL_REFUSAL_CODE_SET: ReadonlySet<string> = new Set(AUTO_HEAL_REFUSAL_CODES);
const AUTO_HEAL_SUB_CAUSE_SET: ReadonlySet<string> = new Set(AUTO_HEAL_SUB_CAUSES);

import type { CpExportFailClass } from "../cron/cron-fault-ledger.ts";
import type { SchedulerDOCtor } from "./scheduler-do-base.ts";

export function RoutingControlPlaneMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    async routeControlPlane(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
        // The no-custody export SLICE the cron pass signs + writes to every destination. INTERNAL-ONLY
        // (the router never exposes it as an admin route): it carries WRAPPED dest envelopes (no plaintext
        // secret) but is still recovery-sensitive, so it stays a DO-internal read the cron pass consumes.
        case "GET /control-plane/export":
          return this.json(await this.buildControlPlaneExport());
        // The last-export change-gate pointer (the cron pass skips re-signing an unchanged slice).
        case "GET /control-plane/export-state":
          return this.json(await this.getControlPlaneExportState());
        // The cron pass reports back that it wrote a signed export covering this version/hash.
        case "POST /control-plane/export-recorded": {
          const body = (await req.json()) as { configVersion?: unknown; configContentHash?: unknown; exportedAt?: unknown; destCredHash?: unknown };
          const configVersion = typeof body.configVersion === "number" && Number.isFinite(body.configVersion) ? body.configVersion : 0;
          const configContentHash = typeof body.configContentHash === "string" ? body.configContentHash : "";
          const exportedAt = typeof body.exportedAt === "string" ? body.exportedAt : new Date().toISOString();
          // destCredHash (CPR: export-change-gate-misses-cred-rotation) folds the dest-credential fingerprint
          // into the change-gate so a credential rotation re-fires the export. Optional (older callers omit it).
          const destCredHash = typeof body.destCredHash === "string" ? body.destCredHash : undefined;
          await this.setControlPlaneExportState({ configVersion, configContentHash, exportedAt, ...(destCredHash !== undefined ? { destCredHash } : {}) });
          await this.recordControlPlaneExported(configVersion);
          return this.json({ ok: true });
        }
        // The recovery-required latch + emptiness + the AUTO-HEAL staging state, read by the cron health
        // pass and surfaced to whoami / the console recovery banner. resumeApplied tells the cron the
        // no-authority resume slice has already run (backups resumed); staged/refused tell the banner the
        // recovery is auto-staged-and-awaiting-a-break-glass-confirm vs stepped back to manual. No secret.
        case "GET /control-plane/recovery-status": {
          const latch = await this.getControlPlaneRecoveryRequired();
          const configEmpty = await this.controlPlaneIsEmpty();
          // CP-RECOVERY-LATCH defect 23: roleTableEmpty is the SECOND emptiness, and until now it was
          // readable nowhere outside the DO even though it is the single discriminator deciding WHICH exit a
          // latched estate has. Every break-glass route (reconcile, apply-staged) refuses a NON-EMPTY role
          // table; acknowledge-recovery refuses an EMPTY one. Without this field the console could only guess
          // which of the two an operator was in, so it offered the break-glass actions to everybody and the
          // established accounts -- which is all of them, the last-Owner guard keeps the table non-empty --
          // met a refusal on every affordance the banner had. One boolean, no secret, no count, no identity.
          const roleTableEmpty = await this.roleTableIsEmpty();
          const rec = await this.getControlPlaneRecoveryRecord();
          const staged = rec?.staged ?? null;
          // Recovery-latch SELF-DIAGNOSIS (needs-new-logging): the amnesia probe class (the latch's own blind
          // spots), the CLOSED auto-heal refusal code (redaction-safe companion to the free-text reason), the
          // resume applied-vs-expected skip + applied generation, the deterministic deploy-identity
          // observation, and the export-pass health. All closed enums / ints / flags / clamped timestamps.
          const amnesiaProbe = await this.getControlPlaneAmnesiaProbe();
          const deploy = await this.getControlPlaneDeployObservation();
          const exportHealth = await this.getControlPlaneExportHealth();
          // G218: the last ESTATE IMPORT's outcome. Null on every engine that was never rebuilt from a kit
          // (the ordinary case), so it adds no noise; present exactly when an import ran, which is exactly
          // when "my estate is back and nothing is running" can be asked.
          const lastImport = await this.getControlPlaneLastImport();
          // CP-RECOVERY-LATCH finding #2: the amnesia latch's one human signal is a CRITICAL notification
          // (control-plane-pass.ts fires it, reused posture-regression event, explicit critical severity) and
          // it has no other channel -- an estate with no notification channel configured never learns its
          // plane went silent. noteUndeliveredCriticalAlert already counts the loss on the bounded admin-
          // counter aggregate; fold it into THIS response (the console recovery banner polls it) rather than
          // leaving it visible only to whoever thinks to pull a reactive support pack. Null when no critical
          // alert has ever gone undelivered, so a healthy estate sees no new noise.
          const counters = await this.readAdminCounters();
          const criticalAlertsUndelivered = counters["notify-critical-alert-undelivered"] ?? null;
          return this.json({
            recoveryRequired: latch.required,
            reason: latch.reason,
            configEmpty,
            roleTableEmpty,
            resumeApplied: staged?.resumeApplied === true,
            refused: rec?.refused ?? null,
            // The CLOSED refusal code, surfaced top-level so the pack can forward it without the free-text reason.
            refusedCode: rec?.refused?.code ?? null,
            // G218: the SECOND axis (why, within the code) and the candidate-scan census. Surfaced top-level
            // for the same reason the code is: the pack forwards these and never the free-text reason.
            refusedSubCause: rec?.refused?.subCause ?? null,
            refusedScan: rec?.refused?.scan ?? null,
            amnesiaProbe,
            deploy,
            exportHealth,
            lastImport,
            criticalAlertsUndelivered,
            staged:
              staged !== null
                ? {
                    sourceKey: staged.sourceKey,
                    version: staged.version,
                    stagedAt: staged.stagedAt,
                    downpipes: staged.export.downpipes.length,
                    resumeApplied: staged.resumeApplied,
                    ...(staged.resumeSkipped !== undefined ? { resumeSkipped: staged.resumeSkipped } : {}),
                    ...(staged.appliedVersion !== undefined ? { appliedVersion: staged.appliedVersion } : {}),
                    ...(staged.appliedAt !== undefined ? { appliedAt: staged.appliedAt } : {}),
                  }
                : null,
          });
        }
        // The cron health pass records the OUTCOME CLASS of its last amnesia-detection attempt (the latch's
        // own blind spots: no bucket to probe; a bucket whose RUNLOG is absent/unreadable). INTERNAL-ONLY.
        case "POST /control-plane/amnesia-probe": {
          const body = (await req.json()) as { probe?: unknown };
          const allowed = new Set(["not-empty", "runs-present", "runlog-absent", "probe-error", "no-resolvable-dest"]);
          const probe = typeof body.probe === "string" && allowed.has(body.probe) ? (body.probe as "not-empty" | "runs-present" | "runlog-absent" | "probe-error" | "no-resolvable-dest") : null;
          if (probe === null) return this.jsonStatus({ ok: false, reason: "a valid probe class is required" }, 400);
          await this.recordControlPlaneAmnesiaProbe(probe);
          return this.json({ ok: true });
        }
        // The cron drives a DETERMINISTIC per-tick deploy-identity observation from the Worker (which holds
        // env.CF_VERSION_METADATA), so a deploy is visible even when GET /admin/status is never polled. INTERNAL.
        case "POST /control-plane/deploy-observe": {
          const body = (await req.json()) as { engineVersion?: unknown; cfVersionId?: unknown };
          const engineVersion = typeof body.engineVersion === "string" && body.engineVersion.length > 0 && body.engineVersion.length <= 128 ? body.engineVersion : null;
          if (engineVersion === null) return this.jsonStatus({ ok: false, reason: "engineVersion is required" }, 400);
          const cfVersionId = typeof body.cfVersionId === "string" && body.cfVersionId.length > 0 && body.cfVersionId.length <= 128 ? body.cfVersionId : undefined;
          const out = await this.recordControlPlaneDeployObservation({ engineVersion, ...(cfVersionId !== undefined ? { cfVersionId } : {}) });
          return this.json({ ok: true, ...out });
        }
        // The cron export pass records the outcome of the last export attempt (skip reason + per-dest write
        // outcome), so a stale recovery generation (budget-starved) or a partial write is explained. INTERNAL.
        case "POST /control-plane/export-health": {
          const body = (await req.json()) as { at?: unknown; skipped?: unknown; wroteAny?: unknown; configVersion?: unknown; perDest?: unknown };
          // G218: bound to the canonical EXPORT_SKIP_REASONS tuple, not a hand-listed literal set -- the
          // hand-listed one is exactly how "empty-recipient-set" (an engine that can NEVER write a recovery
          // artefact) would have been silently dropped at this boundary while the recorder happily posted it.
          const skipAllowed: ReadonlySet<string> = new Set(EXPORT_SKIP_REASONS);
          const perDest = Array.isArray(body.perDest) ? body.perDest.filter((d): d is { id: string; ok: boolean; reason?: CpExportFailClass } => typeof d === "object" && d !== null && typeof (d as { id?: unknown }).id === "string") : [];
          await this.recordControlPlaneExportHealth({
            at: typeof body.at === "string" ? body.at : new Date().toISOString(),
            ...(typeof body.skipped === "string" && skipAllowed.has(body.skipped) ? { skipped: body.skipped as ExportSkipReason } : {}),
            wroteAny: body.wroteAny === true,
            ...(typeof body.configVersion === "number" && Number.isFinite(body.configVersion) ? { configVersion: body.configVersion } : {}),
            perDest,
          });
          return this.json({ ok: true });
        }
        // AUTO-HEAL: the cron stages a Worker-VERIFIED export here (the Worker proved the signature +
        // no-custody before forwarding). INTERNAL-ONLY (not an admin route): it carries WRAPPED dest
        // envelopes, no plaintext secret, and grants no authority on its own. Replaces any prior record.
        case "POST /control-plane/stage": {
          const body = (await req.json()) as { staged?: unknown };
          const staged = body.staged as StagedControlPlane | undefined;
          if (staged === undefined || typeof staged !== "object" || staged === null) {
            return this.jsonStatus({ ok: false, reason: "a staged export is required" }, 400);
          }
          await this.stageControlPlaneRecovery(staged);
          return this.json({ ok: true });
        }
        // AUTO-HEAL: the cron records that nothing could be SAFELY auto-applied (no export / ambiguous /
        // unsigned / no signer), so the auto-heal steps back to the manual break-glass path and stops re-trying.
        case "POST /control-plane/recovery-refused": {
          const body = (await req.json()) as { reason?: unknown; code?: unknown; subCause?: unknown; scan?: unknown };
          const reason = typeof body.reason === "string" && body.reason.length > 0 ? body.reason : "the auto-heal found no export it could safely apply";
          // The code (not just the reason) is now carried through to the recorder, so a real auto-heal
          // refusal is classified and the refusal-unclassified counter no longer fires on every refusal.
          const code = typeof body.code === "string" && AUTO_HEAL_REFUSAL_CODE_SET.has(body.code) ? (body.code as AutoHealRefusalCode) : undefined;
          // G218: the closed sub-cause + the candidate-scan counts. Gated against their closed set / clamped
          // here (the DO is the redaction chokepoint), so no bucket key, field path or message can enter.
          const subCause = typeof body.subCause === "string" && AUTO_HEAL_SUB_CAUSE_SET.has(body.subCause) ? (body.subCause as AutoHealSubCause) : undefined;
          const rawScan = (typeof body.scan === "object" && body.scan !== null ? body.scan : null) as Record<string, unknown> | null;
          const clampScan = (n: unknown): number => (typeof n === "number" && Number.isFinite(n) && n >= 0 ? Math.min(1_000_000, Math.floor(n)) : 0);
          const scan: CandidateScan | undefined =
            rawScan === null
              ? undefined
              : {
                  artefactsSeen: clampScan(rawScan.artefactsSeen),
                  malformedNames: clampScan(rawScan.malformedNames),
                  unsignedCandidates: clampScan(rawScan.unsignedCandidates),
                  conflictingAtLatestGen: clampScan(rawScan.conflictingAtLatestGen),
                };
          await this.recordControlPlaneRecoveryRefused(reason, code, { ...(subCause !== undefined ? { subCause } : {}), ...(scan !== undefined ? { scan } : {}) });
          return this.json({ ok: true });
        }
        // AUTO-HEAL: the cron applies the NO-AUTHORITY resume slice (downpipes/dest/discovery) so backups
        // resume. INTERNAL-ONLY + grants no authority (the latch stays set, the role table stays empty), so
        // it needs no caller auth; the DO guards on the latch being set + a staged export being present.
        case "POST /control-plane/resume-apply":
          return this.json(await this.applyControlPlaneResumeSlice());
        // The full STAGED export (export + signature + provenance), read by the Worker's break-glass apply
        // route so it can RE-VERIFY the signature before the authority restore. INTERNAL-ONLY (the Worker
        // gates the ADMIN_TOKEN before calling), like /control-plane/export.
        case "GET /control-plane/staged-export": {
          const rec = await this.getControlPlaneRecoveryRecord();
          return this.json(rec?.staged ?? null);
        }
        // AUTO-HEAL break-glass CONFIRM: restore the AUTHORITY slice (RBAC + clear latch + re-arm bootstrap
        // + bridge) from the staged export. The router proved the break-glass token + re-verified the staged
        // export's signature BEFORE forwarding; the DO re-asserts the bare-token caller (defence in depth).
        case "POST /control-plane/apply-staged": {
          const caller = decodeCaller(req.headers.get(CALLER_HEADER));
          return this.json(await this.applyControlPlaneAuthoritySlice(caller));
        }
        // The cron health pass SETS the latch when it detects an empty control plane while the bucket has
        // runs (the amnesia signal). Idempotent; the false->true transition writes a critical audit event.
        case "POST /control-plane/recovery-required": {
          const body = (await req.json()) as { reason?: unknown; runlogSeed?: unknown };
          const reason = typeof body.reason === "string" && body.reason.length > 0 ? body.reason : "control plane is empty but the destination bucket has runs";
          // runlogSeed (RUNLOG-FORKS-ON-THE-RECOVERY-PATH): the cron's own verified
          // read of the surviving RUNLOG's high-water mark, when one was established; see
          // setControlPlaneRecoveryRequired for how it anchors the counter.
          const runlogSeed = typeof body.runlogSeed === "number" ? body.runlogSeed : undefined;
          await this.setControlPlaneRecoveryRequired(reason, runlogSeed);
          return this.json({ ok: true });
        }
        // The break-glass-gated reconcile: the router has verified the break-glass token + the export
        // signature BEFORE forwarding here; the DO re-asserts the caller is the bare-token break-glass
        // (defence in depth) and rebuilds inside blockConcurrencyWhile.
        case "POST /control-plane/reconcile": {
          const caller = decodeCaller(req.headers.get(CALLER_HEADER));
          const body = (await req.json()) as { export?: unknown };
          const exp = body.export as ControlPlaneExport;
          return this.json(await this.reconcileControlPlane(exp, caller));
        }
        // CP-RECOVERY-LATCH-NO-CLEAR-PATH-AFTER-ORGANIC-RESUME: the ACKNOWLEDGE-ONLY latch clear.
        // The Worker gates access.policy (an authenticated owner/access-admin, never the bare break-glass
        // token) before forwarding here; the DO re-asserts the same (defence in depth) and separately refuses
        // over an empty role table (see acknowledgeControlPlaneRecovery's own comment for why).
        case "POST /control-plane/acknowledge-recovery": {
          const caller = decodeCaller(req.headers.get(CALLER_HEADER));
          return this.json(await this.acknowledgeControlPlaneRecovery(caller));
        }
        // The CROSS-ENVIRONMENT estate import: the Worker gated access.policy + verified the export against the
        // operator-supplied kit signer.pub + computed crossAccount BEFORE forwarding here; the DO rebuilds only
        // the definition (no authority) and re-asserts the caller is an authenticated Owner (not a bare token).
        case "POST /control-plane/import": {
          const caller = decodeCaller(req.headers.get(CALLER_HEADER));
          const body = (await req.json()) as { export?: unknown; crossAccount?: unknown; accountIdAbsent?: unknown };
          const exp = body.export as ControlPlaneExport;
          return this.json(await this.importControlPlaneDefinition(exp, body.crossAccount === true, caller, body.accountIdAbsent === true));
        }
        default:
          return null;
      }
    }
  };
}
