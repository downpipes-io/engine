// ---- Engine-observed presence/version snapshot ----------------------------
// The engine cannot witness an out-of-band secret put or a redeploy directly, but it CAN detect
// the RESULT: a status presence boolean flipping true, or engineVersion changing. The DO keeps a
// small StatusSnapshot of the last-seen values; on each GET /admin/status the DO diffs the new
// status against the snapshot and appends an engine-observed event per change, then stores the new
// snapshot. These events carry actorMethod "engine", actorEmail null (no attributable human), and
// are clearly distinguishable from human actions. The snapshot holds only booleans and a version
// string, never a value. This is the audit-domain logic for engine-observed presence and version changes; audit.ts re-exports
// every symbol here so importers see one public surface.

import type { AuditDraft } from "./audit-types.ts";

// TRACKED_PRESENCE_FIELDS are the status booleans whose false -> true transition is worth an
// engine-secret-present event (a secret/recipient/destination became present). Only a flip to true
// is recorded (a secret being wired); a flip back to false is not an "applied" event.
export const TRACKED_PRESENCE_FIELDS = ["signerConfigured", "breakGlassConfigured", "destConfigured"] as const;
export type TrackedPresenceField = (typeof TRACKED_PRESENCE_FIELDS)[number];

// StatusSnapshot is the DO's last-seen view of the tracked fields. Stored under a single DO key.
export interface StatusSnapshot {
  presence: Record<TrackedPresenceField, boolean>;
  engineVersion: string;
  // The Cloudflare Worker deploy identity (env.CF_VERSION_METADATA.id). It changes on EVERY deploy, so a
  // same-software-version redeploy, e.g. one that silently drops a live-attached source binding,
  // becomes observable, not only a software upgrade. Optional: absent under env-fallback / local dev.
  cfVersionId?: string;
}

// StatusObservation is the subset of a StatusReport the snapshot diff needs (the DO passes these
// in from the buildStatus result it already computed for GET /status).
export interface StatusObservation {
  signerConfigured: boolean;
  breakGlassConfigured: boolean;
  destConfigured: boolean;
  engineVersion: string;
  cfVersionId?: string;
}

// diffStatus compares an observation against the prior snapshot and returns the engine-observed
// drafts to append, plus the new snapshot to store. A null prior (first ever observation) records
// NOTHING (it establishes the baseline) so onboarding from scratch does not emit a burst of
// "appeared" events for the initial wiring the operator is in the middle of; subsequent flips are
// recorded. This keeps the observed events meaningful (a CHANGE since we last looked) rather than
// noisy.
export function diffStatus(prior: StatusSnapshot | null, obs: StatusObservation): { drafts: AuditDraft[]; next: StatusSnapshot } {
  const next: StatusSnapshot = {
    presence: {
      signerConfigured: obs.signerConfigured,
      breakGlassConfigured: obs.breakGlassConfigured,
      destConfigured: obs.destConfigured,
    },
    engineVersion: obs.engineVersion,
    ...(obs.cfVersionId !== undefined ? { cfVersionId: obs.cfVersionId } : {}),
  };
  if (prior === null) return { drafts: [], next };
  const drafts: AuditDraft[] = [];
  for (const field of TRACKED_PRESENCE_FIELDS) {
    if (!prior.presence[field] && next.presence[field]) {
      drafts.push({
        actorEmail: null,
        actorMethod: "engine",
        sourceIp: null,
        action: "engine-secret-present",
        outcome: "success",
        target: { kind: "engine-state", field: "secret-present", detail: field },
      });
    }
    // The presence LOSS (true -> false) is recorded too, not only the APPEARING case, so a deploy that
    // dropped SIGNER_PRIVATE (or a destination binding) left status.signerConfigured reading false TODAY with
    // nothing anywhere saying WHEN it flipped -- and the whole diagnosis turns on when. It is recorded with
    // outcome "failed" because a tracked secret disappearing is never a healthy transition: the engine loses the
    // ability to seal (signer), to make an archive recoverable at all (break-glass), or to write (destination).
    // The target carries the presence-boolean NAME from the fixed TRACKED_PRESENCE_FIELDS vocabulary, exactly as
    // its false -> true twin does: never a value, and the snapshot itself still holds only booleans.
    if (prior.presence[field] && !next.presence[field]) {
      drafts.push({
        actorEmail: null,
        actorMethod: "engine",
        sourceIp: null,
        action: "engine-secret-absent",
        outcome: "failed",
        target: { kind: "engine-state", field: "secret-absent", detail: field },
      });
    }
  }
  // engine-version-change fires on a software-version change OR a Cloudflare deploy-id change. cfVersionId
  // changes on EVERY `wrangler deploy`, so a same-software-version redeploy that silently drops a live source
  // binding is now recorded, not only a software upgrade. The deploy-id arm requires BOTH ids
  // known so the first poll after this field appears cannot fabricate a change. Detail prefers the software
  // version when it changed, else the new deploy id.
  const softwareChanged = prior.engineVersion !== next.engineVersion;
  const deployChanged = !!prior.cfVersionId && !!next.cfVersionId && prior.cfVersionId !== next.cfVersionId;
  if (softwareChanged || deployChanged) {
    drafts.push({
      actorEmail: null,
      actorMethod: "engine",
      sourceIp: null,
      action: "engine-version-change",
      outcome: "success",
      target: { kind: "engine-state", field: "engineVersion", detail: softwareChanged ? next.engineVersion : (next.cfVersionId ?? next.engineVersion) },
    });
  }
  return { drafts, next };
}

// STATUS_SNAPSHOT_KEY is the single DO storage key for the last-seen status snapshot.
export const STATUS_SNAPSHOT_KEY = "auditStatusSnapshot";
