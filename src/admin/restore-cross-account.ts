import type { ShardRecord } from "../format/manifest.ts";
import type { RestorePlanState } from "./restore-plan-types.ts";
import type { CrossAccountWarning, CrossZoneWarning, RestoreRequest } from "./restore-types.ts";

// The CROSS-ACCOUNT (confused-deputy) guard for the cf-config and media restore legs. Both
// legs re-apply through the Cloudflare API to a CALLER-SUPPLIED accountId (cfConfig.accountId /
// mediaRestore.accountId), so a wrong or drifted account would land a config/media write in the WRONG
// account. This module cross-checks that caller-supplied target against the account the archive was CAPTURED
// from -- the SIGNED origin on each record (rec.account, the source adapter's own accountId, stamped at seal
// and pinned by the root's per-shard SHA-384, so a restore request cannot spoof it). When they match (the
// common same-account restore) nothing is gated. When they differ, or the archive recorded no origin (so the
// target is unverifiable), the leg is cross-account: the dry-run WARNS (crossAccountWarnings) and the apply
// REFUSES unless the caller explicitly echoes the target account (crossAccountConfirmed). Cross-account
// restore is a legitimate disaster-recovery migration; the guard only makes it a DELIBERATE, non-silent
// choice, symmetric to the reserved-binding guard on the read side.

// legOrigin resolves the archive's origin account for one leg's in-scope records: the single account they
// were all captured from, or null when they disagree or any record recorded none (both cases are
// unverifiable, so the caller must confirm). Under the current engine every cf-config / media source carries
// its accountId, so a real archive resolves to a single origin; null is the defensive fail-closed branch.
function legOrigin(recs: ReadonlyArray<{ rec: ShardRecord }>): string | null {
  const accounts = new Set<string | undefined>();
  for (const { rec } of recs) accounts.add(rec.account);
  if (accounts.size !== 1) return null; // no records, or more than one origin: not verifiable
  const only = [...accounts][0];
  return typeof only === "string" && only !== "" ? only : null;
}

// crossAccountWarnings returns one warning per restore LEG whose target account is NOT provably the archive's
// origin account: the leg is present in the request, it has in-scope writable records, and the origin either
// differs from the target or was not recorded. Empty in the common case (a leg that restores to its own
// origin account, or a leg that is absent / has nothing to write). It reads the SIGNED origin off the
// records, never a value the caller controls, so the check cannot be turned off by the request.
export function crossAccountWarnings(body: RestoreRequest, state: RestorePlanState): CrossAccountWarning[] {
  const out: CrossAccountWarning[] = [];
  if (body.cfConfig !== undefined && state.configPlan.length > 0) {
    const targetAccount = body.cfConfig.accountId;
    const originAccount = legOrigin(state.configPlan);
    if (originAccount !== targetAccount) out.push({ leg: "cf-config", originAccount, targetAccount });
  }
  if (body.mediaRestore !== undefined && state.mediaPlan.length > 0) {
    const targetAccount = body.mediaRestore.accountId;
    const originAccount = legOrigin(state.mediaPlan);
    if (originAccount !== targetAccount) out.push({ leg: "media", originAccount, targetAccount });
  }
  return out;
}

// crossAccountConfirmed reports whether a cross-account leg is EXPLICITLY confirmed: the leg's
// confirmDifferentAccountId echoes EXACTLY the target account the write goes to. Requiring the echoed target
// (a type-to-confirm), not a bare boolean, means a drifted or automated caller cannot wave the guard through
// without naming the specific foreign account, so the cross-account write is never silent.
export function crossAccountConfirmed(w: CrossAccountWarning, body: RestoreRequest): boolean {
  const leg = w.leg === "cf-config" ? body.cfConfig : body.mediaRestore;
  return leg !== undefined && leg.confirmDifferentAccountId === w.targetAccount;
}

// unconfirmedCrossAccountLegs returns the cross-account legs an APPLY must refuse before any write:
// cross-account (or unverifiable) AND not explicitly confirmed. Empty => the apply may proceed (every
// present leg is same-account, or every cross-account leg is explicitly confirmed).
export function unconfirmedCrossAccountLegs(body: RestoreRequest, state: RestorePlanState): CrossAccountWarning[] {
  return crossAccountWarnings(body, state).filter((w) => !crossAccountConfirmed(w, body));
}

// crossAccountRefusalReason renders the operator-facing refusal for an unconfirmed cross-account apply. It
// names the origin and target accounts and the exact field to set, so the write is never silent and the
// operator can either correct the target or confirm the cross-account restore deliberately. The account ids
// are the operator's own (not secrets; they are already shown in the console and bound into the plan hash),
// so they are safe in this operator-facing reason; the caller keeps the coarse "cross-account restore not
// confirmed" log line free of them, matching the coarse-log discipline of the rest of restore.
export function crossAccountRefusalReason(legs: CrossAccountWarning[]): string {
  const one = (w: CrossAccountWarning): string => {
    const field = w.leg === "cf-config" ? "cfConfig.confirmDifferentAccountId" : "mediaRestore.confirmDifferentAccountId";
    const origin = w.originAccount !== null
      ? `was captured from Cloudflare account ${w.originAccount}`
      : "did not record which Cloudflare account it was captured from";
    return `the ${w.leg} in this archive ${origin}, but the restore targets account ${w.targetAccount}; a cross-account restore must be confirmed explicitly (set ${field} to ${w.targetAccount}) so it is never silent`;
  };
  return legs.map(one).join("; ");
}


// ---- the ZONE guard ---------------------------------------------------------------------------

// originZoneFrom decodes the cf-config identity record's zoneId.
//
// It returns null when there is no identity record, when the bytes do not parse, or when the record
// carries no zoneId (an account-scoped backup, which cannot be restored into the wrong zone because it
// writes no zone-scoped surface). null means "not verifiable", and the caller treats that the same way
// legOrigin's null is treated on the account side: as a reason to make the operator confirm, never as
// permission to proceed quietly.
export function originZoneFrom(identityBytes: Uint8Array | null): string | null {
  if (identityBytes === null) return null;
  try {
    const v = JSON.parse(new TextDecoder().decode(identityBytes)) as { zoneId?: unknown };
    return typeof v.zoneId === "string" && v.zoneId !== "" ? v.zoneId : null;
  } catch {
    return null;
  }
}

// crossZoneWarning reports a cf-config restore whose target zone is not provably the zone the archive was
// captured from, and which would write at least one ZONE-SCOPED surface.
//
// Account-scoped surfaces are excluded deliberately: they ignore zoneId entirely, so a mismatched zone
// cannot misplace them and warning about them would train the operator to click past the warning that
// matters. An archive with no zone-scoped surfaces in scope produces no warning at all.
export function crossZoneWarning(
  body: RestoreRequest,
  originZone: string | null,
  configPlan: ReadonlyArray<{ rec: { name: string }; surface: { scope: string } }>,
): CrossZoneWarning | null {
  const targetZone = body.cfConfig?.zoneId;
  if (targetZone === undefined || targetZone === "") return null;
  const zoneSurfaces = configPlan.filter((p) => p.surface.scope === "zone").map((p) => p.rec.name);
  if (zoneSurfaces.length === 0) return null;
  if (originZone === targetZone) return null;
  return { originZone, targetZone, zoneSurfaces };
}

// crossZoneConfirmed mirrors crossAccountConfirmed: the caller must echo the EXACT target zone, so a
// drifted or automated caller cannot wave the guard through with a bare boolean.
export function crossZoneConfirmed(w: CrossZoneWarning, body: RestoreRequest): boolean {
  return body.cfConfig?.confirmDifferentZoneId === w.targetZone;
}
