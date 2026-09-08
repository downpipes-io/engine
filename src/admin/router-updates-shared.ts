// router-updates-shared.ts -- the route-shaped guards the APPLY and RAMP update routes enforce from one
// place, split out of router-updates.ts (size hygiene; the ramp halves live in router-updates-ramp.ts and
// must not import router-updates.ts back, the same no-cycle rule router-updates-components.ts follows).
// Behaviour is verbatim from router-updates.ts; only the module boundary moved.

import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { bumpAdminCounter, bumpAdminCounters } from "./diag-counters.ts";
import type { AdminCounterName } from "./diag-records.ts";
import { type UpdateGuardClass, updateRefusalCounter } from "./posture-counters.ts";
import { jsonError, recordAudit } from "./router-core.ts";
import { doURL } from "../do-url.ts";
import { checkChannelFreshness, type FreshnessState, type RecommendedArtefact } from "./updates.ts";

// updateChannelMaxAgeMs reads the OPT-IN R9 channel max-age (UPDATE_CHANNEL_MAX_AGE_DAYS) and returns it in
// milliseconds, or undefined when unset / non-positive / unparseable (the default: max-age enforcement OFF).
// It is opt-in precisely so it can never false-positive on a legitimately dormant-but-current channel; the
// monotonic sequence/issuedAt checks carry the replay protection on their own.
function updateChannelMaxAgeMs(env: Env): number | undefined {
  const raw = typeof env.UPDATE_CHANNEL_MAX_AGE_DAYS === "string" ? Number(env.UPDATE_CHANNEL_MAX_AGE_DAYS.trim()) : NaN;
  return Number.isFinite(raw) && raw > 0 ? raw * 86_400_000 : undefined;
}

// readUpdateFloor reads the persisted ANTI-ROLLBACK floor (R8 settledHighWaterMark) + the FRESHNESS watermark
// (R9 lastChannelSeq/lastChannelIssuedAt) from the update-lifecycle record, plus the opt-in max-age, so the
// apply + ramp routes enforce the SAME floor from one place. Every field is parsed defensively (absent / wrong
// type -> omitted). The read rides the route's own try/catch, so a DO read failure becomes the route's clean
// "nothing was changed" 400 (fail-closed: no apply without the floor).
export async function readUpdateFloor(scheduler: DurableObjectStub, env: Env): Promise<{ settledHighWaterMark?: string; consoleFloor?: string; freshness: FreshnessState }> {
  const resp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
  const rec = (await resp.json()) as { settledHighWaterMark?: unknown; floors?: unknown; lastChannelSeq?: unknown; lastChannelIssuedAt?: unknown };
  const hwm = typeof rec.settledHighWaterMark === "string" && rec.settledHighWaterMark.trim() !== "" ? rec.settledHighWaterMark : undefined;
  // The CONSOLE component's own R8 floor from the per-component floors map (multi-component updates). The
  // engine's floor stays read from the legacy scalar (dual-written as the floors.engine mirror).
  const floorsRaw = rec.floors;
  const consoleFloorRaw = typeof floorsRaw === "object" && floorsRaw !== null && !Array.isArray(floorsRaw) ? (floorsRaw as Record<string, unknown>).console : undefined;
  const consoleFloor = typeof consoleFloorRaw === "string" && consoleFloorRaw.trim() !== "" ? consoleFloorRaw : undefined;
  const lastSeq = typeof rec.lastChannelSeq === "number" && Number.isFinite(rec.lastChannelSeq) ? rec.lastChannelSeq : undefined;
  const lastIssuedAt = typeof rec.lastChannelIssuedAt === "string" && rec.lastChannelIssuedAt.trim() !== "" ? rec.lastChannelIssuedAt : undefined;
  const maxAgeMs = updateChannelMaxAgeMs(env);
  return {
    ...(hwm !== undefined ? { settledHighWaterMark: hwm } : {}),
    ...(consoleFloor !== undefined ? { consoleFloor } : {}),
    freshness: { ...(lastSeq !== undefined ? { lastSeq } : {}), ...(lastIssuedAt !== undefined ? { lastIssuedAt } : {}), ...(maxAgeMs !== undefined ? { maxAgeMs } : {}) },
  };
}

// freshnessRefusal enforces R9 replay protection on the resolved channel descriptor. It returns a jsonError
// Response to RETURN (the descriptor is a replay/superseded and is refused), or null to proceed (a warning is
// logged but the apply continues, the backward-tolerant absent-field case). Shared by apply + ramp.
export function freshnessRefusal(art: RecommendedArtefact, freshness: FreshnessState, onRefused?: () => void, onDegraded?: (names: readonly string[]) => void): Response | null {
  // G332 R6: the erased-claim flags ride with the claim. The resolver already COUNTED a malformed claim (at the
  // erasure, so it fires with or without a watermark); the check reads the flags only so it never files an
  // erased claim under the honestly-absent name.
  const verdict = checkChannelFreshness(
    {
      ...(art.sequence !== undefined ? { sequence: art.sequence } : {}),
      ...(art.issuedAt !== undefined ? { issuedAt: art.issuedAt } : {}),
      ...(art.sequenceMalformed === true ? { sequenceMalformed: true } : {}),
      ...(art.issuedAtMalformed === true ? { issuedAtMalformed: true } : {}),
    },
    freshness,
    Date.now(),
  );
  if (verdict.ok && verdict.degradations !== undefined && verdict.degradations.length > 0) onDegraded?.(verdict.degradations);
  if (!verdict.ok) {
    // G275: THE ONE THAT MATTERS. A freshness/replay refusal means the channel served an artefact that is
    // back-dated or below the sequence high-water mark -- a REPLAYED update, which is a possible attack
    // signal -- and it is the ONLY guard in this family that emits no audit event at all. It has been a bare
    // 400 into a browser since the day it was written.
    onRefused?.();
    return jsonError(`no applicable update: ${verdict.reason}`, 400);
  }
  if (verdict.warn) log("warn", `update channel freshness: ${verdict.warn}`);
  return null;
}

// pendingUpdateRefusal (asvs-HI-14, PRIMARY guard) refuses a NEW apply/ramp while a PRIOR apply/ramp's
// verification is still open. Without this, the module's own documented way to finish an opt-in ramp --
// calling POST /update/apply while the ramp's pending record is still awaiting settlement -- can reach
// planAndPromote while the account is a genuine multi-version SPLIT. verifyAndGuard's record-rollback-target
// step then has only a fifty-fifty-or-worse chance of it mattering: on a >50% ramp, currentLiveVersionId()
// returns the DOMINANT (just-ramped, not-yet-trusted) slice, so a second apply would silently record that
// release as its OWN rollback target -- a later unhealthy verdict's auto-rollback would then redeploy the
// SAME untrusted build while telling the operator "rolled back, nothing was lost". Refusing here, before
// either route resolves the engine account, downloads the artefact, spends a dual-control approval, or asks
// for the deploy token, makes that state impossible to reach through these two routes: settle (POST
// /update/settle or /update/ramp/settle) or roll back the open verification first. Reads the SAME
// /update-status shape POST /update/settle already consumes. verifyAndGuard's own split-check (update-
// types.ts) is defence in depth for a caller that reaches it some other way.
export async function pendingUpdateRefusal(scheduler: DurableObjectStub): Promise<Response | null> {
  const recResp = await scheduler.fetch(doURL("/update-status"), { method: "GET" });
  const rec = (await recResp.json()) as { pending: null | { toVersion?: unknown; percentage?: unknown } };
  if (!rec.pending) return null;
  const kind = typeof rec.pending.percentage === "number" ? "a gradual ramp" : "an update";
  const toVersion = typeof rec.pending.toVersion === "string" && rec.pending.toVersion !== "" ? rec.pending.toVersion : "an uploaded version";
  return jsonError(`a previous apply/ramp is already awaiting verification (${kind} to ${toVersion}); settle it (POST /update/settle or /update/ramp/settle) or roll it back first before starting another. Nothing was changed.`, 409);
}

// recordUpdateRefusal records a FAILED self-apply update attempt as an `update-refused` audit event (UPD
// artefact-download-or-url-missing / engine-account-unmarked-blocks-update): the customer's own tamper-evident
// trail of the attempt. The detail is the engine-authored closed guard class (never a secret, never a message),
// bounded to 120 chars. Best-effort (matches the existing recordAudit calls in the update handlers, which do
// not wrap it).
//
// R7: it is NO LONGER CALLED DIRECTLY BY ANY GUARD, and that is the fix. Six apply/ramp-start guards called it
// on its own and stopped there -- and the pack's configEvents excerpt deliberately drops the audit target's
// `detail`, so every one of those refusals reached a support engineer as the same unclassed "update-refused /
// denied" row. noteUpdateGuardRefusal below is now the ONE entry point (it calls this, plus the closed counter
// that actually carries the class into the pack), so the audit half can no longer be shipped without the
// pack-visible half.
async function recordUpdateRefusal(scheduler: DurableObjectStub, caller: Parameters<typeof recordAudit>[1], sourceIp: string | null, detail: string): Promise<void> {
  await recordAudit(scheduler, caller, sourceIp, "update-refused", "denied", { kind: "engine-state", field: "engineVersion", detail: detail.slice(0, 120) });
}

// noteUpdateGuardRefusal (G275) is the ONE call every update-family guard makes when it refuses, and as of R7
// that sentence is TRUE OF THE CODE rather than of its comment. recordUpdateRefusal above is now private to this
// module and has exactly one caller: this function. A guard cannot ship the audit half without the pack half.
//
// THE FULL PRODUCER LIST (every place an update-family action is refused before or at its deploy decision):
//   apply, engine-only leg      router-updates.ts       pending-open, account-unmarked, artefact-resolve,
//                                                       freshness-replay, artefact-download, no-destination,
//                                                       deploy-token, high-water
//   apply, components leg       router-updates-components.ts  artefact-resolve (console), no-destination,
//                                                       deploy-token, artefact-download (engine + console),
//                                                       high-water
//   settle                      router-updates.ts       no-pending, ramp-shaped, deploy-token, account-unmarked
//   rollback (console/engine)   router-updates.ts       no-target, deploy-token, account-unmarked
//   ramp start                  router-updates-ramp.ts  pending-open, account-unmarked, artefact-resolve,
//                                                       freshness-replay, artefact-download, deploy-token
//   ramp settle                 router-updates-ramp.ts  no-pending, ramp-shaped, deploy-token, account-unmarked
//
// WHY BOTH HALVES. The audit event alone is not enough: the pack's configEvents EXCERPT deliberately does not
// forward the audit target's `detail` field (it is operator prose, and forwarding it would be exactly the
// free-text leak the excerpt exists to prevent). So an `update-refused` row in the pack says an update was
// refused and NOTHING about which guard tripped -- and the guards that mattered most (the "Update now" button's
// own deploy-token check, the components leg's twin, ramp start, settle, ramp-settle, rollback, freshness)
// returned a bare 400 and emitted no pack-visible row at all. The CLOSED counter is what makes the guard legible
// in the pack; the audit event is what makes it tamper-evident in the customer's own trail.
//
// The detail is the closed guardClass itself, not a sentence: an engine-set enum member, so the audit row
// carries no interpolated Cloudflare prose, no version string and no URL.
//
// Best-effort throughout: a refusal must never be turned into a 500 by the act of recording it.
export async function noteUpdateGuardRefusal(
  scheduler: DurableObjectStub,
  caller: Parameters<typeof recordAudit>[1],
  sourceIp: string | null,
  guard: UpdateGuardClass,
): Promise<void> {
  try {
    await bumpAdminCounter(scheduler, updateRefusalCounter(guard) as AdminCounterName);
  } catch {
    /* best-effort */
  }
  try {
    await recordUpdateRefusal(scheduler, caller, sourceIp, guard);
  } catch {
    /* best-effort */
  }
}

// noteUpdateAttempt (G275) counts the ATTEMPT itself, which the pending record cannot: `updates.last` keeps
// only the most recent OUTCOME, so a night of repeated settle attempts collapses to one row and "the ramp has
// been pending verification for two days, how many settle attempts were inconclusive?" -- the question that
// decides whether the ramp is stuck or the verification is genuinely slow -- has no answer at all. A
// cumulative count survives every outcome that overwrites the last one.
export async function noteUpdateAttempt(scheduler: DurableObjectStub, kind: "settle-inconclusive" | "settle-refused" | "rollback-refused"): Promise<void> {
  try {
    await bumpAdminCounter(scheduler, `update-${kind}` as AdminCounterName);
  } catch {
    /* best-effort */
  }
}

// noteUpdateDegradations (G332) counts the SILENT WEAKENINGS of the update safety machinery: a replay claim
// that could not be parsed and was therefore not enforced, a components map that would not read (so the
// console half of the release silently never ships), a provenance block that was dropped, a deploy that fell
// back to the legacy artefact mirror. Each is a control the customer believes is in force. Closed names only.
export async function noteUpdateDegradations(scheduler: DurableObjectStub, names: readonly string[]): Promise<void> {
  try {
    const bumps: Record<string, number> = {};
    for (const n of names) bumps[n] = (bumps[n] ?? 0) + 1;
    await bumpAdminCounters(scheduler, bumps as Partial<Record<AdminCounterName, number>>);
  } catch {
    /* best-effort */
  }
}
