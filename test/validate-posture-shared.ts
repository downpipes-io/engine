// Shared fixtures and in-memory doubles for the posture vectors. The suite is split across
// validate-posture-compute.ts (the pure computePosture groups) and validate-posture-routes.ts (the DO
// routes), orchestrated in order by validate-posture.ts. Every group records assertions through the single
// shared ok() so the one failures counter and the final summary in the orchestrator stay authoritative.
// In-memory doubles only; no network, no deploy, no cost.

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import type { PostureInput, PostureOverrideInput, PostureOverrideKind, PostureReport, PostureCheck } from "../src/admin/posture.ts";

// The single failures counter shared by every group. The orchestrator reads it for the final summary and
// the exit code.
let failures = 0;
export function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
export function failureCount(): number {
  return failures;
}

import { MockStorage } from "./mock-storage.ts";
export { MockStorage };

export function makeScheduler(): { storage: MockStorage; stub: SchedulerDO } {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return { storage, stub: new SchedulerDO(state) };
}

export const OWNER_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };
export const OWNER_HEADER = encodeCaller(OWNER_CALLER);
// access-admin holds NO posture.riskaccept (it is owner-only), so it proves the DO's defence-in-depth
// re-check refuses an unauthorised accept/unaccept even though access-admin can manage people.
export const ACCESS_ADMIN_CALLER: Caller = { method: "access", email: "a@example.au", subject: "subject-a@example.au", role: "access-admin", groups: [] };
export const ACCESS_ADMIN_HEADER = encodeCaller(ACCESS_ADMIN_CALLER);
// An owner via Access (an attributable owner) for the accept audit/acceptedBy path.
export const OWNER_ACCESS_CALLER: Caller = { method: "access", email: "o@example.au", subject: "subject-o@example.au", role: "owner", groups: [] };
export const OWNER_ACCESS_HEADER = encodeCaller(OWNER_ACCESS_CALLER);

export function fetchDO(dobj: SchedulerDO, method: string, path: string, body?: unknown, header?: string): Promise<Response> {
  const url = `https://scheduler.internal${path}`;
  const headers: Record<string, string> = {
    ...(body !== undefined ? { "content-type": "application/json" } : {}),
    ...(header !== undefined ? { "x-downpipe-caller": header } : {}),
  };
  const init: RequestInit = { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) };
  return dobj.fetch(new Request(url, init));
}

export const DAY = 24 * 60 * 60 * 1000;
export const NOW = Date.parse("2026-06-09T00:00:00.000Z");

// byId indexes a report's checks for assertions.
export function byId(report: PostureReport): Map<string, PostureCheck> {
  return new Map(report.checks.map((c) => [c.id, c]));
}

// overrideFor builds one owner-override input record for a fixture (the shape gatherPostureState
// projects from a stored RiskAccept via overrideOf).
export function overrideFor(kind: PostureOverrideKind, reason = "test override"): PostureOverrideInput {
  return { kind, reason, setBy: "o@example.au", setAt: "2026-06-01T00:00:00.000Z" };
}

// A fully-healthy input: no live shared-token path (attributable access), two owners with passkeys and no
// IdP bypass (admin-strong-auth platform-verified), every downpipe recently restore-tested with the
// cadence on, failure alerts configured, destination + break-glass configured, no operational-private,
// no expiring credentials, beacon off. media-diversity carries the Owner's ATTESTED-PASS override (the
// cloud-only platform cannot verify the "two media" leg itself), so every check is score-positive.
export function healthyInput(): PostureInput {
  return {
    status: { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true, adminTokenPresent: false, bootstrapConsumed: true, breakGlassTokenRetired: false, recoveryBreakGlassReady: true },
    downpipes: [
      // destinationCount 2 => the downpipe fans out (redundant-copies passes). A healthy posture is
      // genuinely 3-2-1, so media-diversity is attested below.
      { id: "dp1", name: "Primary", destinationCount: 2, restoreTestCadenceSeconds: 604800, lastRestoreTestAt: NOW - 2 * DAY, lastRestoreTestOk: true, lastRunId: "run-dp1" },
    ],
    expiry: [{ label: "S3 key", state: "ok" }],
    notifyFailureRuleSet: true,
    ownerCount: 2,
    operationalPrivatePresent: false,
    // A healthy estate has a signed export whose recorded recipient set matches the live one. Left absent,
    // the check would honestly report cannot-verify and the "everything passes" fixture would no longer
    // mean what its name says.
    recipientPinDrift: { matches: true, added: 0, removed: 0 },
    beaconEnabled: false,
    // media-diversity is operator-ATTESTED (cloud-only cannot self-verify the "two media" leg); a
    // healthy posture has the Owner's attested-pass override, so it counts as a pass.
    overrides: new Map([["media-diversity", overrideFor("attested-pass", "destinations span two providers per policy")]]),
    // Both admin identities hold passkeys and no IdP connection is enabled, so admin-strong-auth is
    // platform-verified in the healthy baseline.
    identity: { adminIdentities: 2, adminsWithPasskey: 2, idpConnectionsEnabled: 0 },
  };
}
