// The SchedulerDO posture routes: POST /posture computes from the router slice + DO state, snapshots, and
// returns regressions; accept/unaccept re-check posture.riskaccept (a non-owner is refused); an unknown
// checkId is rejected; a second compute after a check flips to failing returns the regression; and a
// malformed compute slice degrades to a conservative posture rather than a fabricated green. In-memory DO
// doubles only; no network. The orchestrator (validate-posture.ts) awaits runRoutes() after runCompute().
//
// runRoutes() is factored into named per-section helpers, each exercising one banner-delimited group,
// awaited here in a fixed order through the same shared ok() counter.

import type { PostureReport } from "../src/admin/posture.ts";
import {
  ok,
  byId,
  makeScheduler,
  fetchDO,
  OWNER_HEADER,
  ACCESS_ADMIN_HEADER,
  OWNER_ACCESS_HEADER,
} from "./validate-posture-shared.ts";

export async function runRoutes(): Promise<void> {
  await routesComputeAndAccept();
  await routesRegressionEmission();
  await routesMalformedSliceDegrades();
  await routesRestoreTestRecencyGrades();
}

// ---- DO routes: compute + risk-accept/unaccept + capability re-check ----------------------
async function routesComputeAndAccept(): Promise<void> {
  const { stub, storage } = makeScheduler();
  // Seed two owners so two-owners passes (the DO counts role: owner entries). The DO's role table is
  // keyed by email; seed two owner entries directly via the storage (mirroring how the role tests do).
  await storage.put("role:o1@example.au", { email: "o1@example.au", role: "owner", grantedBy: "bootstrap", grantedAt: "2026-01-01T00:00:00.000Z" });
  await storage.put("role:o2@example.au", { email: "o2@example.au", role: "owner", grantedBy: "o1@example.au", grantedAt: "2026-01-01T00:00:00.000Z" });
  // Add a downpipe with the cadence on and a recent successful test, and a failure rule + channel so
  // failure-alerts passes.
  await fetchDO(stub, "POST", "/downpipes", { id: "dp1", name: "Primary", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] }, restoreTestCadenceSeconds: 604800 }, OWNER_HEADER);
  await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp1", ok: true, at: Date.now() });
  await fetchDO(stub, "POST", "/notify/channels", { kind: "webhook", name: "ops", url: "https://hooks.example.au/x", enabled: true }, OWNER_HEADER);
  await fetchDO(stub, "POST", "/notify/rules", { scope: { kind: "global" }, minSeverity: "warning", events: ["backup-failure"], channelIds: [], enabled: true }, OWNER_HEADER);

  // Compute posture: the router slice says dest + break-glass configured, no operational-private, Access.
  const slice = { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true };
  const r1Resp = await fetchDO(stub, "POST", "/posture", { status: slice, authMethod: "access", beaconEnabled: false });
  ok("DO: POST /posture 200", r1Resp.status === 200);
  const { report: r1, regressions: reg1 } = (await r1Resp.json()) as { report: PostureReport; regressions: Array<{ id: string }> };
  const m1 = byId(r1);
  ok("DO: two-owners passes (two seeded owners)", m1.get("two-owners")?.status === "pass");
  ok("DO: failure-alerts passes (a failure rule exists)", m1.get("failure-alerts")?.status === "pass");
  ok("DO: restore-test-recency passes (recent ok test)", m1.get("restore-test-recency")?.status === "pass");
  ok("DO: first compute has no regressions (no prior snapshot)", reg1.length === 0);
  ok("DO: a snapshot was persisted", storage.has("posture-snapshot"));

  // Risk-accept: a non-owner (access-admin) is refused (DO defence-in-depth posture.riskaccept re-check).
  const denied = await fetchDO(stub, "POST", "/posture/accept", { checkId: "operational-private-weakening", reason: "accepted by SRE lead" }, ACCESS_ADMIN_HEADER);
  ok("DO: non-owner accept refused (403)", denied.status === 403);
  // An unknown checkId is rejected even for an owner.
  const badId = await fetchDO(stub, "POST", "/posture/accept", { checkId: "not-a-real-check", reason: "x" }, OWNER_ACCESS_HEADER);
  ok("DO: unknown checkId rejected (400)", badId.status === 400);
  // A missing reason is rejected.
  const noReason = await fetchDO(stub, "POST", "/posture/accept", { checkId: "beacon-off" }, OWNER_ACCESS_HEADER);
  ok("DO: missing reason rejected (400)", noReason.status === 400);

  // An unknown override KIND is rejected; the four known kinds are accepted.
  const badKind = await fetchDO(stub, "POST", "/posture/accept", { checkId: "beacon-off", reason: "x", kind: "waived" }, OWNER_ACCESS_HEADER);
  ok("DO: unknown override kind rejected (400)", badKind.status === 400);

  // An owner accepts a (currently-passing) check with NO kind: the record stores the legacy default
  // (risk-accepted), so an older console keeps working unchanged.
  const accepted = await fetchDO(stub, "POST", "/posture/accept", { checkId: "operational-private-weakening", reason: "accepted: offline rehearsal documented" }, OWNER_ACCESS_HEADER);
  ok("DO: owner accept 200", accepted.status === 200);
  ok("DO: accept record stored", storage.has("posture-accept:operational-private-weakening"));
  const rec = storage.rawGet<{ checkId: string; acceptedBy: string | null; reason: string; kind?: string }>("posture-accept:operational-private-weakening");
  ok("DO: accept record carries the owner email + reason", rec?.acceptedBy === "o@example.au" && rec?.reason === "accepted: offline rehearsal documented");
  ok("DO: a kind-less accept stores the legacy default (risk-accepted)", rec?.kind === "risk-accepted");

  // An owner records an ATTESTED-PASS override with a kind: stored, and the computed report carries the
  // override (kind + reason) on the check with the attested-pass status folded.
  const attested = await fetchDO(stub, "POST", "/posture/accept", { checkId: "media-diversity", reason: "destinations span two providers per policy", kind: "attested-pass" }, OWNER_ACCESS_HEADER);
  ok("DO: attested-pass accept 200", attested.status === 200);
  const attRec = storage.rawGet<{ kind?: string }>("posture-accept:media-diversity");
  ok("DO: the attested-pass kind is stored", attRec?.kind === "attested-pass");
  const afterResp = await fetchDO(stub, "POST", "/posture", { status: { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true }, beaconEnabled: false });
  const after = (await afterResp.json()) as { report: PostureReport };
  const mAfter = byId(after.report);
  // The seeded downpipe does not fan out, so media-diversity auto-passes; the override rides dormant.
  ok("DO: the computed check carries the stored override (kind + reason)", mAfter.get("media-diversity")?.override?.kind === "attested-pass" && (mAfter.get("media-diversity")?.override?.reason ?? "").includes("two providers"));
  await fetchDO(stub, "POST", "/posture/unaccept", { checkId: "media-diversity" }, OWNER_ACCESS_HEADER);

  // A NOT-APPLICABLE override pins the status and excludes the check from the score.
  const na = await fetchDO(stub, "POST", "/posture/accept", { checkId: "two-owners", reason: "sole-trader deployment", kind: "not-applicable" }, OWNER_ACCESS_HEADER);
  ok("DO: not-applicable accept 200", na.status === 200);
  const naResp = await fetchDO(stub, "POST", "/posture", { status: { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true }, beaconEnabled: false });
  const naReport = (await naResp.json()) as { report: PostureReport };
  ok("DO: a not-applicable override pins the status to not-applicable", byId(naReport.report).get("two-owners")?.status === "not-applicable");
  await fetchDO(stub, "POST", "/posture/unaccept", { checkId: "two-owners" }, OWNER_ACCESS_HEADER);

  // recipient-set-expected appears at its documented HIGH severity in a real computed report (r1, above,
  // from the same slice every other check in this test reads), and an owner can attest, accept and withdraw
  // it exactly like any other check.
  ok("recipient-set-expected appears in a computed report at HIGH severity", m1.get("recipient-set-expected")?.severity === "high");
  const rseDenied = await fetchDO(stub, "POST", "/posture/accept", { checkId: "recipient-set-expected", reason: "accepted by SRE lead" }, ACCESS_ADMIN_HEADER);
  ok("DO: a non-owner is refused accepting recipient-set-expected (403, same re-check as every other check)", rseDenied.status === 403);
  const rseAccepted = await fetchDO(stub, "POST", "/posture/accept", { checkId: "recipient-set-expected", reason: "rotated the seal recipient deliberately; export pending" }, OWNER_ACCESS_HEADER);
  ok("DO: an owner CAN NOW accept recipient-set-expected (200, was 400 unknown-checkId before the fix)", rseAccepted.status === 200);
  ok("DO: the accept record was stored", storage.has("posture-accept:recipient-set-expected"));
  const rseReport = (await (await fetchDO(stub, "POST", "/posture", { status: { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true }, beaconEnabled: false })).json()) as { report: PostureReport };
  const rseCheck = byId(rseReport.report).get("recipient-set-expected");
  ok("DO: the computed check carries the stored override (kind + reason) at its real HIGH severity", rseCheck?.severity === "high" && rseCheck?.override?.reason === "rotated the seal recipient deliberately; export pending");
  const rseUnaccepted = await fetchDO(stub, "POST", "/posture/unaccept", { checkId: "recipient-set-expected" }, OWNER_ACCESS_HEADER);
  ok("DO: an owner can withdraw the recipient-set-expected override", rseUnaccepted.status === 200);

  // The scheduled-evaluation due check: due with no snapshot; not due right after a compute; due again
  // when the interval is tiny.
  {
    const fresh = makeScheduler();
    const due0 = (await (await fetchDO(fresh.stub, "POST", "/posture/evaluation-due", { intervalMs: 60_000 })).json()) as { due: boolean };
    ok("DO: evaluation-due is true with no snapshot", due0.due === true);
    await fetchDO(fresh.stub, "POST", "/posture", { status: { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true }, beaconEnabled: false });
    const due1 = (await (await fetchDO(fresh.stub, "POST", "/posture/evaluation-due", { intervalMs: 60_000 })).json()) as { due: boolean; lastEvaluatedAt: string | null };
    ok("DO: evaluation-due is false right after a compute", due1.due === false && typeof due1.lastEvaluatedAt === "string");
    const due2 = (await (await fetchDO(fresh.stub, "POST", "/posture/evaluation-due", { intervalMs: 0 })).json()) as { due: boolean };
    ok("DO: a garbled interval falls back to the default (not due right after a compute)", due2.due === false);
  }

  // Unaccept removes it (idempotent), and a non-owner cannot unaccept.
  const unDenied = await fetchDO(stub, "POST", "/posture/unaccept", { checkId: "operational-private-weakening" }, ACCESS_ADMIN_HEADER);
  ok("DO: non-owner unaccept refused (403)", unDenied.status === 403);
  const un = (await (await fetchDO(stub, "POST", "/posture/unaccept", { checkId: "operational-private-weakening" }, OWNER_ACCESS_HEADER)).json()) as { ok: boolean; removed: boolean };
  ok("DO: owner unaccept removed:true", un.removed === true);
  ok("DO: accept record gone", !storage.has("posture-accept:operational-private-weakening"));
  const un2 = (await (await fetchDO(stub, "POST", "/posture/unaccept", { checkId: "operational-private-weakening" }, OWNER_ACCESS_HEADER)).json()) as { removed: boolean };
  ok("DO: unaccept idempotent (removed:false the second time)", un2.removed === false);
}

// ---- DO regression emission across two computes -------------------------------------------
async function routesRegressionEmission(): Promise<void> {
  const { stub } = makeScheduler();
  await fetchDO(stub, "POST", "/downpipes", { id: "dp1", name: "Primary", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp1", include: [], exclude: [] }, restoreTestCadenceSeconds: 604800 }, OWNER_HEADER);
  await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp1", ok: true, at: Date.now() });
  // First compute with dest configured: destination-configured passes, snapshot recorded.
  const sliceGood = { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true };
  await fetchDO(stub, "POST", "/posture", { status: sliceGood, authMethod: "access", beaconEnabled: false });
  // Second compute with dest NOT configured: destination-configured regresses, returned for routing.
  const sliceBad = { destConfigured: false, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true };
  const r2 = (await (await fetchDO(stub, "POST", "/posture", { status: sliceBad, authMethod: "access", beaconEnabled: false })).json()) as { regressions: Array<{ id: string; severity: string }> };
  ok("DO: a check that flips to failing is returned as a regression", r2.regressions.some((x) => x.id === "destination-configured"));
  ok("DO: the regression carries critical severity", r2.regressions.find((x) => x.id === "destination-configured")?.severity === "critical");
}

// ---- a malformed compute slice degrades to a conservative posture, never a fabricated green --
async function routesMalformedSliceDegrades(): Promise<void> {
  const { stub } = makeScheduler();
  // No status slice at all: every presence boolean defaults to its worse-posture reading. dest +
  // break-glass checks fail; access-enforced fails (adminTokenPresent defaults true = a shared-token
  // path may exist). The compute must not throw.
  const r = await fetchDO(stub, "POST", "/posture", {});
  ok("DO: a missing slice still computes (200)", r.status === 200);
  const { report } = (await r.json()) as { report: PostureReport };
  const m = byId(report);
  ok("DO: missing slice -> destination-configured fails (conservative)", m.get("destination-configured")?.status === "fail");
  ok("DO: missing slice -> access-enforced fails (conservative)", m.get("access-enforced")?.status === "fail");
}

// ---- restore-test-recency actually GRADES through the real gather->compute path --------
// The CRITICAL restore-test-recency check must not gate its graded set on a field the DownpipeState never
// holds and gatherPostureState never projects, which would leave the set ALWAYS empty and the check ALWAYS
// passing however stale the restore tests were (a critical check that can never fail). These vectors drive
// the EXACT production path so the projection itself is exercised: a
// downpipe created via POST /downpipes, a real run recorded via /trigger + /complete (so lastRunId is
// set on the DownpipeState), and a scheduled restore test recorded via /restore-test-complete with a
// backdated `at`. A pure computePosture test over a hand-built PostureInput bypasses gatherPostureState
// and would NOT catch this, which is exactly why the bug survived. A downpipe with a source binding is
// created; the DO double records the run/test state directly, no seal I/O is invoked.
async function routesRestoreTestRecencyGrades(): Promise<void> {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const slice = { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true };
  // Drive the real POST /posture path and index the returned checks by id.
  const postureChecks = async (stub: Parameters<typeof fetchDO>[0]) => {
    const { report } = (await (await fetchDO(stub, "POST", "/posture", { status: slice, beaconEnabled: false })).json()) as { report: PostureReport };
    return byId(report);
  };
  // seedRun creates a downpipe and records ONE successful run through the DO (so lastRunId is set,
  // exactly as a real completion does), returning the stub for a follow-up restore-test + posture read.
  const seedRun = async (id: string): Promise<Parameters<typeof fetchDO>[0]> => {
    const { stub } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp", include: [], exclude: [] }, restoreTestCadenceSeconds: 604800 }, OWNER_HEADER);
    const trig = (await (await fetchDO(stub, "POST", "/trigger", { id })).json()) as { runId: string; index: number };
    await fetchDO(stub, "POST", "/complete", { id, runId: trig.runId, index: trig.index });
    return stub;
  };

  // A downpipe that has completed a run but whose last SUCCESSFUL restore test is STALE (>180d) FAILS.
  {
    const stub = await seedRun("dp-stale");
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-stale", ok: true, at: Date.now() - 200 * DAY_MS });
    const c = (await postureChecks(stub)).get("restore-test-recency");
    ok("recency(real path): a stale (>180d) successful restore test FAILS the critical check", c?.status === "fail");
    ok("recency(real path): the failing detail cites the 180-day window", (c?.detail ?? "").includes("180 days"));
  }
  // The same setup with a RECENT successful restore test PASSES.
  {
    const stub = await seedRun("dp-fresh");
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-fresh", ok: true, at: Date.now() - 2 * DAY_MS });
    ok("recency(real path): a recent successful restore test PASSES the check", (await postureChecks(stub)).get("restore-test-recency")?.status === "pass");
  }
  // A test in the 90-180d WARN band passes the critical check but is noted in the detail.
  {
    const stub = await seedRun("dp-warn");
    await fetchDO(stub, "POST", "/restore-test-complete", { id: "dp-warn", ok: true, at: Date.now() - 120 * DAY_MS });
    const c = (await postureChecks(stub)).get("restore-test-recency");
    ok("recency(real path): a 120d test passes but is flagged in the warn band", c?.status === "pass" && (c?.detail ?? "").includes("older than 90 days"));
  }
  // A downpipe that has completed a run but NEVER had a restore test FAILS (it has a sealed archive to
  // test; an absent successful test is a real finding once there is something to restore).
  {
    const stub = await seedRun("dp-untested");
    ok("recency(real path): a run with no restore test yet FAILS", (await postureChecks(stub)).get("restore-test-recency")?.status === "fail");
  }
  // A NEVER-RUN downpipe (no lastRunId) is EXCLUDED from the grade: no sealed archive to restore-test
  // yet, so it is named in the detail, not failed. With only never-run downpipes the check passes.
  {
    const { stub } = makeScheduler();
    await fetchDO(stub, "POST", "/downpipes", { id: "dp-new", name: "Brand new", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_dp", include: [], exclude: [] }, restoreTestCadenceSeconds: 604800 }, OWNER_HEADER);
    const c = (await postureChecks(stub)).get("restore-test-recency");
    ok("recency(real path): a never-run downpipe is excluded, so the check passes", c?.status === "pass");
    ok("recency(real path): the never-run downpipe is named in the detail", (c?.detail ?? "").includes("not yet completed a first run"));
  }
}
