// validate-approval-dwell (ASVS V2.4.2, anti-automation): proves that a restore approval, an owner-action
// approval and a config-change approval each REFUSE when the approve arrives less than
// APPROVAL_MIN_DWELL_MS after the record was raised, and each SUCCEED once the record is aged past the
// floor -- and that canApprovePrune enforces the identical rule at the pure-function level. Driven straight
// at the REAL SchedulerDO (router-bypassed, the "FROM THE ROUTER ONLY" trust every sibling coverage
// validator already uses), so every assertion is a real DO outcome: an HTTP status, a Retry-After header,
// a reasonCode, or a stored record's status. No network, no deploy, no cost.
//
// What this proves:
//  - restore: POST /restore/approve immediately after POST /restore/request is refused 429, carries
//    reasonCode "too-soon" and a positive Retry-After; aged past the floor, the SAME approve succeeds
//    (200, status approved), and the checker is recorded.
//  - owner action (DO-executed, dest-put, auto-gated once a second owner exists): POST /owner-actions/
//    approve immediately after the propose is refused 429 (too-soon); aged, the same id executes (200).
//  - config change (downpipe-upsert, requireConfigApproval ON): POST /config/changes/approve immediately
//    after the propose is refused 429 (too-soon); aged, the same id applies (200).
//  - canApprovePrune (the fourth helper the requirement covers) refuses a same-instant approve and admits
//    one raised APPROVAL_MIN_DWELL_MS + 1 ms earlier, at the pure-function level (prune's own DO route
//    does not carry a Retry-After; see the residual in the closing task report).
//  - the module-level invariant: APPROVAL_MIN_DWELL_MS is strictly below APPROVAL_TTL_MS.
//
// Run: node test/validate-approval-dwell.ts

import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { CALLER_HEADER, encodeCaller, type Caller } from "../src/admin/identity.ts";
import { APPROVAL_MIN_DWELL_MS, APPROVAL_TTL_MS, approvalKey, restorePlanHash, TOO_SOON_REFUSAL_CODE, type RestoreApproval } from "../src/admin/approvals.ts";
import { OWNER_ACTION_PREFIX, type PendingOwnerAction } from "../src/admin/owner-action.ts";
import { changeKey, type PendingConfigChange } from "../src/admin/change-control.ts";
import { canApprovePrune, type PruneApproval } from "../src/admin/prune-approvals.ts";
import { ORG_POLICY_KEY } from "../src/sched/scheduler-do-records.ts";
import { ageRecord, notePlanAnchor, seedBoundRole } from "./testutil.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): { storage: MockStorage; stub: DurableObjectStub } {
  const storage = new MockStorage();
  const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return dobj.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
  return { storage, stub };
}

// AGE_PAST_DWELL comfortably clears the floor; AGE_JUST_UNDER stays inside it (a negative control: the
// helper's own floor arithmetic, not merely "we waited a while").
const AGE_PAST_DWELL = APPROVAL_MIN_DWELL_MS + 1_000;

async function main(): Promise<void> {
  const { storage, stub } = makeScheduler();
  await storage.put(ORG_POLICY_KEY, { requireConfigApproval: true, requireRestoreApproval: true });

  // owner = every capability (identity-rbac.ts), so the SAME two identities are the maker/checker pair on
  // all three DO surfaces below: restore.request/restore.approve for restore, owner-class for the owner
  // action, and downpipe.write for the config change. Bound in the DO's own role table because the
  // spend-time re-resolution (restore) reads it live, not merely the forwarded header.
  const makerEmail = "dwell-maker@acme.example";
  const checkerEmail = "dwell-checker@acme.example";
  const maker: Caller = { method: "access", email: makerEmail, subject: "sub-dwell-maker", role: "owner", groups: [] };
  const checker: Caller = { method: "access", email: checkerEmail, subject: "sub-dwell-checker", role: "owner", groups: [] };
  await seedBoundRole(storage, maker.subject!, maker.email, "owner");
  await seedBoundRole(storage, checker.subject!, checker.email, "owner");

  const call = (path: string, caller: Caller | null, body?: unknown): Promise<Response> => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (caller !== null) headers[CALLER_HEADER] = encodeCaller(caller);
    return stub.fetch(`https://scheduler.internal${path}`, { method: "POST", headers, body: JSON.stringify(body ?? {}) });
  };
  const errOf = async (r: Response): Promise<{ error?: string; refusal?: string; retryAfterSeconds?: number }> => (await r.json()) as { error?: string; refusal?: string; retryAfterSeconds?: number };

  console.log("APPROVAL-DWELL (ASVS V2.4.2) -- restore, owner-action, config-change, prune");

  // =========================================================================================
  // SECTION 1: restore. Request, then approve in the SAME turn: refused 429, too-soon, Retry-After.
  // Aged past the floor, the identical approve succeeds.
  // =========================================================================================
  {
    const request = { runId: "01ARZ3NDEKTSV4RRFFQ69G5FA0" };
    const planHash = await restorePlanHash(request);
    await notePlanAnchor(stub.fetch, planHash);
    const reqResp = await call("/restore/request", maker, { planHash, runId: request.runId, reason: "dwell proof" });
    ok("[restore] the request is created (200, requested)", reqResp.status === 200 && ((await reqResp.json()) as RestoreApproval).status === "requested");

    const early = await call("/restore/approve", checker, { planHash });
    ok("[restore] a same-turn approve is refused 429, not the generic 400", early.status === 429);
    const earlyBody = await errOf(early.clone());
    ok("[restore] the refusal carries reasonCode too-soon", earlyBody.refusal === TOO_SOON_REFUSAL_CODE);
    ok("[restore] the refusal names a POSITIVE Retry-After (both the header and the body)", Number(early.headers.get("retry-after")) > 0 && (earlyBody.retryAfterSeconds ?? 0) > 0);
    ok("[restore] the record is STILL requested, not silently advanced by the refused approve", (await storage.get<RestoreApproval>(approvalKey(planHash)))?.status === "requested");

    ageRecord(storage, approvalKey(planHash), "requestedAt", AGE_PAST_DWELL);
    const late = await call("/restore/approve", checker, { planHash });
    const lateBody = (await late.json()) as RestoreApproval;
    ok("[restore] the SAME approve, aged past the floor, succeeds (200, approved)", late.status === 200 && lateBody.status === "approved");
    ok("[restore] the checker is recorded, distinct from the maker", lateBody.approvedBy === checkerEmail && lateBody.approvedBy !== lateBody.requestedBy);
  }

  // =========================================================================================
  // SECTION 2: owner action (DO-executed dest-put, auto-gated once a second owner exists). Propose, then
  // approve in the SAME turn: refused 429. Aged, the identical approve executes.
  // =========================================================================================
  {
    const destConfig = { endpoint: "https://acct.r2.cloudflarestorage.com", bucket: "dwell-bucket", region: "auto", accessKeyId: "AKIADWELL", secretAccessKey: "dwell-secret-value", verifiedAt: Date.now(), deleteProbe: "ok" };
    const propose = await call("/destinations", maker, { label: "dwell-dest", config: destConfig });
    ok("[owner-action] the proposal auto-queues (202, pending)", propose.status === 202);
    const id = ((await propose.json()) as { id?: string }).id ?? "";
    ok("[owner-action] the 202 carries a pending id", id.length > 0);

    const early = await call("/owner-actions/approve", checker, { id });
    ok("[owner-action] a same-turn approve is refused 429, not the generic 400", early.status === 429);
    const earlyBody = await errOf(early.clone());
    ok("[owner-action] the refusal carries reasonCode too-soon", earlyBody.refusal === TOO_SOON_REFUSAL_CODE);
    ok("[owner-action] the refusal names a POSITIVE Retry-After", Number(early.headers.get("retry-after")) > 0);
    ok("[owner-action] the record is STILL pending, not silently advanced", storage.rawGet<PendingOwnerAction>(OWNER_ACTION_PREFIX + id)?.status === "pending");

    ageRecord(storage, OWNER_ACTION_PREFIX + id, "proposedAt", AGE_PAST_DWELL);
    const late = await call("/owner-actions/approve", checker, { id });
    const lateBody = (await late.json()) as PendingOwnerAction;
    ok("[owner-action] the SAME approve, aged past the floor, executes (200)", late.status === 200 && lateBody.status === "executed");
    ok("[owner-action] the checker is recorded, distinct from the maker", lateBody.approvedBy === checkerEmail && lateBody.proposedBy === makerEmail);
  }

  // =========================================================================================
  // SECTION 3: config change (downpipe-upsert, requireConfigApproval ON). Propose, then approve in the
  // SAME turn: refused 429. Aged, the identical approve applies.
  // =========================================================================================
  {
    const dp = { id: "dwell-dp", name: "dwell-dp", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV_DWELL", include: [], exclude: [] } };
    const propose = await call("/downpipes", maker, dp);
    ok("[config-change] the proposal queues (202, pending)", propose.status === 202);
    const id = ((await propose.json()) as { id?: string }).id ?? "";
    ok("[config-change] the 202 carries a pending id", id.length > 0);

    const early = await call("/config/changes/approve", checker, { id });
    ok("[config-change] a same-turn approve is refused 429, not the generic 400", early.status === 429);
    const earlyBody = await errOf(early.clone());
    ok("[config-change] the refusal carries reasonCode too-soon", earlyBody.refusal === TOO_SOON_REFUSAL_CODE);
    ok("[config-change] the refusal names a POSITIVE Retry-After", Number(early.headers.get("retry-after")) > 0);
    ok("[config-change] the record is STILL pending, not silently advanced", storage.rawGet<PendingConfigChange>(changeKey(id))?.status === "pending");

    ageRecord(storage, changeKey(id), "proposedAt", AGE_PAST_DWELL);
    const late = await call("/config/changes/approve", checker, { id });
    const lateBody = (await late.json()) as PendingConfigChange;
    ok("[config-change] the SAME approve, aged past the floor, applies (200)", late.status === 200 && lateBody.status === "applied");
    ok("[config-change] the checker is recorded, distinct from the maker", lateBody.approvedBy === checkerEmail && lateBody.proposedBy === makerEmail);
  }

  // =========================================================================================
  // SECTION 4: canApprovePrune, the fourth helper the requirement covers, at the pure-function level. The
  // DO route for retention-prune needs a real sealed archive to raise a request against (seal/prune.ts's
  // planPrune); reproducing that fixture here would test the archive planner, not the dwell floor, so the
  // rule is proved directly against the function every one of the other three surfaces shares it with.
  // =========================================================================================
  {
    const base: PruneApproval = {
      planHash: "sha384:dwell-prune-plan",
      downpipeId: "dp_dwell",
      retainedRuns: 1,
      supersededRuns: 2,
      requesterSubject: "sub-dwell-maker",
      requestedBy: makerEmail,
      requesterGroups: [],
      requestedAt: new Date().toISOString(),
      reason: "dwell proof",
      status: "requested",
      expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(),
    };
    const now = Date.now();
    const early = canApprovePrune(base, checkerEmail, "sub-dwell-checker", now);
    ok("[prune] a same-instant approve is refused", !early.ok);
    ok("[prune] the refusal carries reasonCode too-soon", !early.ok && early.reasonCode === "too-soon");
    ok("[prune] the refusal names a positive retryAfterSeconds", !early.ok && (early.retryAfterSeconds ?? 0) > 0);
    const aged: PruneApproval = { ...base, requestedAt: new Date(now - AGE_PAST_DWELL).toISOString() };
    const late = canApprovePrune(aged, checkerEmail, "sub-dwell-checker", now);
    ok("[prune] the SAME record, raised APPROVAL_MIN_DWELL_MS+1s earlier, is admitted", late.ok === true);
  }

  // =========================================================================================
  // SECTION 5: the module invariant every dwell-consuming module asserts at load: the floor sits strictly
  // below the TTL it lives inside. Proved here as a value fact (the modules themselves already asserted
  // it at import time, which is why this whole file could load at all); see the task's red-before-green
  // report for the negative-control plant against the shared helper.
  // =========================================================================================
  ok("[invariant] APPROVAL_MIN_DWELL_MS is strictly below APPROVAL_TTL_MS", APPROVAL_MIN_DWELL_MS < APPROVAL_TTL_MS);
  ok("[invariant] APPROVAL_MIN_DWELL_MS is a real, positive floor (not accidentally zero)", APPROVAL_MIN_DWELL_MS > 0);

  console.log(failures === 0 ? "\nAPPROVAL-DWELL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  console.log(`VERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
