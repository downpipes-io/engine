// PROOF AUDIT-VERIFY (runs last, after all earlier proofs have logged their events) + the large-keyspace
// PROOF 14 of the config change-control validator: the audit chain still
// VERIFIES over every recorded change-control event, and a keyspace LARGER than the DO list page is
// captured + restored fully by the dry-run so a mere proposal leaves no side effect at
// tenant scale. Split out for size; byte-identical, runs in order. The audit proof
// reads the shared live DO; the scale proof spins up its OWN paged DO.

import type { Ctx } from "./validate-config-change-control-harness.ts";
import {
  TEAM,
  AUD,
  OWNER,
  OWNER2,
  OPERATOR,
  OPERATOR2,
  PLATFORM_LIST_PAGE,
  makePagedScheduler,
} from "./validate-config-change-control-harness.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { verifyChain } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";

export async function runAuditAndScale(ctx: Ctx): Promise<void> {
  const { ok, call, readLog, tokenFor, ADMIN_TOKEN, dp } = ctx;

  // ===========================================================================================
  // PROOF AUDIT-VERIFY (runs last): the audit chain still VERIFIES over all the recorded change-control events
  // ===========================================================================================
  {
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean; checkedThrough: number };
    ok("the audit chain verifies intact after the change-control flow", verify.intact === true && verify.checkedThrough >= 1);
    const log = await readLog();
    const ascending = [...log.events].reverse();
    const independent = await verifyChain(ascending);
    ok("an independent re-verification agrees the chain is intact", independent.intact === true);
    const actions = new Set(log.events.map((e) => e.action));
    ok("config-change-propose events are in the chain", actions.has("config-change-propose"));
    ok("config-change-approve events are in the chain", actions.has("config-change-approve"));
    ok("config-change-reject events are in the chain", actions.has("config-change-reject"));
    ok("config-change-supersede events are in the chain", actions.has("config-change-supersede"));
    ok("config-policy-change events are in the chain (the toggle)", actions.has("config-policy-change"));
  }

  // ===========================================================================================
  // PROOF 14: a keyspace LARGER than the DO list page is captured + restored fully by the dry-run.
  // dryRunConfigMutation must checkpoint AND roll back over the WHOLE keyspace.
  // A bare list() truncates at one page, so a proposed downpipe whose key sorts beyond the page would
  // NOT be rolled back and would persist after a mere proposal. With the paginated full-prefix scan the
  // proposal leaves NO side effect regardless of tenant scale.
  // ===========================================================================================
  {
    const paged = makePagedScheduler();
    const pagedEnv = (): Env => ({ ...paged.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD, ADMIN_TOKEN }) as unknown as Env;
    async function pagedCall(email: string, method: "GET" | "POST", path: string, body?: unknown): Promise<Response> {
      const assertion = await tokenFor(email);
      const init: RequestInit = {
        method,
        headers: { "cf-access-jwt-assertion": assertion, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      };
      return handleAdmin(new Request(`https://engine.example${path}`, init), pagedEnv());
    }
    // Bootstrap an Owner + an operator that holds downpipe.write on this fresh DO.
    await pagedCall(OWNER, "GET", "/admin/whoami");
    // A second Owner so the dual-control gate can be armed below (the two-Owner enable floor); granted inline
    // while this fresh DO has one Owner and the gate is off.
    await pagedCall(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
    await pagedCall(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "operator" });
    await pagedCall(OWNER, "POST", "/admin/roles", { email: OPERATOR2, role: "operator" });
    // Seed > one platform list page of downpipes DIRECTLY into storage (the same dp: state shape an upsert
    // persists), so the WHOLE keyspace exceeds one page cheaply. The ids zero-pad with a numeric prefix so
    // they all sort BELOW the proposed tail id (which begins "dp_zzz_"): the proposed write lands on the
    // truncated tail a bare list() would never capture, exactly where an un-rolled-back write would persist.
    const SEED = PLATFORM_LIST_PAGE + 100; // 1100 > one page, so the checkpoint scan MUST page
    const seededIds: string[] = [];
    for (let i = 0; i < SEED; i++) {
      const id = `dp_seed_${String(i).padStart(6, "0")}`;
      seededIds.push(id);
      paged.storage.rawPut(`dp:${id}`, {
        config: { id, name: `seed ${i}`, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: `KV_${id}`, include: [], exclude: [] } },
        inFlight: false,
        lastRunId: null,
        nextRunAt: Date.now() + 3_600_000,
      });
    }
    // Precondition: the keyspace genuinely exceeds one page, AND a single un-paged list() truncates it (so
    // the test is meaningful: the OLD bare-list checkpoint would have seen only this one page).
    ok("paged: the seeded fleet exceeds one DO list page", paged.storage.keysWithPrefix("dp:").length === SEED && SEED > PLATFORM_LIST_PAGE);
    const onePage = await paged.storage.list({ prefix: "" });
    ok("paged: a single un-paged list() returns only ONE page (the truncation the fix repairs)", onePage.size === PLATFORM_LIST_PAGE);
    const dpKeyCountBefore = paged.storage.keysWithPrefix("dp:").length;

    // Arm the gate (owner) so a config mutation goes through dryRunConfigMutation under a checkpoint.
    const armed = await pagedCall(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("paged: the gate is ON for the large-keyspace proposal", armed.status === 200);

    // Propose a downpipe whose key sorts AFTER every seeded dp: key (and well past the first page), so under
    // a truncated single-page checkpoint the dry-run write to dp:dp_zzz_tail_proposal would escape rollback.
    const proposedId = "dp_zzz_tail_proposal";
    const proposal = await pagedCall(OPERATOR, "POST", "/admin/downpipes", dp(proposedId, "tail proposal"));
    ok("paged: the large-keyspace mutation is queued (202), not applied", proposal.status === 202);

    // THE PROOF: the proposed downpipe must NOT exist after the dry-run, and the dp: keyspace is exactly what
    // it was pre-proposal. The OLD bare list() truncated the checkpoint+rollback to page 1, so the would-be
    // write to the tail key dp:dp_zzz_tail_proposal was never rolled back and the downpipe persisted after a
    // mere propose. The paginated full-prefix scan captures + restores the whole keyspace, leaving no trace.
    ok("paged: the proposed downpipe does NOT persist in storage after the dry-run", !paged.storage.keysWithPrefix("dp:").includes(`dp:${proposedId}`));
    ok("paged: the dp: keyspace is unchanged by the proposal (full-keyspace rollback)", paged.storage.keysWithPrefix("dp:").length === dpKeyCountBefore);
    ok("paged: every seeded downpipe key is still present (no key dropped by a truncated restore)", seededIds.every((id) => paged.storage.keysWithPrefix("dp:").includes(`dp:${id}`)));
  }
}
