// SchedulerDO auth-boundary vectors (engine-test-018-01 split): the constant-time bootstrap-invite
// token comparison (engine-src-043-01) and the in-DO authz refusal mapping to 403 with no capability
// leak (engine-src-037-03). encodeCaller + CALLER_HEADER build a forwarded non-owner caller so a
// capability denial is driven through the DO's own gate (the bypass scenario the DO guard defends
// against). Behaviour-preserving: same assertions, same order as the original main().
import { ok, makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";
import { encodeCaller, CALLER_HEADER } from "../src/admin/identity.ts";
import type { SchedulerDO } from "../src/sched/scheduler-do.ts";

export async function run(): Promise<void> {
  // ---- engine-src-043-01: constant-time bootstrap-invite token comparison -------------------
  // bootstrapInviteMatches must compare the presented and stored tokens in constant time (the shared
  // constantTimeEqual primitive), returning the bound email ONLY on an exact match, and null on a wrong
  // token OR a length mismatch (the primitive throws on unequal length, so the helper must guard that).
  // The mint route seeds a real invite on a fresh, empty-table DO; we then call the private matcher.
  {
    const { stub } = makeScheduler();
    type Matcher = { bootstrapInviteMatches(token: string, now: number): Promise<string | null> };
    const matcher = stub as unknown as Matcher;
    const now = Date.now();
    const mintRes = await stubFetch(stub, "POST", "/passkey/bootstrap/mint", { email: "owner@example.test" });
    const minted = (await mintRes.json()) as { token: string | null };
    const token = minted.token;
    ok("043-01: bootstrap invite minted on an empty-table DO", typeof token === "string" && token.length > 0);
    if (typeof token === "string") {
      // Exact match returns the bound email.
      ok("043-01: an exact token match returns the bound email", (await matcher.bootstrapInviteMatches(token, now)) === "owner@example.test");
      // A same-length but wrong token returns null (the constant-time compare reports unequal).
      const wrongSameLength = `${"z".repeat(token.length - 1)}z`.slice(0, token.length);
      ok("043-01: a same-length wrong token returns null", (await matcher.bootstrapInviteMatches(wrongSameLength, now)) === null);
      // A SHORTER token returns null and must NOT throw (the length guard runs before the primitive,
      // which would otherwise throw on unequal-length buffers).
      let shortThrew = false;
      let shortResult: string | null = "sentinel";
      try { shortResult = await matcher.bootstrapInviteMatches(token.slice(0, -1), now); } catch { shortThrew = true; }
      ok("043-01: a shorter token does not throw", shortThrew === false);
      ok("043-01: a shorter token returns null", shortResult === null);
      // A LONGER token also returns null without throwing.
      let longThrew = false;
      let longResult: string | null = "sentinel";
      try { longResult = await matcher.bootstrapInviteMatches(`${token}x`, now); } catch { longThrew = true; }
      ok("043-01: a longer token does not throw", longThrew === false);
      ok("043-01: a longer token returns null", longResult === null);
    }
  }

  // ---- engine-src-037-03: an authz refusal in the DO is a 403 with no capability name -------
  // A capability denial (the DO's defence-in-depth gate, reached when the router gate is bypassed) must
  // map to HTTP 403, NOT the old blanket 400, and the body must NOT echo the required capability name
  // (the old catch returned { error: "forbidden: drill.run capability required" } with a 400). A
  // SyntaxError (malformed JSON) must still be a 400 client error.
  {
    const { stub } = makeScheduler();
    // A forwarded VIEWER caller lacks drill.run; POST /drill-evidence calls requireCapability(caller,
    // "drill.run"), which now throws AuthError. The role here is the router-forwarded role the route trusts.
    const viewerHeader = encodeCaller({ method: "access", email: "viewer@example.test", subject: "viewer-subj", role: "viewer", groups: [] });
    const denied = await (stub as SchedulerDO).fetch(new Request("https://scheduler.internal/drill-evidence", {
      method: "POST",
      headers: { "content-type": "application/json", [CALLER_HEADER]: viewerHeader },
      body: JSON.stringify({ runId: "r1", kind: "rehearsal" }),
    }));
    ok("037-03: a capability denial returns 403 (not the old 400)", denied.status === 403);
    const deniedBody = (await denied.text());
    ok("037-03: the 403 body carries no raw capability name (no \"drill.run\")", !deniedBody.includes("drill.run"));
    ok("037-03: the 403 body carries no \"capability required\" leak", !deniedBody.includes("capability required"));
    ok("037-03: the 403 body is the generic forbidden shape", deniedBody.includes("forbidden"));

    // A genuine client error (malformed JSON) is still a 400, not swallowed into the new 403/500 paths.
    const badJson = await (stub as SchedulerDO).fetch(new Request("https://scheduler.internal/drill-evidence", {
      method: "POST",
      headers: { "content-type": "application/json", [CALLER_HEADER]: viewerHeader },
      body: "{ not json",
    }));
    ok("037-03: malformed JSON is still a 400 client error", badJson.status === 400);

    // A validation failure (a plain Error a guard throws) stays a 400 with its actionable message. An
    // OWNER caller passes the capability gate, then recordDrillEvidence rejects a missing runId at 400.
    const ownerHeader = encodeCaller({ method: "access", email: "owner@example.test", subject: "owner-subj", role: "owner", groups: [] });
    const badInput = await (stub as SchedulerDO).fetch(new Request("https://scheduler.internal/drill-evidence", {
      method: "POST",
      headers: { "content-type": "application/json", [CALLER_HEADER]: ownerHeader },
      body: JSON.stringify({ kind: "rehearsal" }),
    }));
    ok("037-03: a validation failure (missing runId) stays a 400", badInput.status === 400);
    const badInputBody = await badInput.text();
    ok("037-03: the 400 validation body keeps its actionable message", badInputBody.includes("runId"));
  }
}
