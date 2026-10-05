// validate-approval-policy-disarm: with two Owners and an approval policy ON, one Owner must not be able to
// turn that policy OFF alone, without a fresh re-authentication, and without an alert.
//
// It covers the two owner-opt-in approval policies that share the config gate's shape but not its off switch:
//   - POST /admin/config/restore-approval-policy  (requireRestoreApproval)
//   - POST /admin/config/update-approval-policy   (requireAllUpdateApproval)
//
// For each policy it asserts three safe behaviours, each reported on its own line:
//   A. a disarm by ONE Owner does not take effect at once (it needs a second Owner, as the config gate does);
//   B. a stale session cannot propose or complete a disarm (an Access caller whose assertion is older than
//      STEPUP_FRESH_MS): the stale Owner's disarm is refused with 401 stepUpRequired and queues nothing, and
//      a stale second Owner's approve of a fresh proposal is refused with 401 stepUpRequired. Both propose
//      routes are STEPUP_SUBS members; the console calls the restore toggle through Transport.gatedFetch.
//   E. in a ONE-Owner estate, where the disarm runs inline, a stale Owner's disarm is refused with 401
//      stepUpRequired and the policy stays ON; the same Owner with a fresh assertion disarms at once. The
//      update toggle is armed by the lone Owner; the restore toggle is armed with two Owners, then one leaves.
//   C. a completed disarm raises an alert at warning or above to a configured all-events webhook, and the
//      alert names the policy;
//   D. no deadlock: the bare-token break-glass disarms at once (200, disarmed:true) and that alerts too.
//
// Controls, so a green or red cannot come from the harness:
//   - step-up positive control: the same stale caller IS refused on /config/signin-context-policy, a
//     STEPUP_SUBS member, so the stale-clock method can produce a 401;
//   - alert positive control: the config gate's second-Owner disarm DOES deliver a warning post to the sink;
//   - arm checks: each policy reads ON before the disarm is tried.
//
// Run: node test/validate-approval-policy-disarm.ts

import { STEPUP_FRESH_MS } from "../src/admin/session.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import type { Env } from "../src/env.d.ts";
import { AUD, buildContext, handleAdmin, makeScheduler, TEAM } from "./validate-owner-action-dualcontrol-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  if (!cond) failures++;
  console.log(`${cond ? "ok  " : "FAIL"}  ${label}`);
}

const ctx = await buildContext();
const { call, OWNER, OWNER2, webhookPosts, ageOwnerAction } = ctx;

// Clock shift for the step-up check. The harness mints every Access assertion with the iat fixed at build
// time, so moving Date.now forward past STEPUP_FRESH_MS makes the same (still unexpired) assertion stale.
const realNow = Date.now;
function shiftClock(ms: number): void {
  Date.now = () => realNow() + ms;
}
function restoreClock(): void {
  Date.now = realNow;
}

type PolicyView = { requireRestoreApproval?: boolean; requireAllUpdateApproval?: boolean; requireConfigApproval?: boolean };
async function view(): Promise<PolicyView> {
  return (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as PolicyView;
}
type Post = { event?: string; severity?: string; detail?: string };
function warnOrAbove(posts: unknown[]): Post[] {
  return (posts as Post[]).filter((p) => p !== null && (p.severity === "warning" || p.severity === "critical"));
}

interface Policy {
  name: string;
  route: string;
  field: "requireRestoreApproval" | "requireAllUpdateApproval";
  detail: RegExp;
}
const POLICIES: Policy[] = [
  { name: "restore-approval", route: "/admin/config/restore-approval-policy", field: "requireRestoreApproval", detail: /^Restore approval was turned OFF/ },
  { name: "update-approval", route: "/admin/config/update-approval-policy", field: "requireAllUpdateApproval", detail: /^Update approval for every release was turned OFF/ },
];

async function isOn(p: Policy): Promise<boolean> {
  return (await view())[p.field] === true;
}
async function arm(p: Policy): Promise<boolean> {
  const r = await call(OWNER, "POST", p.route, { [p.field]: true });
  return r.status === 200 && (await isOn(p));
}

try {
  // ---- E. ONE OWNER. Before the second Owner exists the disarm runs inline, so the step-up gate is the only
  // thing between a stale session and the disarm. The update toggle has no two-Owner floor on arm, so it can
  // be armed here; the restore toggle cannot be armed by one Owner.
  {
    const p = POLICIES.find((x) => x.name === "update-approval");
    if (p === undefined) throw new Error("update-approval policy row missing");
    ok(`[${p.name}] E. arm check: one Owner arms the policy (200, ON)`, await arm(p));
    shiftClock(STEPUP_FRESH_MS + 60_000);
    try {
      const stale = await call(OWNER, "POST", p.route, { [p.field]: false });
      const staleBody = await stale.text();
      console.log(`      one-Owner stale disarm -> ${stale.status} ${staleBody.slice(0, 120)}`);
      ok(`[${p.name}] E1. SAFE: a stale lone Owner's disarm is refused (401 stepUpRequired, policy still ON)`, stale.status === 401 && /stepUpRequired/.test(staleBody) && (await isOn(p)));
    } finally {
      restoreClock();
    }
    const fresh = await call(OWNER, "POST", p.route, { [p.field]: false });
    const freshBody = (await fresh.json()) as { disarmed?: boolean };
    ok(`[${p.name}] E2. a fresh lone Owner's disarm runs at once (200, disarmed:true, policy OFF)`, fresh.status === 200 && freshBody.disarmed === true && !(await isOn(p)));
  }

  // ---- SETUP: two Owners, a webhook channel and an all-events rule at minSeverity warning.
  const g = await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
  ok("setup: a second Owner is granted", g.status === 200);
  const ch = (await (await call(OWNER, "POST", "/admin/notify/channels", { kind: "webhook", name: "disarm-sink", url: "https://hooks.example.com/alert" })).json()) as { channel?: { id?: string }; id?: string };
  const chId = ch.channel?.id ?? ch.id ?? "";
  ok("setup: a webhook channel exists", chId.length > 0);
  const rule = await call(OWNER, "POST", "/admin/notify/rules", { scope: { kind: "global" }, minSeverity: "warning", events: "all", channelIds: [chId], enabled: true });
  ok("setup: an all-events rule at minSeverity warning exists", rule.status === 200);

  // ---- ALERT POSITIVE CONTROL: the config gate's disarm, completed by a second Owner, reaches the sink.
  {
    const armCfg = await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: true });
    ok("control: the config gate arms (200)", armCfg.status === 200 && (await view()).requireConfigApproval === true);
    const before = webhookPosts.length;
    const d = await call(OWNER, "POST", "/admin/config/approval-policy", { requireConfigApproval: false });
    ok("control: one Owner's config-gate disarm is queued (202), not applied", d.status === 202 && (await view()).requireConfigApproval === true);
    const id = ((await d.json()) as { id?: string }).id ?? "";
    ageOwnerAction(id);
    const a = await call(OWNER2, "POST", `/admin/owner-actions/${id}/approve`);
    ok("control: the second Owner's approve completes the config-gate disarm", a.status === 200 && (await view()).requireConfigApproval === false);
    ok("control: the config-gate disarm delivered a warning-or-above post to the sink", warnOrAbove(webhookPosts.slice(before)).length > 0);
  }

  for (const p of POLICIES) {
    console.log(`\n== ${p.name} ==`);

    // ---- B. STEP-UP. Arm with a fresh assertion, then make the assertion stale and try to disarm.
    ok(`[${p.name}] arm check: the policy reads ON before the step-up check`, await arm(p));
    const queuedBefore = (await ctx.inbox(OWNER)).length;
    shiftClock(STEPUP_FRESH_MS + 60_000);
    try {
      const ctl = await call(OWNER, "POST", "/admin/config/signin-context-policy", { notifyNewSignInContext: false });
      ok(`[${p.name}] step-up positive control: a stale caller is refused on /config/signin-context-policy (401)`, ctl.status === 401);
      const stale = await call(OWNER, "POST", p.route, { [p.field]: false });
      const staleBody = await stale.text();
      console.log(`      stale-caller disarm -> ${stale.status} ${staleBody.slice(0, 120)}`);
      ok(`[${p.name}] B1. SAFE: a stale Owner's disarm is refused (401 stepUpRequired, policy still ON)`, stale.status === 401 && /stepUpRequired/.test(staleBody) && (await isOn(p)));
    } finally {
      restoreClock();
    }
    ok(`[${p.name}] B1. the refused stale disarm queued no owner action`, (await ctx.inbox(OWNER)).length === queuedBefore);
    // A fresh Owner proposes the disarm, so B2 grades the approve leg on a real queued proposal.
    const proposal = await call(OWNER, "POST", p.route, { [p.field]: false });
    const proposalBody = await proposal.text();
    const staleId = proposal.status === 202 ? ((JSON.parse(proposalBody) as { id?: string }).id ?? "") : "";
    ok(`[${p.name}] B2 setup: a fresh Owner's disarm queues (202)`, staleId.length > 0 && (await isOn(p)));
    shiftClock(STEPUP_FRESH_MS + 60_000);
    try {
      const staleApprove = await call(OWNER2, "POST", `/admin/owner-actions/${staleId}/approve`);
      const staleApproveBody = await staleApprove.text();
      console.log(`      stale second-Owner approve -> ${staleApprove.status} ${staleApproveBody.slice(0, 120)}`);
      ok(`[${p.name}] B2. SAFE: a stale second Owner cannot complete the disarm (401 stepUpRequired, policy still ON)`, staleId.length > 0 && staleApprove.status === 401 && /stepUpRequired/.test(staleApproveBody) && (await isOn(p)));
    } finally {
      restoreClock();
    }
    // Withdraw the B2 proposal so the A/C leg below grades a fresh one.
    if (staleId.length > 0) await call(OWNER, "POST", `/admin/owner-actions/${staleId}/reject`);

    // ---- A and C share one disarm attempt by one Owner with a fresh assertion.
    if (!(await isOn(p))) ok(`[${p.name}] re-arm after the step-up check`, await arm(p));
    ok(`[${p.name}] arm check: the policy reads ON before the one-Owner disarm`, await isOn(p));
    const before = webhookPosts.length;
    const d = await call(OWNER, "POST", p.route, { [p.field]: false });
    const dBody = await d.text();
    console.log(`      one-Owner disarm -> ${d.status} ${dBody.slice(0, 120)}`);
    const stillOn = await isOn(p);
    ok(`[${p.name}] A. SAFE: one Owner's disarm does not take effect at once (policy still ON)`, stillOn);
    if (stillOn && d.status === 202) {
      // Complete the disarm the way the config gate does, so C is graded on a disarm that happened.
      const id = (JSON.parse(dBody) as { id?: string }).id ?? "";
      ageOwnerAction(id);
      const a = await call(OWNER2, "POST", `/admin/owner-actions/${id}/approve`);
      console.log(`      second-Owner approve -> ${a.status}`);
    }
    const offNow = !(await isOn(p));
    const alerts = warnOrAbove(webhookPosts.slice(before));
    console.log(`      policy OFF after the disarm path: ${offNow}; warning-or-above posts: ${alerts.length}; all posts: ${webhookPosts.length - before}`);
    ok(`[${p.name}] C. SAFE: the disarm raised a warning-or-above alert to the all-events webhook`, offNow && alerts.length > 0);
    ok(`[${p.name}] C. the alert names the policy`, alerts.some((a) => typeof a.detail === "string" && p.detail.test(a.detail)));
  }

  // ---- E (restore). ONE OWNER LEFT. The restore toggle can only be armed with two Owners, so arm it now and
  // then remove the second Owner. Its disarm then runs inline, and step-up is the only gate in front of it.
  {
    const p = POLICIES.find((x) => x.name === "restore-approval");
    if (p === undefined) throw new Error("restore-approval policy row missing");
    ok(`[${p.name}] E. arm check: two Owners arm the policy (200, ON)`, await arm(p));
    // If the removal queues for change control, the second Owner approves it.
    const rm = await call(OWNER, "POST", "/admin/roles/delete", { email: OWNER2 });
    const rmBody = (await rm.json()) as { queued?: boolean; id?: string };
    let rmDone = rm.status === 200;
    if (rm.status === 202 && rmBody.queued === true && typeof rmBody.id === "string") {
      // Step past the approval dwell. The shift is far inside STEPUP_FRESH_MS, so the approver stays fresh.
      shiftClock(60_000);
      let ap: Response;
      try {
        ap = await call(OWNER2, "POST", `/admin/config/changes/${rmBody.id}/approve`);
      } finally {
        restoreClock();
      }
      console.log(`      remove second Owner -> 202 queued, approve -> ${ap.status} ${(await ap.clone().text()).slice(0, 160)}`);
      rmDone = ap.status === 200;
    }
    ok(`[${p.name}] E. setup: the second Owner is removed, one Owner left, policy still ON`, rmDone && (await isOn(p)));
    shiftClock(STEPUP_FRESH_MS + 60_000);
    try {
      const stale = await call(OWNER, "POST", p.route, { [p.field]: false });
      const staleBody = await stale.text();
      console.log(`      one-Owner stale disarm -> ${stale.status} ${staleBody.slice(0, 120)}`);
      ok(`[${p.name}] E1. SAFE: a stale lone Owner's disarm is refused (401 stepUpRequired, policy still ON)`, stale.status === 401 && /stepUpRequired/.test(staleBody) && (await isOn(p)));
    } finally {
      restoreClock();
    }
    const fresh = await call(OWNER, "POST", p.route, { [p.field]: false });
    const freshBody = (await fresh.json()) as { disarmed?: boolean };
    ok(`[${p.name}] E2. a fresh lone Owner's disarm runs at once (200, disarmed:true, policy OFF)`, fresh.status === 200 && freshBody.disarmed === true && !(await isOn(p)));
  }

  // ---- D. NO DEADLOCK. The bare-token break-glass cannot propose or approve owner actions, so it keeps an
  // immediate off switch, and that disarm alerts. A fresh scheduler, so no Owner row exists besides the token.
  for (const p of POLICIES) {
    const bsched = makeScheduler();
    const benv = { ...bsched.env, ADMIN_TOKEN: "bg-disarm-token", CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD } as unknown as Env;
    const bcall = (method: "GET" | "POST", path: string, body?: unknown): Promise<Response> =>
      handleAdmin(new Request(`https://engine.example${path}`, { method, headers: { authorization: "Bearer bg-disarm-token", ...(body !== undefined ? { "content-type": "application/json" } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }), benv);
    const bch = (await (await bcall("POST", "/admin/notify/channels", { kind: "webhook", name: "bg-sink", url: "https://hooks.example.com/alert" })).json()) as { channel?: { id?: string }; id?: string };
    await bcall("POST", "/admin/notify/rules", { scope: { kind: "global" }, minSeverity: "warning", events: "all", channelIds: [bch.channel?.id ?? bch.id ?? ""], enabled: true });
    const bArm = await bcall("POST", p.route, { [p.field]: true });
    ok(`[${p.name}] D. break-glass arm is immediate (200)`, bArm.status === 200);
    const before = webhookPosts.length;
    const bDisarm = await bcall("POST", p.route, { [p.field]: false });
    const bBody = (await bDisarm.json()) as { disarmed?: boolean };
    const bOn = ((await (await bcall("GET", "/admin/config/approval-policy")).json()) as PolicyView)[p.field];
    ok(`[${p.name}] D. the break-glass disarm is immediate (200, disarmed:true, policy OFF)`, bDisarm.status === 200 && bBody.disarmed === true && bOn === false);
    ok(`[${p.name}] D. the break-glass disarm alerted and named the policy`, warnOrAbove(webhookPosts.slice(before)).some((a) => typeof a.detail === "string" && p.detail.test(a.detail) && /break-glass/.test(a.detail)));
  }
} finally {
  restoreClock();
  globalThis.fetch = ctx.realFetch;
}

verdictReached(failures, checks);
console.log(failures === 0 ? "\nPASS" : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
