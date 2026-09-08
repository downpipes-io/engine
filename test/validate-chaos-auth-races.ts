// validate-chaos-auth-races.ts -- AUTH/RBAC CHAOS: concurrency races on the dual-control approve path,
// driven through the REAL router + change-control handlers with forged callers (the legitimate harness
// pattern). These are the races the lifecycle/audit tests do not cover: two distinct approvers approving the
// SAME pending change AT ONCE, and a maker racing a checker on their own change. The invariant: a pending
// change applies AT MOST ONCE, the maker != checker rule holds even under a race, and no double-apply.
import { buildContext, OPERATOR, OPERATOR2, OWNER } from "./validate-config-change-control-harness.ts";

let pass = 0, fail = 0;
const ok = (d: string, c: boolean) => { console.log(`  ${c ? "ok  " : "FAIL"} ${d}`); c ? pass++ : fail++; };

const { ctx } = await buildContext();
const { call, dp, listDownpipes, setGate } = ctx;
await setGate(OWNER, true); // arm dual-control so a mutation queues a pending change instead of applying

console.log("AUTH RACE 1: two distinct approvers approve the SAME pending change concurrently");
{
  const q = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_race1", "race1"));
  const id = ((await q.json()) as { id: string }).id;
  const [a, b] = await Promise.all([
    call(OPERATOR2, "POST", `/admin/config/changes/${id}/approve`),
    call(OWNER, "POST", `/admin/config/changes/${id}/approve`),
  ]);
  const codes = [a.status, b.status];
  // The load-bearing invariant is APPLY-AT-MOST-ONCE, not which approver "wins": the engine may answer both
  // concurrent approvers 200 (idempotent) as long as the change applies exactly once. A double-apply (two
  // downpipes) or a 5xx/corruption would be the real bug.
  ok(`no 5xx under the concurrent double-approve (codes ${codes.join(",")})`, !codes.some((s) => s >= 500));
  ok("the change applied EXACTLY ONCE (one dp_race1 downpipe, never two -- idempotent, no double-apply)", (await listDownpipes()).filter((d) => d.config.id === "dp_race1").length === 1);
}

console.log("AUTH RACE 2: the MAKER races a distinct checker to approve the maker's own change");
{
  const q = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_race2", "race2"));
  const id = ((await q.json()) as { id: string }).id;
  const [maker, checker] = await Promise.all([
    call(OPERATOR, "POST", `/admin/config/changes/${id}/approve`),   // maker == checker -> MUST be refused
    call(OPERATOR2, "POST", `/admin/config/changes/${id}/approve`),  // distinct checker -> may apply
  ]);
  // Both status codes are read directly, so a crash on the maker's self-approve cannot be mistaken for
  // a policy refusal.
  ok(`no 5xx under the maker/checker race (codes ${maker.status},${checker.status})`, maker.status < 500 && checker.status < 500);
  ok("the maker's self-approve is REFUSED even under the race (maker != checker holds)", maker.status >= 400 && maker.status < 500);
  ok("the distinct checker applied it exactly once", (await listDownpipes()).filter((d) => d.config.id === "dp_race2").length === 1);
}

console.log("AUTH RACE 3: double-apply attempt -- approve, then a concurrent re-approve of the SAME id");
{
  const q = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_race3", "race3"));
  const id = ((await q.json()) as { id: string }).id;
  await call(OPERATOR2, "POST", `/admin/config/changes/${id}/approve`); // applies
  const [r1, r2] = await Promise.all([
    call(OPERATOR2, "POST", `/admin/config/changes/${id}/approve`),
    call(OWNER, "POST", `/admin/config/changes/${id}/approve`),
  ]);
  ok("re-approving an already-applied change is refused both times (no double-apply)", r1.status >= 400 && r2.status >= 400);
  ok(`no 5xx under the re-approve race (codes ${r1.status},${r2.status})`, r1.status < 500 && r2.status < 500);
  ok("still exactly one dp_race3 (terminal, not re-applied)", (await listDownpipes()).filter((d) => d.config.id === "dp_race3").length === 1);
}

console.log(`\n${fail === 0 ? "AUTH RACE CHAOS PASS" : "AUTH RACE CHAOS: " + fail + " FAIL"}: ${pass} pass / ${fail} fail`);
if (fail > 0) process.exitCode = 1;
if (fail > 0) process.exit(1);
