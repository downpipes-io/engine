// An offboarded member's sign-in-context baseline (signinctx:<subject>) and IdP group snapshot
// (oidcgroups:<subject>) go with their role.
//
// WHY THIS EXISTS. Every sign-in, while the owner's new-location notice is on, stores up to ten coarse network
// prefixes under signinctx:<subject> (src/sched/scheduler-do-session.ts). The 90-day TTL is applied only on that
// subject's next sign-in, and a leaver never signs in again, so without this delete the row never expires (ASVS
// v5.0.0-14.2.7). Role delete (also the path SCIM DELETE takes) deletes the row and the member's group snapshot,
// both keyed by the subject the role row names. A group-only person has no role row. Their snapshot holds the
// address, so an offboard by address finds it by scanning the prefix. A record not refreshed for 90 days is
// deleted by the scheduler alarm, and a bare group list (no address, no time) is stamped by the first alarm
// that sees it and deleted 14 days later.
//
// Run with `node test/validate-leaver-signin-context.ts`.

import { CALLER_HEADER, encodeCaller, roleSubjectKey } from "../src/admin/identity.ts";
import { groupsOf, makeOidcGroupsRecord } from "../src/sched/oidc-groups-record.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { MockStorage } from "./mock-storage.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const storage = new MockStorage();
// biome-ignore lint/suspicious/noExplicitAny: the DO constructor takes a partial state in tests
const dobj: any = new SchedulerDO({ storage } as any);
const owner = { method: "token", email: "founder@acme.example", subject: null, role: "owner", groups: [] };
const H = { [CALLER_HEADER]: encodeCaller(owner as Parameters<typeof encodeCaller>[0]), "content-type": "application/json" };
async function doPost(path: string, body: unknown): Promise<number> {
  const r = await dobj.fetch(new Request(`https://scheduler.internal${path}`, { method: "POST", headers: H, body: JSON.stringify(body) }));
  return r.status;
}

await storage.put(roleSubjectKey("passkey|founder@acme.example"), { subject: "passkey|founder@acme.example", email: "founder@acme.example", role: "owner", grantedBy: "system", grantedAt: "2026-06-13T00:00:00.000Z" });
const leaver = { email: "leaver@acme.example", subject: "oidc:entra|sub-leaver" };
const stayer = { email: "stayer@acme.example", subject: "oidc:entra|sub-stayer" };
for (const u of [leaver, stayer]) {
  await storage.put(roleSubjectKey(u.subject), { subject: u.subject, email: u.email, role: "operator", grantedBy: "founder@acme.example", grantedAt: "2026-06-13T00:00:00.000Z" });
}
ok("the owner turns the new-location notice on", (await doPost("/config/signin-context-policy", { notifyNewSignInContext: true })) === 200);
await storage.put(`oidcgroups:${leaver.subject}`, ["admins"]);
await storage.put(`oidcgroups:${stayer.subject}`, ["admins"]);
await dobj.recordSignInContext(leaver.subject, "198.51.100.23");
await dobj.recordSignInContext(stayer.subject, "203.0.113.9");
ok("CONTROL: both members have a group snapshot", (await storage.get(`oidcgroups:${leaver.subject}`)) !== undefined && (await storage.get(`oidcgroups:${stayer.subject}`)) !== undefined);
ok("CONTROL: both members have a sign-in-context row", (await storage.get(`signinctx:${leaver.subject}`)) !== undefined && (await storage.get(`signinctx:${stayer.subject}`)) !== undefined);

ok("the owner deletes the leaver's role (200)", (await doPost("/roles/delete", { email: leaver.email })) === 200);
ok("the leaver's role row is gone", (await storage.get(roleSubjectKey(leaver.subject))) === undefined);
ok("the leaver's sign-in-context row is gone", (await storage.get(`signinctx:${leaver.subject}`)) === undefined);
ok("the leaver's group snapshot is gone", (await storage.get(`oidcgroups:${leaver.subject}`)) === undefined);
ok("CONTROL: the other member's group snapshot stays", (await storage.get(`oidcgroups:${stayer.subject}`)) !== undefined);
ok("CONTROL: the other member's sign-in-context row stays", (await storage.get(`signinctx:${stayer.subject}`)) !== undefined);

// ---- the group-only leaver: no role row, a snapshot that names the address ----
const DAY = 24 * 60 * 60 * 1000;
const groupOnly = { email: "grouponly@acme.example", subject: "oidc:entra|sub-grouponly" };
const bystander = { email: "bystander@acme.example", subject: "oidc:entra|sub-bystander" };
const snap = (email: string, ageMs: number) => ({ email, groups: ["admins"], updatedAt: Date.now() - ageMs });
await storage.put(`oidcgroups:${groupOnly.subject}`, snap(groupOnly.email, DAY));
await storage.put(`oidcgroups:${bystander.subject}`, snap(bystander.email, DAY));
ok("CONTROL: the group-only person holds no role row", (await storage.get(roleSubjectKey(groupOnly.subject))) === undefined);
ok("the owner offboards the group-only person by address (200)", (await doPost("/roles/delete", { email: groupOnly.email })) === 200);
ok("the group-only person's group record is gone", (await storage.get(`oidcgroups:${groupOnly.subject}`)) === undefined);
ok("CONTROL: another person's group record stays", (await storage.get(`oidcgroups:${bystander.subject}`)) !== undefined);

// ---- age-out ----
const bareList = { subject: "oidc:entra|sub-oldshape" };
await storage.put(`oidcgroups:${bareList.subject}`, ["admins"]);
const stale = { email: "stale@acme.example", subject: "oidc:entra|sub-stale" };
await storage.put(`oidcgroups:${stale.subject}`, snap(stale.email, 91 * DAY));
ok("a reader accepts a bare group list", (await dobj.spendTimeGroupsFor(bareList.subject, [])).join() === "admins");
ok("a reader accepts a group record with email and updatedAt", (await dobj.spendTimeGroupsFor(bystander.subject, [])).join() === "admins");
ok("the sign-in writer's record names the address, the groups and the time", JSON.stringify(makeOidcGroupsRecord("a@b.example", ["g"], 5)) === '{"email":"a@b.example","groups":["g"],"updatedAt":5}' && groupsOf(makeOidcGroupsRecord("a@b.example", ["g"], 5))?.join() === "g");
await dobj.alarm();
const migrating = (await storage.get<{ groups?: string[]; migratedAt?: number }>(`oidcgroups:${bareList.subject}`)) ?? {};
ok("the first alarm stamps a bare group list with migratedAt and keeps its groups readable", typeof migrating.migratedAt === "number" && (await dobj.spendTimeGroupsFor(bareList.subject, [])).join() === "admins");
const realNow = Date.now;
Date.now = () => realNow() + 13 * DAY;
await dobj.alarm();
ok("an inactive bare group list survives day 13", (await storage.get(`oidcgroups:${bareList.subject}`)) !== undefined);
Date.now = () => realNow() + 15 * DAY;
await dobj.alarm();
Date.now = realNow;
ok("an inactive bare group list is gone after 14 days", (await storage.get(`oidcgroups:${bareList.subject}`)) === undefined);
ok("a record not refreshed for 90 days ages out", (await storage.get(`oidcgroups:${stale.subject}`)) === undefined);
ok("CONTROL: a record refreshed a day ago survives the alarm", (await storage.get(`oidcgroups:${bystander.subject}`)) !== undefined);

// ---- a subject change leaves no live residue ----
const mover = { email: "mover@acme.example", before: "oidc:entra|sub-mover-1", after: "oidc:entra|sub-mover-2" };
await storage.put(`oidcgroups:${mover.before}`, snap(mover.email, 91 * DAY));
await storage.put(`oidcgroups:${mover.after}`, snap(mover.email, DAY));
await dobj.alarm();
ok("after a subject change the earlier subject's record ages out", (await storage.get(`oidcgroups:${mover.before}`)) === undefined);
ok("CONTROL: the current subject's record stays while the person is not offboarded", (await storage.get(`oidcgroups:${mover.after}`)) !== undefined);
ok("the owner offboards the mover by address (200)", (await doPost("/roles/delete", { email: mover.email })) === 200);
ok("no record for the mover survives the offboard", (await storage.get(`oidcgroups:${mover.after}`)) === undefined);

console.log(failures === 0 ? "\nLEAVER RECORDS PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures, checks);
if (failures > 0) process.exit(1);
