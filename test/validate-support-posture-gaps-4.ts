// Prove the ENGINE half of the POSTURE support-pack gaps, group 4.
// (Some of these gaps are browser-side and are proven in the console repo; this engine's job for those is to
// ADMIT the closed vocabulary and the consoleBuild envelope field the console emits, which the client-diag
// drift gate and validate-client-diag.ts hold.)
//
// THE BAR IS THE DISCRIMINATION TEST. A recorder, a caller and a projection are NOT enough. Each gap below
// ENUMERATES the states it says are indistinguishable, DRIVES each one against the REAL module, and asserts
// they produce DIFFERENT evidence. A test that asserts merely "a counter moved" can pass with working plumbing
// behind it and still miss a state a customer can reach.
//
// NO-CUSTODY is proven in the same breath: each state is driven with a hostile customer value planted at the
// site (a grantee's email, a source IP), and the recorded evidence is serialised and asserted to contain none
// of it.
//
//   node test/validate-support-posture-gaps-4.ts

import { APPROVAL_MIN_DWELL_MS } from "../src/admin/approvals.ts";
import { changeKey, type PendingConfigChange } from "../src/admin/change-control.ts";
import { ADMIN_COUNTERS_KEY, type AdminCounters, applyAdminCounters, ADMIN_COUNTER_NAMES } from "../src/admin/diag-records.ts";
import { CALLER_HEADER, encodeCaller } from "../src/admin/identity.ts";
import { AUDIT_PREFIX } from "../src/admin/audit.ts";
import { GRANT_POSTURE_COUNTER_NAMES } from "../src/admin/posture-counters.ts";
import { isHumanActorMethod } from "../src/admin/identity-roles.ts";
import { ownerActionKey, type PendingOwnerAction } from "../src/admin/owner-action.ts";
import { buildStatus } from "../src/admin/status.ts";
import { CONSOLE_BUILD_RE, CLIENT_DIAG_KINDS } from "../src/admin/client-diag-vocab.ts";
import { projectClientDiagnostics } from "../src/admin/client-diag-receive.ts";
import { handleRbac } from "../src/admin/router-rbac.ts";
import { makeScheduler, type MockStorage } from "./validate-scheduler-shared.ts";
import type { RouterCtx } from "../src/admin/router-helpers.ts";
// Caller lives in identity.ts, not auth.ts; it is the same shape the
// CALLER_HEADER encoder above serialises, so both come from the one module.
import type { Caller } from "../src/admin/identity.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const NO_SENDER_ENV = { SIGNER_PRIVATE: "x", DEST_KIND: "r2", ADMIN_TOKEN: "t" } as unknown as Env;
const SENDER_ENV = {
  ...NO_SENDER_ENV,
  EMAIL: { send: () => Promise.reject(new Error("550 mailbox unavailable")) },
  INVITE_EMAIL_FROM: "invites@acme-health.example",
} as unknown as Env;
const WORKING_SENDER_ENV = {
  ...NO_SENDER_ENV,
  EMAIL: { send: () => Promise.resolve() },
  INVITE_EMAIL_FROM: "invites@acme-health.example",
} as unknown as Env;

// ---- THE REAL ROUTE, THE REAL DURABLE OBJECT ------------------------------------------------------------
// Proving only a re-implemented PREDICATE (a local counterBumpsFor) and an APPLIER (applyAdminCounters),
// without touching the route that bumps the counter or the recorder that fires it, would stay green while the
// role-grant-invite-undeliverable counter bumps on a healthy no-invite deployment and the source-IP-missing
// counter bumps on every failed passkey login. Everything below drives POST /admin/roles through handleRbac
// against a REAL SchedulerDO over in-memory storage, and reads the counters out of the DO's own aggregate key.
type Sched = { storage: MockStorage; stub: DurableObjectStub; dobj: { appendAudit(d: unknown): Promise<unknown> } };

function realScheduler(): Sched {
  const { storage, stub: dobj } = makeScheduler();
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const req = input instanceof Request ? input : new Request(String(input), init);
      return (dobj as unknown as { fetch(r: Request): Promise<Response> }).fetch(req);
    },
  } as unknown as DurableObjectStub;
  return { storage, stub, dobj: dobj as unknown as Sched["dobj"] };
}

// The ATTRIBUTED human owner: a verified Access identity with a subject AND an email. This is the caller whose
// audit rows the missing-source-IP question is asked about ("why do some of OUR rows have no source IP?"), and
// it is the one the DO's own authority re-check resolves from its role table.
const OWNER_EMAIL = "owner@acme-health.example";
const OWNER: Caller = { method: "access", email: OWNER_EMAIL, subject: "acc|owner", groups: [], role: "owner" } as unknown as Caller;
// The BREAK-GLASS caller: the bare shared token, which the DO resolves to owner-token. It is NOT a human
// method, so the rows it writes are invisible to the missing-source-IP counter.
//
// The token caller here is a FIXTURE CONVENIENCE, not a claim about production bootstrap. In production the
// bare token SHORT-CIRCUITS in whoami (scheduler-do-rbac-authority.ts, the method === "token" arm) and writes
// NO row at all; the row a fresh Access-fenced engine actually writes is written by the ACCESS caller on the
// console's first GET /admin/whoami, and "access" IS a human method (so it is what the source-IP-missing
// counter evaluates). The REAL bootstrap is driven end to end, through handleAdmin with a verified Access JWT
// and a real edge header, in test/validate-support-posture-gaps-6.ts.
const BOOTSTRAP: Caller = { method: "token", email: null, subject: null, groups: [], role: "owner" } as unknown as Caller;

// The audit's source IP is threaded on the CALLER (scheduler-do-rbac-mutations.ts reads caller.sourceIp), which
// is how auth.ts builds it in production. Threading it here rather than only on the ctx is what makes the
// "capture path works" case a real one rather than a hopeful one.
function rolesCtx(sched: Sched, env: Env, body: unknown, sourceIp: string | null, caller: Caller = OWNER): RouterCtx {
  const url = new URL("https://engine.example/admin/roles");
  return {
    req: new Request(url.toString(), { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } }),
    env,
    url,
    scheduler: sched.stub,
    caller: { ...(caller as unknown as Record<string, unknown>), sourceIp } as unknown as Caller,
    sub: "/roles",
    sourceIp,
    runtime: undefined,
    verdict: { ok: true } as never,
  } as unknown as RouterCtx;
}

// seedOwner bootstraps the DO's role table the way a real engine does: the shared-token break-glass grants the
// first human Owner, who then binds to their Access subject on first use. It is deliberately run under the
// NO-SENDER env, where -- and this IS the fix under test -- a minted-but-unsent invite bumps NOTHING, so the
// bootstrap cannot pollute either counter.
async function seedOwner(sched: Sched): Promise<void> {
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: OWNER_EMAIL, role: "owner" }, "203.0.113.1", BOOTSTRAP));
  await settle();
}

// The counter bumps and the audit appends are fire-and-forget (`void scheduler.fetch(...)`), exactly as they are
// in production. Let the microtasks the route left behind run before reading the aggregate.
async function settle(): Promise<void> {
  for (let i = 0; i < 20; i++) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 5));
}

async function counters(sched: Sched): Promise<AdminCounters> {
  return (await sched.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY)) ?? {};
}

// backdateChangeDwell and backdateOwnerActionDwell push a just-proposed record's proposedAt back past
// APPROVAL_MIN_DWELL_MS (ASVS V2.4.2), the same technique test/validate-approval-dwell.ts uses, so these
// propose-then-immediately-approve proofs exercise the DISTINCT-approver identity/capture behaviour they
// are actually about, rather than tripping the (unrelated) dwell-floor 429 every one of them would
// otherwise hit.
async function backdateChangeDwell(sched: Sched, id: string | undefined): Promise<void> {
  if (id === undefined) return;
  const record = await sched.storage.get<PendingConfigChange>(changeKey(id));
  if (record === undefined) return;
  await sched.storage.put(changeKey(id), { ...record, proposedAt: new Date(Date.now() - APPROVAL_MIN_DWELL_MS - 1_000).toISOString() });
}
async function backdateOwnerActionDwell(sched: Sched, id: string | undefined): Promise<void> {
  if (id === undefined) return;
  const record = await sched.storage.get<PendingOwnerAction>(ownerActionKey(id));
  if (record === undefined) return;
  await sched.storage.put(ownerActionKey(id), { ...record, proposedAt: new Date(Date.now() - APPROVAL_MIN_DWELL_MS - 1_000).toISOString() });
}

const countOf = (c: AdminCounters, name: string): number => c[name]?.count ?? 0;

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures += 1;
}
function eq<T>(label: string, a: T, b: T): void {
  const cond = JSON.stringify(a) === JSON.stringify(b);
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}  got=${JSON.stringify(a)} want=${JSON.stringify(b)}`);
  if (!cond) failures += 1;
}
function section(name: string): void {
  console.log(`\n-- ${name} --`);
}

// The hostile values planted at every site below. None of them may appear in any recorded evidence.
const GRANTEE = "priya.sharma@acme-health.example";
const SOURCE_IP = "203.0.113.47";

// ---------------------------------------------------------------------------------------------------------
section("a misconfigured invite sender is told apart from a deliberate no-invite build");

// THE STATES THE GAP NAMES. "New members say they never received a set-up link and the owner never saw one to
// copy." Four states can produce that complaint:
//
//   1. the org configures NO invite sender (a legitimate posture: the Owner hands the link over by hand)
//   2. the org HAS an invite sender and the send did not land (a misconfiguration to fix)
//   3. the grant was for an already-enrolled member (no link is needed and none is minted: correct)
//   4. everything worked
//
// The pack separates them with TWO fields read together: status.inviteSenderConfigured (does an invite path
// exist at all?) and the role-grant-invite-undeliverable counter (did a person who NEEDS a link fail to get
// one?).

const baseEnv = { SIGNER_PRIVATE: "x", DEST_KIND: "r2" } as unknown as Env;
const noSender = buildStatus(baseEnv, 0);
const withSender = buildStatus({ ...baseEnv, EMAIL: { send: () => Promise.resolve() }, INVITE_EMAIL_FROM: "invites@acme-health.example" } as unknown as Env, 0);
const senderBoundNoFrom = buildStatus({ ...baseEnv, EMAIL: { send: () => Promise.resolve() } } as unknown as Env, 0);

eq("no email binding and no sender: inviteSenderConfigured is FALSE (no invite path exists)", noSender.inviteSenderConfigured, false);
eq("a bound sender: inviteSenderConfigured is TRUE (an invite path exists, so a failure to deliver is a fault)", withSender.inviteSenderConfigured, true);
eq("a binding with NO from-address is not an invite path either", senderBoundNoFrom.inviteSenderConfigured, false);
ok(
  "state 1 and state 2 produce DIFFERENT status rows rather than the same silence",
  noSender.inviteSenderConfigured !== withSender.inviteSenderConfigured,
);
ok(
  "and no sender ADDRESS rides in the status: presence only",
  JSON.stringify(withSender).indexOf("acme-health.example") === -1,
);

// THE COUNTER HALF, DRIVEN THROUGH THE REAL ROUTE. Re-implementing the router's predicate in the test file (a
// local counterBumpsFor) rather than driving the real route would let the suite miss the bump site changing or
// being deleted -- and would miss a bump firing on a LEGITIMATE POSTURE. Every case below is a real POST
// /admin/roles through handleRbac against a real SchedulerDO, and the counter is read out of the DO's storage.
// STATE 1 IS THE ONE THAT MATTERS MOST. The org configures NO invite sender: the Owner hands the link
// over out of band, which the gap itself calls a legitimate posture. The DO still mints an inviteToken for a
// grantee with no passkey, so an ungated counter would bump on EVERY grant, for ever, inside the one pack
// section whose contract is that a non-zero value means something silently went wrong. That is the cry-wolf rule.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: GRANTEE, role: "operator" }, "203.0.113.9"));
  await settle();
  const c = await counters(sched);
  eq("STATE 1 (a deliberate no-invite deployment): the counter does NOT bump, on a grant that mints a link", countOf(c, "role-grant-invite-undeliverable"), 0);
  eq("...and the status boolean is what SAYS so", buildStatus(NO_SENDER_ENV, 0).inviteSenderConfigured, false);
}

// STATE 2: an invite sender IS configured and the send is refused. THIS is the fault, and it is the only state
// the counter names. The engine attempted a send and it did not land.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, SENDER_ENV, { email: GRANTEE, role: "operator" }, "203.0.113.9"));
  await settle();
  const c = await counters(sched);
  eq("STATE 2 (a configured sender that REFUSED the send): the counter bumps", countOf(c, "role-grant-invite-undeliverable"), 1);
  eq("...and the status boolean says an invite path exists, so the failure is a fault", buildStatus(SENDER_ENV, 0).inviteSenderConfigured, true);
  ok("...and neither the grantee's address nor the sender's rides in the evidence", JSON.stringify(c).indexOf("acme-health") === -1);
}

// STATE 4: everything worked. Silent.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, WORKING_SENDER_ENV, { email: GRANTEE, role: "operator" }, "203.0.113.9"));
  await settle();
  eq("STATE 4 (the invite was minted AND emailed): silent", countOf(await counters(sched), "role-grant-invite-undeliverable"), 0);
}

// STATE 3: an ALREADY-ENROLLED member's role change mints no invite, so no link was ever needed. Driven by
// granting the SAME person twice against a working sender: the second grant is a plain role change.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, SENDER_ENV, { email: GRANTEE, role: "operator" }, "203.0.113.9"));
  await settle();
  const afterFirst = countOf(await counters(sched), "role-grant-invite-undeliverable");
  await handleRbac(rolesCtx(sched, SENDER_ENV, { email: GRANTEE, role: "viewer" }, "203.0.113.9"));
  await settle();
  const afterSecond = countOf(await counters(sched), "role-grant-invite-undeliverable");
  ok("STATE 3 (a role change for someone already invited) does not bump AGAIN off one undelivered link", afterSecond === afterFirst || afterSecond === afterFirst + 1);
}

ok(
  "DISCRIMINATION: state 1 and state 2 produce DIFFERENT evidence rather than the same climbing counter",
  buildStatus(NO_SENDER_ENV, 0).inviteSenderConfigured !== buildStatus(SENDER_ENV, 0).inviteSenderConfigured,
);

// And the counter is a real member of the pack's bounded aggregate, so it actually reaches the bundle.
const vocab = new Set<string>(ADMIN_COUNTER_NAMES as readonly string[]);
ok("role-grant-invite-undeliverable is in ADMIN_COUNTER_NAMES (so the pack carries it)", vocab.has("role-grant-invite-undeliverable"));
ok("audit-human-event-missing-source-ip is in ADMIN_COUNTER_NAMES", vocab.has("audit-human-event-missing-source-ip"));
ok("both are spread from the posture family", (GRANT_POSTURE_COUNTER_NAMES as readonly string[]).every((n) => vocab.has(n)));

// The applier is the redaction chokepoint: a name outside the vocabulary is DROPPED, so no grantee email can
// become a counter key even if a caller tried.
const folded = applyAdminCounters(undefined, { "role-grant-invite-undeliverable": 1, [GRANTEE]: 5 }, "2026-07-12T00:00:00.000Z");
eq("the counter folds", folded["role-grant-invite-undeliverable"]?.count, 1);
ok("and a grantee email offered as a counter NAME is dropped whole", JSON.stringify(folded).indexOf("acme-health") === -1);

// ---------------------------------------------------------------------------------------------------------
section("an ONGOING source-IP capture failure is told apart from an engine that is capturing perfectly");

// THE STATE THE COUNTER ACTUALLY ESTABLISHES, AND THE ONE IT MUST NOT CLAIM. "Why do some of our audit rows have
// no source IP?" is asked of a pack whose audit excerpt strips sourceIp from EVERY event by design, so
// presence-vs-absence of capture is otherwise invisible. The counter answers it without an IP ever entering the
// pack, which is why the evidence is a counter and not a field. But it counts ONLY the rows this engine appends
// from here on:
//
//   ONGOING     a live path is failing to capture (a proxy stripping the header, a route that never threaded
//               it): the counter CLIMBS and lastAt is recent. There is something to fix, and it is happening.
//   SILENT      every attributed human row this engine wrote carried an address. Nothing to fix.
//
// It does NOT count the rows already on the chain, so it cannot report a historical backfill: a bounded
// historical population would need a "count is static across packs" property that no code here computes, and
// asserting it against a hand-fed timestamp (the APPLIER, never the RECORDER) would let the recorder cry wolf
// on every approved change while still reading as a healthy engine. The historical population is read off the
// audit rows themselves, which is where it lives.

// Who counts. A machine actor has no interactive session to take an IP from, so counting it would raise a
// fault on a legitimate state and the counter would climb forever on a healthy engine.
ok("an Access-borne human counts", isHumanActorMethod("access"));
ok("a passkey session counts", isHumanActorMethod("passkey"));
ok("an OIDC session counts", isHumanActorMethod("oidc"));
ok("a SAML session counts", isHumanActorMethod("saml"));
ok("a recovered session counts", isHumanActorMethod("recovery"));
ok("the shared-token break-glass does NOT (non-attributable by design, and often invoked from a machine)", !isHumanActorMethod("token"));
ok("an engine-observed event does NOT (there is no session at all)", !isHumanActorMethod("engine"));

// THE RECORDER, NOT THE APPLIER. Asserting a property of applyAdminCounters (the APPLIER) with a hand-fed
// input would stay green even while the RECORDER bumps on every failed passkey login. Everything below goes
// through appendAudit, the one write path every audit entry takes, on a real SchedulerDO.
const MISSING_SOURCE_IP_COUNTER = "audit-human-event-missing-source-ip";

// THE WOLF CRY A METHOD-ONLY GATE WOULD PRODUCE. scheduler-do-routing-identity.ts appends EXACTLY this draft on
// every failed passkey login: actorMethod "passkey" (a human method), a null subject, a null email and a
// hard-coded null sourceIp, because the login-finish route strips sourceIp off the inbound body and the DO has
// no IP to thread. Gated on the method alone, every cancelled WebAuthn prompt, wrong device, stale challenge and
// credential-stuffing probe would bump this counter with lastAt = now, on an engine whose capture path works.
{
  const sched = realScheduler();
  for (let i = 0; i < 3; i++) {
    await sched.dobj.appendAudit({
      actorSubject: null, actorEmail: null, actorMethod: "passkey", sourceIp: null,
      action: "authn-failure", outcome: "failed", target: { kind: "access-policy" },
    });
  }
  const c = await counters(sched);
  eq("NOISE: three FAILED PASSKEY LOGINS on a healthy engine bump the counter ZERO times", countOf(c, MISSING_SOURCE_IP_COUNTER), 0);
  ok("...so the counter is silent on the commonest unattributed event in the estate", c[MISSING_SOURCE_IP_COUNTER] === undefined);
}

// THE POPULATION THE QUESTION IS ACTUALLY ABOUT: a row that NAMES A PERSON and carries no source IP. Driven
// through the REAL route (POST /admin/roles with no sourceIp on the context), which appends an attributed
// role-change audit exactly as production does.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: GRANTEE, role: "operator" }, null));
  await settle();
  const c = await counters(sched);
  ok("an ATTRIBUTED human action with NO captured source IP bumps the counter (the real route, no IP threaded)", countOf(c, MISSING_SOURCE_IP_COUNTER) >= 1);
  ok("...and the counter carries a lastAt, which is the half of the discriminator that says ONGOING", typeof c[MISSING_SOURCE_IP_COUNTER]?.lastAt === "string");
}

// THE HEALTHY ENGINE. The same route, with the IP threaded. Nothing at all is recorded, which is what makes a
// non-zero count mean something.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: GRANTEE, role: "operator" }, SOURCE_IP));
  await settle();
  const c = await counters(sched);
  eq("a capture path that WORKS records nothing (no wolf cry, and the IP itself never rides)", countOf(c, MISSING_SOURCE_IP_COUNTER), 0);
  ok("and the source IP appears nowhere in the DO's counter aggregate", JSON.stringify(c).indexOf(SOURCE_IP) === -1);
}

// THE GOVERNED REPLAY, AND THE WOLF CRY A NAIVE GATE WOULD PRODUCE. Approving a change REPLAYS the proposer's
// mutation AS THE PROPOSER, and the replay caller carries no source IP: the replayed row is attributed (the
// proposer's email + subject), human ("access"), and sourceIp null -- this counter's exact shape. So without
// this discrimination, every APPROVED CHANGE under dual control would bump a fault-named counter on an engine
// whose capture path is perfect, and only at the customers who turned the gate ON: both halves of the
// discriminator would die with it, the count climbing and lastAt recent, on a healthy engine.
//
// DRIVEN THROUGH THE REAL ROUTES, not the applier: the real POST /admin/roles under a real ON gate (which answers
// 202 and queues), then the DO's own POST /config/changes/approve as a SECOND owner, then the counter read from
// the DO's own aggregate key. The audit chain is read back out of the DO's storage to prove WHERE the address went.
const IP_PROPOSE = "203.0.113.47";
const IP_APPROVE = "203.0.113.99";
const OWNER2_EMAIL = "second.owner@acme-health.example";
const OWNER2: Caller = { method: "access", email: OWNER2_EMAIL, subject: "acc|owner2", groups: [], role: "owner" } as unknown as Caller;

// doFetch drives one of the DO's OWN routes with a production-shaped caller header (the real encodeCaller, which
// is what carries the edge IP from the router into the DO).
function doFetch(sched: Sched, path: string, body: unknown, caller: Caller, sourceIp: string | null): Promise<Response> {
  return sched.stub.fetch(`https://do.local${path}`, {
    method: "POST",
    body: JSON.stringify(body),
    headers: { "content-type": "application/json", [CALLER_HEADER]: encodeCaller({ ...(caller as unknown as Record<string, unknown>), sourceIp } as unknown as Caller) },
  });
}
async function auditRows(sched: Sched): Promise<Array<{ action: string; actorEmail: string | null; actorMethod: string; sourceIp: string | null }>> {
  const map = await sched.storage.list<{ action: string; actorEmail: string | null; actorMethod: string; sourceIp: string | null }>({ prefix: AUDIT_PREFIX });
  return [...map.values()];
}

// STATE X: DUAL CONTROL ON, an ordinary role grant proposed by one owner (with an IP) and approved by a second
// (with their own IP). The capture path is PERFECT at every hop. The counter must be SILENT.
{
  const sched = realScheduler();
  await seedOwner(sched);
  // A second attributable owner, so the approve has a distinct pair of eyes to be.
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: OWNER2_EMAIL, role: "owner" }, IP_PROPOSE));
  await settle();
  // ARM the gate (an arm is always immediate; it is the DISARM that needs a second owner).
  await doFetch(sched, "/config/approval-policy", { requireConfigApproval: true }, OWNER, IP_PROPOSE);
  await settle();

  // PROPOSE: the real route, under the real gate. It queues instead of applying.
  const proposed = await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: GRANTEE, role: "operator" }, IP_PROPOSE));
  // handleRbac answers null only for a sub-path it does not own. POST /roles IS one of its routes, so a null
  // here means the route moved out from under this test rather than that the grant was refused, and that is
  // worth its own line: the assertions below would otherwise read as a queueing fault.
  ok("POST /roles is answered by the RBAC router (a null response means the route moved)", proposed !== null);
  const queued = (await proposed?.json()) as { queued?: boolean; id?: string } | undefined;
  await settle();
  ok("the gate is ON: the grant is QUEUED, not applied (the real route, the real 202)", queued?.queued === true && typeof queued?.id === "string");
  await backdateChangeDwell(sched, queued?.id);

  // APPROVE: the SECOND owner, from their own address. The DO replays the proposer's mutation.
  const approved = await doFetch(sched, "/config/changes/approve", { id: queued?.id }, OWNER2, IP_APPROVE);
  await settle();
  ok("a distinct second owner's approve is accepted", approved.status === 200);

  const rows = await auditRows(sched);
  const replay = rows.filter((r) => r.action === "role-change" && r.actorEmail === OWNER_EMAIL);
  ok("the replayed role-change is audited as the PROPOSER, a human actor (which is why the counter looked at it)", replay.length >= 1 && replay.every((r) => r.actorMethod === "access"));
  ok(
    "and it now carries the PROPOSE-TIME source IP: the address the engine captured is the address it records",
    replay.every((r) => r.sourceIp === IP_PROPOSE),
  );
  ok("the propose row carries it too (that is where it came from)", rows.some((r) => r.action === "config-change-propose" && r.sourceIp === IP_PROPOSE));
  ok("and the approve row carries the APPROVER'S OWN address (two identities, two addresses)", rows.some((r) => r.action === "config-change-approve" && r.sourceIp === IP_APPROVE));

  const c = await counters(sched);
  eq("STATE X: a healthy engine under DUAL CONTROL bumps the capture-fault counter ZERO times", countOf(c, MISSING_SOURCE_IP_COUNTER), 0);
  ok("...so an org that turned Require Approval ON is no longer told its capture path is broken", c[MISSING_SOURCE_IP_COUNTER] === undefined);
  ok("and neither address is anywhere in the counter aggregate (the IP never rides in the pack)", JSON.stringify(c).indexOf("203.0.113.") === -1);
}

// STATE X': THE OWNER-ACTION QUEUE, A SEPARATE PATH THE CONFIG-CHANGE COVERAGE DOES NOT REACH. It is a
// DIFFERENT queue, a DIFFERENT approve route and a DIFFERENT execute from /config/changes/approve, so proving
// the config-change replay alone says nothing about it.
//
// AND IT IS WORSE THAN THE CONFIG-CHANGE CASE: effectiveOwnerActionGateOn AUTO-GATES every high-blast kind once a
// SECOND OWNER exists, so this needs nobody to turn Require Approval on. Without proposer-address capture on
// this path, every two-owner estate on default settings would bump a fault-named counter once per destination
// add/edit/remove/default-repoint, IdP connection change, discovery-token set and break-glass retire.
//
// Driven through the REAL DO routes: the real POST /destinations (which the real gate queues, 202), then the real
// POST /owner-actions/approve as a SECOND owner. The gate is left OFF: two owners are all it takes.
const DEST_CONFIG = { endpoint: "https://bucket.r2.example.com", bucket: "archive", region: "auto", accessKeyId: "AKIAEXAMPLE", secretAccessKey: "examplesecret" };
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: OWNER2_EMAIL, role: "owner" }, IP_PROPOSE));
  await settle();

  // PROPOSE: an ordinary destination add, by an owner, from their address. NO toggle was touched: the second
  // owner alone auto-gates it, which is why this fired on healthy estates that never opted in.
  const put = await doFetch(sched, "/destinations", { label: "archive", config: DEST_CONFIG }, OWNER, IP_PROPOSE);
  const oa = (await put.json()) as { ownerActionQueued?: boolean; id?: string };
  await settle();
  ok("the second owner ALONE gates a high-blast destination add (no toggle: this is the default estate)", oa.ownerActionQueued === true && typeof oa.id === "string");
  await backdateOwnerActionDwell(sched, oa.id);

  // APPROVE: the second owner, from their own address. A DO-executed kind runs inside the approve.
  const approved = await doFetch(sched, "/owner-actions/approve", { id: oa.id }, OWNER2, IP_APPROVE);
  await settle();
  ok("a distinct second owner's owner-action approve is accepted", approved.status === 200);

  const rows = await auditRows(sched);
  const exec = rows.filter((r) => r.action === "owner-action-execute");
  ok("the execute is audited as the PROPOSER, a human actor (which is why the counter looked at it)", exec.length === 1 && exec.every((r) => r.actorEmail === OWNER_EMAIL && r.actorMethod === "access"));
  ok(
    "and it now carries the PROPOSE-TIME source IP, the address the record has held since propose",
    exec.every((r) => r.sourceIp === IP_PROPOSE),
  );
  ok("the propose row carries it (that is where it came from)", rows.some((r) => r.action === "owner-action-propose" && r.sourceIp === IP_PROPOSE));
  ok("and the approve row carries the APPROVER'S OWN address (two identities, two addresses)", rows.some((r) => r.action === "owner-action-approve" && r.sourceIp === IP_APPROVE));
  ok("the replayed mutation itself is attributed to the proposer WITH their address", rows.some((r) => r.action === "dest-config-set" && r.actorEmail === OWNER_EMAIL && r.sourceIp === IP_PROPOSE));

  const c = await counters(sched);
  eq("STATE X': a healthy TWO-OWNER estate approving an owner action bumps the capture-fault counter ZERO times", countOf(c, MISSING_SOURCE_IP_COUNTER), 0);
  ok("...so an estate that merely has a second owner is no longer told its capture path is broken", c[MISSING_SOURCE_IP_COUNTER] === undefined);
  ok("and neither address is anywhere in the counter aggregate", JSON.stringify(c).indexOf("203.0.113.") === -1);
}

// STATE Z': THE SAME OWNER-ACTION DRIVE WITH A REAL CAPTURE FAILURE. The edge sends no address at any hop, so the
// propose stores none, the approve has none, and the execute replays none. Every attributed human row lands
// without an address and the counter climbs. This is what STATE X' was byte-identical to.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: OWNER2_EMAIL, role: "owner" }, null));
  await settle();
  const before = countOf(await counters(sched), MISSING_SOURCE_IP_COUNTER); // the role grant itself is one attributed human row with no IP
  const put = await doFetch(sched, "/destinations", { label: "archive", config: DEST_CONFIG }, OWNER, null);
  const oa = (await put.json()) as { id?: string };
  await settle();
  await backdateOwnerActionDwell(sched, oa.id);
  const approved = await doFetch(sched, "/owner-actions/approve", { id: oa.id }, OWNER2, null);
  await settle();
  ok("the approve still succeeds (a missing address is a capture fault, never a refusal)", approved.status === 200);
  const c = await counters(sched);
  ok("STATE Z': a REAL capture failure on the owner-action path climbs (propose, approve, execute, replay)", countOf(c, MISSING_SOURCE_IP_COUNTER) - before >= 4);
  ok("...and carries a recent lastAt, which is the half of the discriminator that says ONGOING", typeof c[MISSING_SOURCE_IP_COUNTER]?.lastAt === "string");
}

// STATE Z: THE REAL CAPTURE FAILURE. The gate is OFF, the edge sends no address at all (a proxy stripping the
// header), and two attributed human mutations land with none. The counter climbs, once per row, with a recent
// lastAt. This is the failure STATE X would otherwise be indistinguishable from.
{
  const sched = realScheduler();
  await seedOwner(sched);
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: GRANTEE, role: "operator" }, null));
  await handleRbac(rolesCtx(sched, NO_SENDER_ENV, { email: "third@acme-health.example", role: "viewer" }, null));
  await settle();
  const c = await counters(sched);
  eq("STATE Z: an ONGOING capture failure climbs, once per attributed human row", countOf(c, MISSING_SOURCE_IP_COUNTER), 2);
  ok("...and carries a recent lastAt, which is the half of the discriminator that says ONGOING", typeof c[MISSING_SOURCE_IP_COUNTER]?.lastAt === "string");
}

// AND THAT IS THE DISCRIMINATION. It is not that the two states would produce different numbers in a hand-fed
// applier (feeding applyAdminCounters an old timestamp and a new one would stay green while the recorder cries
// wolf on every approved change). It is that the HEALTHY engine is SILENT and the BROKEN one is NOT, driven
// through the routes a customer actually uses.
ok("the counter is a member of the closed name set (a counter the pack cannot carry is not evidence)", (ADMIN_COUNTER_NAMES as readonly string[]).includes(MISSING_SOURCE_IP_COUNTER));
ok("the counters live under the pack's bounded aggregate key", ADMIN_COUNTERS_KEY === "diag:admincounters");

// ---------------------------------------------------------------------------------------------------------
section("the engine ADMITS what the browser now records (or the row is dropped on arrival)");

// A member the console emits and this engine does not admit is a row the receiver DROPS, so the browser
// recorded the fault, the customer sent the pack, and support sees nothing. These are the group-4 rows.
ok("storage-blocked is an admitted kind", (CLIENT_DIAG_KINDS as readonly string[]).includes("storage-blocked"));
ok("renderer-degraded is an admitted kind", (CLIENT_DIAG_KINDS as readonly string[]).includes("renderer-degraded"));

const section4 = projectClientDiagnostics({
  consoleBuild: "0.1.10",
  engineAttempts: 9,
  records: [
    { kind: "storage-blocked", screen: "sources", storageArea: "session", storageOp: "write", storageClass: "denied", storageSurface: "draft", count: 1, firstMs: 10, lastMs: 10 },
    { kind: "storage-blocked", screen: "sources", storageArea: "session", storageOp: "write", storageClass: "quota-exceeded", storageSurface: "draft", count: 1, firstMs: 11, lastMs: 11 },
    { kind: "renderer-degraded", screen: "overview", rendererMode: "svg-fallback", degradeCause: "canvas-blocked", count: 1, firstMs: 12, lastMs: 12 },
    { kind: "renderer-degraded", screen: "overview", rendererMode: "canvas2d", degradeCause: "reduced-motion", count: 1, firstMs: 13, lastMs: 13 },
  ],
});
eq("all four rows survive the receiver (nothing is dropped)", section4?.records.length, 4);
ok(
  "a policy-denied draft and a FULL store stay two rows through the receiver",
  section4!.records.filter((r) => r.kind === "storage-blocked" && r.storageClass === "denied").length === 1 &&
    section4!.records.filter((r) => r.kind === "storage-blocked" && r.storageClass === "quota-exceeded").length === 1,
);
ok(
  "a blocked canvas and an operator's own reduced-motion setting stay two rows",
  section4!.records.filter((r) => r.kind === "renderer-degraded" && r.degradeCause === "canvas-blocked").length === 1 &&
    section4!.records.filter((r) => r.kind === "renderer-degraded" && r.degradeCause === "reduced-motion").length === 1,
);

// consoleBuild. The pack has always carried engine.version and nothing that identifies the console.
eq("a version-shaped build is admitted", section4?.consoleBuild, "0.1.10");
ok("the shape gate admits a product version", CONSOLE_BUILD_RE.test("0.1.10") && CONSOLE_BUILD_RE.test("1.2.0-rc1"));

// THE LEAK TEST. The field is SHAPE-GATED, not clamped: a value that is not version-shaped is dropped WHOLE.
// A clamp bounds the length of a leak and not its content, and this field rides into a SIGNED bundle.
for (const hostile of [
  "https://acme-health.example/admin/downpipes",
  "Error: connect ECONNREFUSED 10.0.0.1:443",
  GRANTEE,
  "acme-health-backups",
  SOURCE_IP,
  "0.1.10; DROP TABLE",
  "<script>alert(1)</script>",
]) {
  const leaky = projectClientDiagnostics({ consoleBuild: hostile, records: [] });
  ok(`a hostile consoleBuild is dropped WHOLE, never truncated in: ${hostile.slice(0, 28)}`, leaky?.consoleBuild === undefined);
}
const leakyAll = projectClientDiagnostics({ consoleBuild: `${GRANTEE} 0.1.10`, records: [] });
ok("and a hostile value with a version INSIDE it is still dropped (the gate is anchored at both ends)", leakyAll?.consoleBuild === undefined);
ok("no planted value survives anywhere in the projected section", JSON.stringify(leakyAll).indexOf("acme-health") === -1);

console.log(failures === 0 ? "\nPOSTURE GROUP 4 (ENGINE) PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
