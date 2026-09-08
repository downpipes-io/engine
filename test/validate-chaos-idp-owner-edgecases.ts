// validate-chaos-idp-owner-edgecases.ts -- regression test for owner-mint laundering, driven through the
// REAL router + DO with forged callers (the same in-process chaos pattern as validate-chaos-auth-races.ts:
// real handlers, no cloud).
//
// THE INVARIANT UNDER TEST. With the dual-control toggle OFF and two or more owners, destination and IdP
// ops auto-gate (HIGH_BLAST_ALWAYS_GATED), so a lone compromised owner cannot repoint a destination without
// a second owner approving. Role grants must be gated the same way: a compromised owner must not be able to
// inline-mint its OWN colluding OWNER and use it as the "distinct" checker to approve its own exfil.
//
// THE MECHANISM (both in scheduler-do-change-control.ts):
//  1. autoGateOwnerMint auto-gates an OWNER-minting role-set once a second owner exists, toggle or not. It is
//     narrow -- access-admin and every other appointment stay inline; only minting a new Owner dual-gates.
//  2. approveChange requires an OWNER (not merely a roles.write holder) to approve an owner-conferring change,
//     so a minted access-admin cannot approve the owner-mint (the hop), and no owner-escalation-by-approval.
// Together a lone compromised owner cannot manufacture the Owner checker its own high-blast op needs.

import { buildContext, ok, failureCount } from "./validate-owner-action-dualcontrol-harness.ts";

const ctx = await buildContext();
const { OWNER, OWNER2, call, doFetch, ownerCaller, destConfig, listDestinations } = ctx;

const roleOf = async (email: string): Promise<string> =>
  ((await (await call(email, "GET", "/admin/whoami")).json()) as { role?: string }).role ?? "viewer";
const jsonId = async (r: Response): Promise<string> => ((await r.json()) as { id?: string }).id ?? "";

console.log("Scenario A: owner-mint auto-gate + owner-approver rule close the laundering (toggle OFF)");
{
  // The honest protective state: a SECOND owner exists, so destination changes auto-gate even with the toggle
  // off. This is the state a customer sets up believing "two owners = dual control on data".
  await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" });
  ok("[A] two owners exist, so the destination surface auto-gates", (await roleOf(OWNER2)) === "owner");

  // The gate is NARROW: appointing an access-admin (ordinary people-management) still applies inline. Do it
  // NOW, before the owner-mint proposal below, so its config-history snapshot does not supersede that pending
  // owner-mint (an intervening inline config mutation moves the head).
  const admin = await call(OWNER, "POST", "/admin/roles", { email: "puppet-admin@acme.example", role: "access-admin" });
  ok("[A] appointing an access-admin is still inline (200) -- the gate is scoped to owner-minting only", admin.status === 200);
  await call("puppet-admin@acme.example", "GET", "/admin/whoami"); // bind the grant to the alias subject
  ok("[A] the access-admin puppet resolves to access-admin (a roles.write holder)", (await roleOf("puppet-admin@acme.example")) === "access-admin");

  // The compromised owner proposes an exfil destination -> auto-gated (202), and CANNOT self-approve.
  const propose = await doFetch("/destinations", ownerCaller(OWNER), { label: "exfil", config: destConfig("attacker-exfil-bucket") });
  ok("[A] the exfil dest-put is auto-queued (202), not applied on the proposer alone", propose.status === 202);
  const self = await doFetch("/owner-actions/approve", ownerCaller(OWNER), { id: await jsonId(propose) });
  ok("[A] the compromised owner cannot self-approve the exfil (maker != checker, 400)", self.status === 400);

  // To obtain an OWNER checker for that exfil, the attacker proposes an owner-mint -> NOW auto-gated (fix #1).
  const mint = await call(OWNER, "POST", "/admin/roles", { email: "puppet@acme.example", role: "owner" });
  ok("[A] minting a puppet OWNER is auto-gated (202), not inline", mint.status === 202);
  const mintId = await jsonId(mint);

  // THE ACCESS-ADMIN HOP, now BLOCKED (fix #2): a roles.write holder that is NOT an Owner cannot approve an
  // owner-conferring change, so the attacker cannot use its minted access-admin to approve the owner-mint.
  const hop = await call("puppet-admin@acme.example", "POST", `/admin/config/changes/${mintId}/approve`);
  ok("[A] an access-admin CANNOT approve an owner-grant (only an Owner may) -> the hop is closed", hop.status >= 400 && hop.status < 500);
  ok("[A] the puppet owner was NOT created (no manufacturable owner checker)", (await roleOf("puppet@acme.example")) !== "owner");

  // With no way to manufacture an Owner checker, the exfil cannot be approved by the attacker alone.
  ok("[A] the exfil destination is still NOT live", !(await listDestinations()).destinations.some((d) => d.label === "exfil"));

  // Sanity: the mechanism blocks laundering, not legitimate appointments -- a genuine second Owner can approve.
  const legit = await call(OWNER2, "POST", `/admin/config/changes/${mintId}/approve`);
  ok("[A] a genuine second Owner CAN approve the owner-mint (200)", legit.status === 200);
  ok("[A] with a real Owner's approval the appointment lands", (await roleOf("puppet@acme.example")) === "owner");
}

console.log("\nScenario B: arming the toggle also gates owner-minting (defence in depth)");
{
  await ctx.setGate(OWNER, true); // arm (immediate for an attributable owner)
  const gateOn = ((await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean }).requireConfigApproval;
  ok("[B] dual control is armed", gateOn === true);
  const grant = await call(OWNER, "POST", "/admin/roles", { email: "puppet3@acme.example", role: "owner" });
  ok("[B] with the toggle on, minting an owner is gated (202 pending)", grant.status === 202);
  ok("[B] the would-be owner is NOT an owner without a second approver", (await roleOf("puppet3@acme.example")) !== "owner");
}

console.log(`\n${failureCount() === 0 ? "IDP/OWNER EDGE-CASE CHAOS PASS" : "IDP/OWNER EDGE-CASE CHAOS: " + failureCount() + " FAIL"}`);
if (failureCount() > 0) process.exitCode = 1;
if (failureCount() > 0) process.exit(1);
