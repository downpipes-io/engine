// validate-replay-identity-liveness: THE CONNECTION AXIS A REPLAY NEVER CONSULTED.
//
// THE RULE THE FILE IS ABOUT. A replay must never resolve to more authority than a live request from that
// same identity would. This proves the connection-liveness axis of that rule: it is a whole axis rather
// than a stale value.
//
// WHAT A LIVE REQUEST PASSES AND A REPLAY DID NOT. An oidc/saml session is valid only while the connection
// its subject was minted through still EXISTS and is ENABLED: scheduler-do-session re-reads that record on
// every request, which is what makes deleting or disabling an IdP connection a real revocation rather than a
// hint. A replay presents no session and so passed none of it. The measured consequence: a person could be
// offboarded, have every sign-in factor revoked, have every session terminated account-wide AND have the
// identity-provider connection they authenticate through deleted outright, and their queued high-blast owner
// action still ran on approval, because the re-resolution asked only the role table.
//
// IT IS FIXED IN roleForCaller, NOT IN scopeGroupMapping, and the difference is the whole scope of the fix.
// The group-mapping scope derives a connection id from the subject string and never checks liveness, which is
// where the gap is easiest to see; but the request path refuses a dead-connection session OUTRIGHT, so a
// person carrying a DIRECT role row on a dead connection is refused every request too. Refusing only their
// group-derived authority would have closed the visible half and left the other one open.
//
// IT SUSPENDS RATHER THAN VOIDS, exactly as every other axis of the binding does, and A11 drives that:
// re-enable the connection and the same queued action runs with no fresh ceremony. A connection DELETED and
// re-created gets a new connection id and therefore a new subject, so its members' records were already dead
// on the subject axis and nothing here changes that.
//
// THIS SITE, AND ITS SIBLING. The owner-action replay caller already carries the `replay` flag, so this
// file measures the LIVENESS gate and nothing else. The CONFIG-CHANGE replay caller is a separate site,
// built inline rather than through a named helper, and it is proved separately in
// validate-replay-bind-config-change.ts. They are two files rather than two sections for a mechanical reason
// worth knowing: each dual-control harness forges its own RS256 Access key and serves its own JWKS through a
// stubbed global fetch, the verifier caches a JWKS per issuer, and both harnesses use the same issuer, so a
// second harness built in the SAME process has every one of its tokens rejected. Driven together, the second
// section failed with "authorise rejected the presented credential" on every call, which reads exactly like a
// broken fix and is nothing of the kind. One harness per process.
//
// Deleting the liveness branch reddens A6/A7/A9/A10/A11 here and B7/B8/B9 in the sibling; deleting the
// sibling's replay flag reddens only the sibling and leaves this file at 19 of 19. So neither source change
// is carried by the other's assertions.
//
// Run: node test/validate-replay-identity-liveness.ts

import { connKey } from "../src/admin/oidc-store-kv.ts";
import { roleSubjectKey } from "../src/admin/identity.ts";
import { buildContext as buildOwnerActionContext } from "./validate-owner-action-dualcontrol-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A native-IdP subject is "oidc:<connId>|<issuer>|<sub>", so the connection id is recoverable from the
// subject alone: that is precisely why the re-resolution CAN check liveness, and why it was worth checking
// that it did not. The role rows are planted directly because a direct grant on a native subject is the
// shape the group mapping cannot produce (capGroupRole clamps a group mapping below owner), and an owner
// action needs an owner.
const nativeSubject = (connId: string, who: string): string => `oidc:${connId}|https://idp.example|${who}`;

async function sectionA(): Promise<void> {
  const ctx = await buildOwnerActionContext();
  const { sched, OWNER2, call, doFetch, ownerCaller, destConfig, setGate } = ctx;
  const store = sched.storage;

  // Plant a native-IdP OWNER on a LIVE connection, and a second on a connection that will be killed. Both
  // are ordinary bound role rows; only the connection's fate differs between them, which is what makes the
  // comparison a measurement of the liveness axis rather than of anything else.
  const plant = (connId: string, who: string, enabled: boolean): string => {
    const subject = nativeSubject(connId, who);
    store.rawPut(connKey(connId), { id: connId, kind: "oidc", enabled, name: connId });
    store.rawPut(roleSubjectKey(subject), { subject, email: `${who}@acme.example`, role: "owner", grantedBy: "seed", grantedAt: new Date().toISOString() });
    return subject;
  };
  const nativeCaller = (connId: string, who: string) => ({ method: "access" as const, email: `${who}@acme.example`, subject: nativeSubject(connId, who), role: "owner" as const, groups: [] });

  // Queue a gated dest-put proposed BY the native-IdP owner, returning the pending record's id.
  const proposeAs = async (connId: string, who: string, label: string): Promise<{ status: number; id: string }> => {
    const r = await doFetch("/destinations", nativeCaller(connId, who), { label, config: destConfig(`${label}-bucket`) });
    const j = (await r.json()) as { id?: string };
    return { status: r.status, id: j.id ?? "" };
  };
  const destExists = async (label: string): Promise<boolean> => (await ctx.listDestinations()).destinations.some((d) => d.label === label);

  try {
    // A second owner is what arms dual control at all: with one owner every high-blast op runs inline and no
    // record is ever written, so there would be nothing to re-resolve and nothing to measure.
    ok("A0a: CONTROL, a second owner exists", (await call(ctx.OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" })).status === 200);
    ok("A0b: CONTROL, the dual-control gate arms, so a high-blast owner action queues rather than running", (await setGate(ctx.OWNER, true)).status === 200);

    // ---- THE FALSE-POSITIVE DIRECTION FIRST, because every refusal below is worthless if the legitimate
    // path does not work. A native-IdP owner on a LIVE, ENABLED connection proposes and their action runs.
    {
      plant("conn-live", "livesub", true);
      const q = await proposeAs("conn-live", "livesub", "replay-live");
      ok("A1: CONTROL, a native-IdP owner on a LIVE connection can queue a gated owner action", q.status === 202 && q.id.length > 0);
      ok("A2: CONTROL, and a second owner's approval RUNS it, so nothing here strands a working estate", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: q.id })).status === 200);
      ok("A3: CONTROL, the destination really was added", await destExists("replay-live"));
    }

    // ---- THE DELETED CONNECTION. The measured case: everything that should have stopped this person has
    // happened, including the deletion of the connection they authenticate through, and their queued action
    // still ran because the re-resolution presented no session and so passed no revocation axis.
    {
      plant("conn-doomed", "doomedsub", true);
      const q = await proposeAs("conn-doomed", "doomedsub", "replay-deleted");
      ok("A4: CONTROL, the doomed proposer queues an action while their connection is still live", q.status === 202 && q.id.length > 0);
      // DELETE the connection, which in production also revokes every live session on it. Nothing else about
      // the proposer changes: their role row is untouched, so a refusal below cannot be the role table.
      await sched.storage.delete(connKey("conn-doomed"));
      ok("A5: CONTROL, their role row is UNTOUCHED, so A6 is about the connection and not about the grant", store.rawGet(roleSubjectKey(nativeSubject("conn-doomed", "doomedsub"))) !== undefined);
      const approve = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: q.id });
      ok("A6: the approve is REFUSED once the proposer's IdP connection is deleted", approve.status >= 400);
      ok("A7: and the destination was NOT added, so the refusal is a real one and not a status", !(await destExists("replay-deleted")));
    }

    // ---- THE DISABLED CONNECTION, the other of the two states the request path refuses on, and the one
    // that shows this is a SUSPENSION rather than a void.
    {
      plant("conn-off", "offsub", true);
      const q = await proposeAs("conn-off", "offsub", "replay-disabled");
      ok("A8: CONTROL, the proposer queues an action while their connection is enabled", q.status === 202 && q.id.length > 0);
      store.rawPut(connKey("conn-off"), { id: "conn-off", kind: "oidc", enabled: false, name: "conn-off" });
      ok("A9: the approve is REFUSED while the proposer's connection is DISABLED", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: q.id })).status >= 400);
      ok("A10: and the destination was NOT added", !(await destExists("replay-disabled")));
      // Re-enable and the SAME queued action runs, with no re-proposal and no fresh approval ceremony.
      store.rawPut(connKey("conn-off"), { id: "conn-off", kind: "oidc", enabled: true, name: "conn-off" });
      ok("A11: CONTROL, re-enabling the connection lets the SAME action run, so this suspends rather than voids", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: q.id })).status === 200);
      ok("A12: CONTROL, and it really ran", await destExists("replay-disabled"));
    }

    // ---- THE UNAFFECTED SHAPES. A Cloudflare-Access or passkey subject belongs to no native connection, so
    // it must never load one and must never be refused by this branch. Without this a fix that refused every
    // replay would satisfy every assertion above.
    {
      const q = await proposeAs("conn-live", "livesub", "replay-access-control");
      ok("A13: CONTROL, a second action queues", q.status === 202);
      ok("A14: CONTROL, an ORDINARY Access-subject owner's action still runs untouched by the liveness branch", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: q.id })).status === 200);
      const accessQ = await doFetch("/destinations", ownerCaller(ctx.OWNER), { label: "replay-access-proposer", config: destConfig("replay-access-proposer-bucket") });
      const accessId = ((await accessQ.json()) as { id?: string }).id ?? "";
      ok("A15: CONTROL, an Access-subject PROPOSER queues", accessQ.status === 202 && accessId.length > 0);
      ok("A16: CONTROL, and their action runs: no connection is ever loaded for a subject that has none", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: accessId })).status === 200);
      ok("A17: CONTROL, and it really ran", await destExists("replay-access-proposer"));
    }
  } finally {
    globalThis.fetch = ctx.realFetch;
  }
}

async function main(): Promise<void> {
  console.log("SECTION A: the connection-liveness axis, at the owner-action replay site");
  await sectionA();

  // Both arguments: called bare the guard reads failures as undefined and declares a verdict that means
  // nothing, and the check count rides so a run that asserted nothing cannot report a pass.
  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
