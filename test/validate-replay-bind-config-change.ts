// validate-replay-bind-config-change: A THIRD REPLAY SITE. A recorded identity re-resolved with no request
// of theirs in hand must never resolve to more authority than a live request from that identity would.
//
// resolveStoredIdentityAuthority and proposerReplayCaller hand a RECORDED EMAIL to roleForCaller, and
// resolveBoundEntry's bind-on-first-auth is a WRITE that matches a pending grant BY EMAIL, binds it onto
// whatever subject is presented, and deletes the pending row. So an ordinary invite issued at a departed
// person's re-used address could re-arm the departed person's act AND consume the new person's grant into
// the departed subject.
//
// approveChange builds its replay caller INLINE rather than through a named helper. Every queued config
// change was exposed through this site: a departed proposer's change, their address re-issued to somebody
// new, and the approve would bind the newcomer's grant onto the departed subject and apply the change
// with it.
//
// THIS FILE IS SEPARATE FROM validate-replay-identity-liveness.ts FOR A MECHANICAL REASON, and it is worth
// writing down. Each dual-control harness forges its own RS256 Access signing key and serves its own JWKS
// through a stubbed global fetch. The verifier caches a JWKS per issuer, and both harnesses use the same
// issuer, so a second harness built in the SAME process has every one of its tokens rejected by the first
// one's cached keys. Driven together, section B failed with "authorise rejected the presented credential" on
// every call, which reads exactly like a broken fix and is nothing of the kind. One harness per process.
//
// Run: node test/validate-replay-bind-config-change.ts

import { roleSubjectKey } from "../src/admin/identity.ts";
import { changeContentHash, changeKey, type PendingConfigChange } from "../src/admin/change-control.ts";
import { connKey } from "../src/admin/oidc-store-kv.ts";
import { buildContext as buildChangeContext, OWNER as CC_OWNER, OPERATOR as CC_OPERATOR, OPERATOR2 as CC_OPERATOR2 } from "./validate-config-change-control-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function run(): Promise<void> {
  const { ctx, realFetch } = await buildChangeContext();
  const { call, sched, setGate } = ctx;
  const store = sched.storage;

  // Re-address a queued change to a NATIVE-IdP proposer. The harness's forged Access assertions can only mint
  // Access-shaped subjects, so the record is re-written to the identity under test AND ITS contentHash IS
  // RECOMPUTED over the new binding, which is what makes this a fixture and not a tamper: the record that
  // results is exactly the record the DO would have written had that person proposed. (An identity swap
  // WITHOUT the recompute is a different thing entirely and is already proved to be caught, by PROOF 17 of
  // validate-config-change-control.) The matching connection and bound role row are planted alongside.
  const readdress = async (changeId: string, connId: string, who: string, enabled: boolean): Promise<string> => {
    const subject = `oidc:${connId}|https://idp.example|${who}`;
    const email = `${who}@acme.example`;
    store.rawPut(connKey(connId), { id: connId, kind: "oidc", enabled, name: connId });
    store.rawPut(roleSubjectKey(subject), { subject, email, role: "operator", grantedBy: "seed", grantedAt: new Date().toISOString() });
    const rec = store.rawGet<PendingConfigChange>(changeKey(changeId))!;
    const contentHash = await changeContentHash(rec.kind, rec.params, email, subject, [], rec.baseVersionId, rec.baseVersionHash);
    store.rawPut(changeKey(changeId), { ...rec, proposedBy: email, proposedBySubject: subject, proposedByGroups: [], contentHash });
    return subject;
  };
  // A notify-channel-set is the kind driven here, and the choice is load-bearing rather than incidental.
  // addNotifyChannel RE-CHECKS the caller's live authority at apply (requireNotifyConfig), which is what the
  // approve path's re-resolution feeds; addDownpipe does NOT re-check downpipe.write at all, so a downpipe
  // upsert would apply whatever the re-resolution answered and the whole section would have proved nothing.
  const queue = async (name: string): Promise<string> => {
    const r = await call(CC_OPERATOR, "POST", "/admin/notify/channels", { kind: "webhook", name, url: `https://${name}.acme.example/hook` });
    return r.status === 202 ? ((await r.json()) as { id: string }).id : "";
  };
  const built = async (name: string): Promise<boolean> => (await ctx.listChannels()).some((c) => c.name === name);

  try {
    ok("B1: CONTROL, the dual-control gate arms", (await setGate(CC_OWNER, true)).status === 200);

    // ---- THE FALSE-POSITIVE DIRECTION FIRST. A native-IdP proposer on a LIVE connection has their queued
    // change applied on approval, exactly as before, so nothing below is a fix that simply refuses everything.
    {
      const changeId = await queue("replay-live-proposer");
      ok("B2: CONTROL, the change queues", changeId.length > 0);
      await readdress(changeId, "cc-live", "ccliveprop", true);
      ok("B3: CONTROL, a distinct approver applies it while the proposer's connection is LIVE", (await call(CC_OPERATOR2, "POST", `/admin/config/changes/${changeId}/approve`)).status === 200);
      ok("B4: CONTROL, and the change really applied", await built("replay-live-proposer"));
    }

    // ---- THE DELETED CONNECTION, and it is REACHABLE here for a reason worth stating: an IdP connection is
    // NOT part of the config snapshot, so deleting one moves no config-history head. The supersede check
    // therefore does not fire and the approve runs all the way to the authority re-resolution, which is the
    // only thing left standing between a departed proposer's queued change and the estate.
    {
      const changeId = await queue("replay-dead-proposer");
      ok("B5: CONTROL, a second change queues", changeId.length > 0);
      await readdress(changeId, "cc-dead", "ccdeadprop", true);
      await sched.storage.delete(connKey("cc-dead"));
      ok("B6: CONTROL, the proposer's role row is UNTOUCHED, so B7 is about the connection and not the grant", store.rawGet(roleSubjectKey(`oidc:cc-dead|https://idp.example|ccdeadprop`)) !== undefined);
      const approve = await call(CC_OPERATOR2, "POST", `/admin/config/changes/${changeId}/approve`);
      ok("B7: the approve is REFUSED once the proposer's IdP connection is deleted", approve.status >= 400);
      ok("B8: and the change did NOT apply", !(await built("replay-dead-proposer")));
      // THE ASSERTION THAT SAYS IT IS THE RIGHT REFUSAL. A superseded record would also refuse and would also
      // leave the change unapplied, so without this B7 could be satisfied by the base-moved guard rather than
      // by the authority axis this file is about.
      ok("B9: and the record is still PENDING, not superseded, so the refusal is the AUTHORITY axis", store.rawGet<PendingConfigChange>(changeKey(changeId))?.status === "pending");
    }

  } finally {
    globalThis.fetch = realFetch;
  }
}

async function main(): Promise<void> {
  await run();
  // Both arguments: called bare the guard reads failures as undefined and declares a verdict that means
  // nothing, and the check count rides so a run that asserted nothing cannot report a pass.
  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
