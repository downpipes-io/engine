// validate-apply-time-capability: THE APPLY THAT ASKED NOBODY. A queued config change is proposed under one
// authority and applied later under another person's approval, and the machine's own account of that moment
// (applyConfigMutation's comment) says "the no-escalation guards ... and the per-method capability re-check
// all run here because they live in the methods this delegates to". For three of the eighteen kinds they do
// not live there at all.
//
//   downpipe-upsert    dispatches this.addDownpipe(params, caller). addDownpipe re-checks ONLY the narrower
//                      scheduledtest.config, and only when the cadence actually CHANGES. downpipe.write is
//                      never asked for.
//   downpipe-delete    dispatches this.removeDownpipe(params) with NO CALLER ARGUMENT AT ALL.
//   cf-config-mode-set dispatches this.setCfConfigMode(params), also with no caller, under a comment that
//                      says the capability "is enforced by the router gate on POST and re-checked at approve
//                      via CHANGE_WRITE_CAPABILITY, so this method itself takes no caller". CHANGE_WRITE_-
//                      CAPABILITY at approve is checked against the CHECKER (canApproveChange), never the
//                      maker, so that sentence is true of the approver and silent about the proposer.
//
// The consequence is that every apply-time authority fix landed on this path today lands on fifteen kinds and
// not eighteen. roleForCaller RETURNS viewer rather than throwing, so the binding, bind-on-first-auth
// suppression and connection-liveness axis all compute the right answer for these three kinds and then
// nothing reads it.
//
// REACHABILITY, WHICH IS THE WHOLE QUESTION, AND IT HAS EXACTLY TWO ANSWERS. approveChange's base-moved check
// fires BEFORE the authority re-resolution, and offboarding or demoting the proposer is itself a config
// mutation that auto-snapshots, so the obvious attack supersedes the change instead of applying it (section F
// measures that, because "it is refused" and "it is refused for the reason you think" are different claims).
// A bypass therefore needs an authority lapse that moves NO config head, and there are two:
//
//   JIT EXPIRY        a time-boxed grant lapsing is a CLOCK event. Nothing is written, nothing snapshots,
//                     and effectiveRole demotes the entry to viewer on the next read. Sections B, C and D.
//   CONNECTION DEATH  an IdP connection is not part of the config snapshot. Section E.
//
// So the two loose ends are one thing: the expiry question IS the reachability proof for the addDownpipe gap.
//
// ONE HARNESS PER PROCESS. Each dual-control harness forges its own RS256 Access signing key and serves its
// own JWKS through a stubbed global fetch; the verifier caches a JWKS per issuer and both harnesses use the
// same issuer, so a second harness built in the SAME process has every one of its tokens rejected by the
// first one's cached keys, which reads exactly like a broken fix and is nothing of the kind.
//
// Run: node test/validate-apply-time-capability.ts

import { changeKey, type PendingConfigChange } from "../src/admin/change-control.ts";
import { ROLE_SUBJECT_PREFIX } from "../src/admin/identity.ts";
import type { RoleEntry } from "../src/admin/identity.ts";
import { connKey } from "../src/admin/oidc-store-kv.ts";
import { roleSubjectKey } from "../src/admin/identity.ts";
import { changeContentHash } from "../src/admin/change-control.ts";
import { buildContext, OWNER, OPERATOR, OPERATOR2 } from "./validate-config-change-control-harness.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function run(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  const { call, sched, setGate, dp } = ctx;
  const store = sched.storage;

  // The proposer's BOUND role row, found by scanning `role:sub:` for the email rather than reconstructing the
  // subject string, so this fixture does not depend on how an Access subject is spelled.
  const roleKeyOf = (email: string): string => {
    for (const k of store.keysWithPrefix(ROLE_SUBJECT_PREFIX)) {
      if (store.rawGet<RoleEntry>(k)?.email === email) return k;
    }
    return "";
  };
  // lapse() is THE CLOCK PASSING, not an edit. A time-boxed grant is created with expiresAt through the
  // ordinary route; what makes it lapse is time, and no code runs and no config is written at the moment it
  // does. Writing a past expiresAt straight onto the stored row reproduces exactly the state the DO would
  // read one second after a real grant expired, and (the load-bearing part) it writes NO config version, so
  // the queued change's base is untouched and the approve reaches the authority re-resolution.
  const lapse = (email: string, expired: boolean): void => {
    const key = roleKeyOf(email);
    const row = store.rawGet<RoleEntry>(key)!;
    if (expired) store.rawPut(key, { ...row, expiresAt: new Date(Date.now() - 60_000).toISOString() });
    else {
      const { expiresAt: _drop, ...rest } = row;
      store.rawPut(key, rest);
    }
  };
  const headId = async (): Promise<number> => (await ctx.configHistory()).headId;
  const pipes = async (): Promise<DownpipeState[]> => ctx.listDownpipes();
  const has = async (id: string): Promise<boolean> => (await pipes()).some((d) => d.config.id === id);
  const modeOf = async (id: string): Promise<string | undefined> =>
    (await pipes()).find((d) => d.config.id === id)?.config.source.cfConfigMode;
  const idOf = async (r: Response): Promise<string> => (r.status === 202 ? ((await r.json()) as { id: string }).id : "");
  const status = (id: string): string | undefined => store.rawGet<PendingConfigChange>(changeKey(id))?.status;

  try {
    // ---- SEED, gate OFF, so the fixtures the delete and the mode-set act on already exist.
    ok("S1: seed, a downpipe to delete is created inline", (await call(OWNER, "POST", "/admin/downpipes", dp("dpdel", "delete me"))).status === 200);
    ok("S2: seed, a downpipe to re-mode is created inline", (await call(OWNER, "POST", "/admin/downpipes", dp("dpmode", "mode me"))).status === 200);
    ok("S3: seed, a second downpipe to delete is created inline", (await call(OWNER, "POST", "/admin/downpipes", dp("dpdel2", "delete me too"))).status === 200);
    ok("A0: the dual-control gate arms", (await setGate(OWNER, true)).status === 200);

    // =========================================================================================
    // SECTION A: THE FALSE-POSITIVE DIRECTION FIRST, all three kinds, a proposer whose grant is
    // intact. A fix that refused every replay would satisfy every refusal below, so these run
    // first and each one is a real applied effect rather than a status.
    // =========================================================================================
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes", dp("dpctl", "control upsert")));
      ok("A1: a live proposer queues a downpipe-upsert (202)", q.length > 0);
      ok("A2: a distinct approver applies it (200)", (await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`)).status === 200);
      ok("A3: and the downpipe really exists", await has("dpctl"));
    }
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes/delete", { id: "dpdel2" }));
      ok("A4: a live proposer queues a downpipe-delete (202)", q.length > 0);
      ok("A5: a distinct approver applies it (200)", (await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`)).status === 200);
      ok("A6: and the downpipe is really gone", !(await has("dpdel2")));
    }
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes/cf-config/mode", { id: "dpmode", mode: "manual" }));
      ok("A7: a live proposer queues a cf-config-mode-set (202)", q.length > 0);
      ok("A8: a distinct approver applies it (200)", (await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`)).status === 200);
      ok("A9: and the mode really changed to manual", (await modeOf("dpmode")) === "manual");
    }

    // =========================================================================================
    // SECTION B: downpipe-upsert, proposer's grant LAPSED BY EXPIRY.
    // =========================================================================================
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes", dp("dpattack", "attack upsert")));
      ok("B1: the proposer queues a downpipe-upsert while still authorised (202)", q.length > 0);
      const before = await headId();
      lapse(OPERATOR, true);
      // THE PREMISE, ASSERTED RATHER THAN ASSUMED, in both directions it can be wrong.
      ok("B2: the config head did NOT move across the lapse, so the approve reaches the authority re-resolution", (await headId()) === before);
      ok("B3: and the lapse is REAL, because the same proposer's own LIVE upsert is now refused", (await call(OPERATOR, "POST", "/admin/downpipes", dp("dplive", "live probe"))).status === 403);
      const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`);
      ok("B4: approving a lapsed proposer's queued downpipe-upsert is REFUSED", approve.status >= 400);
      ok("B5: and the downpipe was NOT created", !(await has("dpattack")));
      // A superseded record would also refuse and also leave nothing applied, so without this B4 could be
      // satisfied by the base-moved guard instead of the authority axis this file is about.
      ok("B6: and the record is still PENDING, not superseded, so the refusal is the AUTHORITY axis", status(q) === "pending");
      lapse(OPERATOR, false);
      // IT SUSPENDS RATHER THAN VOIDS. Restore the grant and the SAME queued change spends, with no fresh
      // ceremony: that is the property that made binding the right answer rather than a shorter TTL, and a
      // fix implemented as "refuse a replay whose proposer ever lapsed" would go red right here.
      ok("B7: with the grant restored the SAME change applies, so the refusal suspended rather than voided", (await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`)).status === 200);
      ok("B8: and the downpipe now exists", await has("dpattack"));
    }

    // =========================================================================================
    // SECTION C: downpipe-delete, proposer's grant LAPSED BY EXPIRY. A separate kind because it
    // dispatches to a method that takes NO CALLER at all, and because its capability is
    // downpipe.delete rather than downpipe.write.
    // =========================================================================================
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes/delete", { id: "dpdel" }));
      ok("C1: the proposer queues a downpipe-delete while still authorised (202)", q.length > 0);
      const before = await headId();
      lapse(OPERATOR, true);
      ok("C2: the config head did NOT move across the lapse", (await headId()) === before);
      const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`);
      ok("C3: approving a lapsed proposer's queued downpipe-delete is REFUSED", approve.status >= 400);
      ok("C4: and the downpipe SURVIVES", await has("dpdel"));
      ok("C5: and the record is still PENDING, not superseded", status(q) === "pending");
      lapse(OPERATOR, false);
    }

    // =========================================================================================
    // SECTION D: cf-config-mode-set, proposer's grant LAPSED BY EXPIRY. The kind whose own comment
    // asserts the security property that is missing.
    // =========================================================================================
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes/cf-config/mode", { id: "dpmode", mode: "auto" }));
      ok("D1: the proposer queues a cf-config-mode-set while still authorised (202)", q.length > 0);
      const before = await headId();
      lapse(OPERATOR, true);
      ok("D2: the config head did NOT move across the lapse", (await headId()) === before);
      const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`);
      ok("D3: approving a lapsed proposer's queued cf-config-mode-set is REFUSED", approve.status >= 400);
      ok("D4: and the capture mode is UNCHANGED", (await modeOf("dpmode")) === "manual");
      ok("D5: and the record is still PENDING, not superseded", status(q) === "pending");
      lapse(OPERATOR, false);
    }

    // =========================================================================================
    // SECTION E: THE SECOND REACHABLE ROUTE: the connection-liveness axis computing an answer nothing
    // read for this kind, driven against the kind that notify-channel-set's own proof had to avoid.
    // =========================================================================================
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes", dp("dpconn", "dead connection upsert")));
      ok("E1: a change queues for re-addressing to a native-IdP proposer (202)", q.length > 0);
      // Re-address the record to a native-IdP identity AND RECOMPUTE its contentHash over the new binding,
      // which is what makes this a fixture rather than a tamper: the record that results is exactly the
      // record the DO would have written had that person proposed. The harness's forged Access assertions
      // can only mint Access-shaped subjects, so there is no other way to reach this identity shape.
      const subject = `oidc:atc-conn|https://idp.example|atcprop`;
      const email = "atcprop@acme.example";
      store.rawPut(connKey("atc-conn"), { id: "atc-conn", kind: "oidc", enabled: true, name: "atc-conn" });
      store.rawPut(roleSubjectKey(subject), { subject, email, role: "operator", grantedBy: "seed", grantedAt: new Date().toISOString() });
      const rec = store.rawGet<PendingConfigChange>(changeKey(q))!;
      store.rawPut(changeKey(q), {
        ...rec,
        proposedBy: email,
        proposedBySubject: subject,
        proposedByGroups: [],
        contentHash: await changeContentHash(rec.kind, rec.params, email, subject, [], rec.baseVersionId, rec.baseVersionHash),
      });
      const before = await headId();
      await store.delete(connKey("atc-conn"));
      ok("E2: deleting the IdP connection moved NO config head, which is why this route is reachable", (await headId()) === before);
      ok("E3: the proposer's role row is UNTOUCHED, so E4 is about the connection and not the grant", store.rawGet(roleSubjectKey(subject)) !== undefined);
      ok("E4: approving is REFUSED once the proposer's IdP connection is deleted", (await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`)).status >= 400);
      ok("E5: and the downpipe was NOT created", !(await has("dpconn")));
      ok("E6: and the record is still PENDING, not superseded", status(q) === "pending");
    }

    // =========================================================================================
    // SECTION F: THE ROUTE THAT LOOKS LIKE THE ATTACK AND IS NOT, written down so the next reader
    // does not re-derive it, and because an existing proof of these teeth rests on it. Demoting or
    // offboarding the proposer is ITSELF a config mutation: it auto-snapshots, the head moves, and
    // approveChange's base-moved check fires BEFORE the authority re-resolution ever runs. So a
    // demotion-driven proof of the apply-time ceiling is carried by a guard on an ENTIRELY
    // DIFFERENT AXIS, and would stay green if the ceiling re-check were deleted outright.
    // =========================================================================================
    {
      const q = await idOf(await call(OPERATOR, "POST", "/admin/downpipes", dp("dpdemote", "demotion route")));
      ok("F1: a change queues (202)", q.length > 0);
      await setGate(OWNER, false);
      ok("F2: the proposer is demoted to viewer inline (200)", (await call(OWNER, "POST", "/admin/roles", { email: OPERATOR, role: "viewer" })).status === 200);
      await setGate(OWNER, true);
      ok("F3: approving is refused", (await call(OPERATOR2, "POST", `/admin/config/changes/${q}/approve`)).status >= 400);
      ok("F4: and the downpipe was NOT created", !(await has("dpdemote")));
      // THE DISCRIMINATOR. This is SUPERSEDED, not pending: the demotion moved the config head, so the
      // refusal is base-moved and says nothing at all about the proposer's authority.
      ok("F5: but the record is SUPERSEDED, so the demotion route is closed by the base-moved guard and not by any authority check", status(q) === "superseded");
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
