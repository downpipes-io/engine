// PROOF 14(channel)/15/16/17/18/19 of the config change-control validator: the alert-destination gate (the
// BLOCKER) + host-only redaction in history, the expiry-tracker gate, actor-identity tamper caught at
// apply (F4), the dry-run leaves no side effect across the FULL keyspace + the alarm (F5), and a
// custom-role proposer's queued notify change applying on approval without widening authority. Split
// out for size; byte-identical, runs in order against the shared live DO.

import type { Ctx } from "./validate-config-change-control-harness.ts";
import { OWNER, OPERATOR, OPERATOR2 } from "./validate-config-change-control-harness.ts";
import { type PendingConfigChange, changeContentHash } from "../src/admin/change-control.ts";

export async function runPolicies(ctx: Ctx): Promise<void> {
  const { ok, call, listDownpipes, pendingChanges, pendingKeyCount, setGate, sched, listChannels, listExpiry, configHistory, configDiff, dp } = ctx;

  // ===========================================================================================
  // PROOF 14: THE ALERT DESTINATION is gated (the BLOCKER). Gate ON queues a notify-channel set + a
  // delete; gate OFF applies inline. A lone operator CANNOT redirect where alerts go with the gate on.
  // ===========================================================================================
  {
    // Gate is ON here (PROOF 2/10 left it on). A channel SET queues rather than applying: the destination
    // the engine delivers failure/stale alerts to cannot be changed by a lone operator under the gate.
    const before = pendingKeyCount();
    const setQ = await call(OPERATOR, "POST", "/admin/notify/channels", { kind: "webhook", name: "sre-sink", url: "https://sre.acme.example/hook" });
    ok("a gate-on channel set returns 202 (queued, not applied)", setQ.status === 202);
    const setId = ((await setQ.json()) as { id: string }).id;
    ok("the queued channel set created a pending record", pendingKeyCount() === before + 1);
    // The destination did NOT change: no channel is configured yet (the lone operator could not add it).
    ok("the queued channel set did NOT add the destination", !(await listChannels()).some((c) => c.name === "sre-sink"));
    const rec = (await pendingChanges(OWNER)).find((c) => c.id === setId);
    ok("the queued channel change is in the inbox as notify-channel-set", rec?.kind === "notify-channel-set");
    ok("the queued channel change records the operator as maker", rec?.proposedBy === OPERATOR);
    // The self-approve is refused (maker != checker): a lone operator cannot push their own redirect through.
    const selfApprove = await call(OPERATOR, "POST", `/admin/config/changes/${setId}/approve`);
    ok("the operator cannot approve their OWN destination change (maker != checker)", selfApprove.status >= 400);
    ok("the lone-operator self-approve left the destination unchanged", !(await listChannels()).some((c) => c.name === "sre-sink"));
    // A DISTINCT notify.config holder (operator2) approves -> the channel applies via the real addNotifyChannel.
    const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${setId}/approve`);
    ok("a distinct notify.config holder approves the channel set (200)", approve.status === 200);
    const applied = (await listChannels()).find((c) => c.name === "sre-sink");
    ok("the approved channel set APPLIED (the destination is now configured)", applied !== undefined);

    // A channel DELETE is also gated: queue + approve.
    const delQ = await call(OPERATOR, "POST", "/admin/notify/channels/delete", { id: applied?.id });
    ok("a gate-on channel delete returns 202 (queued)", delQ.status === 202);
    const delId = ((await delQ.json()) as { id: string }).id;
    ok("the queued delete did NOT remove the channel yet", (await listChannels()).some((c) => c.name === "sre-sink"));
    const delRec = (await pendingChanges(OWNER)).find((c) => c.id === delId);
    ok("the queued channel delete is notify-channel-delete", delRec?.kind === "notify-channel-delete");
    const delApprove = await call(OPERATOR2, "POST", `/admin/config/changes/${delId}/approve`);
    ok("a distinct approver applies the channel delete (200)", delApprove.status === 200);
    ok("the approved delete removed the alert destination", !(await listChannels()).some((c) => c.name === "sre-sink"));

    // GATE OFF: a channel set applies INLINE (no pending), byte-identical to the pre-gate path.
    await setGate(OWNER, false);
    const beforeOff = pendingKeyCount();
    const inline = await call(OPERATOR, "POST", "/admin/notify/channels", { kind: "webhook", name: "sre-sink-2", url: "https://sre2.acme.example/hook" });
    ok("a gate-off channel set returns 200 (applied inline, not 202)", inline.status === 200);
    const inlineId = ((await inline.json()) as { id: string }).id;
    ok("the gate-off channel set added the destination inline", (await listChannels()).some((c) => c.name === "sre-sink-2"));
    ok("the gate-off channel set queued NOTHING", pendingKeyCount() === beforeOff);
    // Clean up + restore the gate ON for the following proofs.
    await call(OPERATOR, "POST", "/admin/notify/channels/delete", { id: inlineId });
    await setGate(OWNER, true);
  }

  // ===========================================================================================
  // PROOF 15: an alert DESTINATION appears in config history + the diff after it is written, with the
  // secret part REDACTED (host only, never a path token / the full url).
  //
  // The legacy single-webhook policy this proof used to drive is gone; the property it guards
  // is NOT. A notify channel's url is the same class of value the legacy policy's url was: a bearer
  // credential whose token usually rides in the PATH (a Slack/Teams/generic-webhook ingest token), and
  // config-snapshot.ts redacts it through the SAME webhookHost() helper to urlHost + urlConfigured. So
  // the proof is re-pointed at the surviving write route, POST /admin/notify/channels, which is now the
  // only way a url of that class enters the version chain.
  // ===========================================================================================
  {
    // Set the gate OFF, capture a clean baseline head, then add a channel whose URL embeds a SECRET in the
    // path. The gate-off mutation AUTO-SNAPSHOTS (so the channel change is versioned automatically); diff
    // the baseline head against the new head: the version must name the destination HOST but NEVER the path secret.
    await setGate(OWNER, false);
    await call(OWNER, "POST", "/admin/config/snapshot"); // ensure a stable baseline head exists
    const baseId = (await configHistory()).headId;
    const secretUrl = "https://hooks.slack.example/services/T000/B000/" + "S3CR3T-tok3n-do-not-log";
    const setInline = await call(OPERATOR, "POST", "/admin/notify/channels", { kind: "webhook", name: "redaction-probe", url: secretUrl });
    ok("the channel with a path-secret url was added inline (gate off)", setInline.status === 200);
    const probeId = ((await setInline.json()) as { id: string }).id;
    const headId = (await configHistory()).headId;
    ok("the channel change auto-snapshotted a new config-history version", headId > baseId);
    const diff = await configDiff(baseId, headId);
    const channelLine = (diff.changes ?? []).find((c) => c.area === "notify-channel");
    ok("the config diff carries a notify-channel line", channelLine !== undefined);
    // The SECRET (the path token) must NEVER appear anywhere in the version chain (diff OR the stored version).
    const versionResp = await call(OWNER, "GET", `/admin/config/version?id=${headId}`);
    const versionText = await versionResp.text();
    const diffText = JSON.stringify(diff);
    ok("the stored config version names the destination HOST", /hooks\.slack\.example/.test(versionText));
    ok("the path SECRET does not appear in the diff", !/S3CR3T-tok3n-do-not-log/.test(diffText));
    ok("the path SECRET does not appear in the stored config version", !/S3CR3T-tok3n-do-not-log/.test(versionText));
    ok("the full url path does not appear in the stored version (host-only redaction)", !/services\/T000/.test(versionText));
    // Clean up + restore the gate.
    await call(OPERATOR, "POST", "/admin/notify/channels/delete", { id: probeId });
    await setGate(OWNER, true);
  }

  // ===========================================================================================
  // PROOF 16: the EXPIRY tracker is gated (HIGH). Gate ON queues an expiry set + delete; an approved
  // expiry change produces a coherent config-history diff.
  // ===========================================================================================
  {
    // Gate ON. An expiry SET queues rather than applying inline.
    const before = pendingKeyCount();
    const expItem = { id: "key-rotation-2026", label: "S3 destination access key", kind: "key", expiresAt: "2026-12-31T00:00:00.000Z", source: "manual" };
    const setQ = await call(OPERATOR, "POST", "/admin/expiry", expItem);
    ok("a gate-on expiry set returns 202 (queued)", setQ.status === 202);
    const setId = ((await setQ.json()) as { id: string }).id;
    const rec = (await pendingChanges(OWNER)).find((c) => c.id === setId);
    ok("the queued expiry change is expiry-item-set", rec?.kind === "expiry-item-set");
    ok("the queued expiry change carries an expiry diff line", (rec?.diff ?? []).some((c) => c.area === "expiry" && /key-rotation-2026|S3 destination access key/.test(c.text)));
    ok("the queued expiry set did NOT add the item yet", !(await listExpiry()).some((e) => e.id === "key-rotation-2026"));
    // Approve via a distinct expiry.config holder -> the item applies and snapshots a coherent diff.
    const histBefore = await configHistory();
    const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${setId}/approve`);
    ok("a distinct expiry.config holder approves the expiry set (200)", approve.status === 200);
    ok("the approved expiry item now exists", (await listExpiry()).some((e) => e.id === "key-rotation-2026"));
    const histAfter = await configHistory();
    ok("the approved expiry change snapshotted a new config version", histAfter.versions.length === histBefore.versions.length + 1);
    // Diff the prior head (before the approve) against the new head: the expiry add must be a coherent line.
    const diff = await configDiff(histBefore.headId, histAfter.headId);
    ok("the expiry change produced a coherent config diff (expiry area)", (diff.changes ?? []).some((c) => c.area === "expiry" && /key-rotation-2026|S3 destination access key/.test(c.text)));

    // An expiry DELETE is also gated: queue + approve.
    const delQ = await call(OPERATOR, "POST", "/admin/expiry/delete", { id: "key-rotation-2026" });
    ok("a gate-on expiry delete returns 202 (queued)", delQ.status === 202);
    const delId = ((await delQ.json()) as { id: string }).id;
    ok("the queued expiry delete is expiry-item-delete", (await pendingChanges(OWNER)).find((c) => c.id === delId)?.kind === "expiry-item-delete");
    ok("the queued delete did NOT remove the item yet", (await listExpiry()).some((e) => e.id === "key-rotation-2026"));
    const delApprove = await call(OPERATOR2, "POST", `/admin/config/changes/${delId}/approve`);
    ok("a distinct approver applies the expiry delete (200)", delApprove.status === 200);
    ok("the approved delete removed the expiry item", !(await listExpiry()).some((e) => e.id === "key-rotation-2026"));
  }

  // ===========================================================================================
  // PROOF 17: ACTOR-IDENTITY TAMPER is caught at apply. A stored record whose proposedBy or
  // proposedByGroups is tampered (so the contentHash no longer recomputes) is refused at approve.
  // ===========================================================================================
  {
    // proposedBy tamper: queue a downpipe upsert, then rewrite proposedBy to a more-privileged identity
    // WITHOUT updating the (now stale) contentHash. The approve recompute over the tampered identity fails.
    const q1 = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_id_tamper", "id-tamper"));
    const id1 = ((await q1.json()) as { id: string }).id;
    const rec1 = sched.storage.rawGet<PendingConfigChange>("configchange:" + id1)!;
    rec1.proposedBy = OWNER; // borrow a more privileged proposer, leave contentHash stale
    sched.storage.rawPut("configchange:" + id1, rec1);
    const approve1 = await call(OPERATOR2, "POST", `/admin/config/changes/${id1}/approve`);
    ok("a proposedBy-tampered change is refused at approve (4xx, integrity)", approve1.status >= 400);
    ok("the proposedBy-tampered refusal is the integrity check", /integrity check/.test(((await approve1.json()) as { error?: string }).error ?? ""));
    ok("the proposedBy-tampered change applied nothing", !(await listDownpipes()).some((d) => d.config.id === "dp_id_tamper"));
    await sched.storage.delete("configchange:" + id1);

    // proposedByGroups tamper: same, mutating the groups the apply re-resolves authority from.
    const q2 = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_grp_tamper", "grp-tamper"));
    const id2 = ((await q2.json()) as { id: string }).id;
    const rec2 = sched.storage.rawGet<PendingConfigChange>("configchange:" + id2)!;
    rec2.proposedByGroups = ["smuggled-admin-group"]; // mutate the authority input, leave contentHash stale
    sched.storage.rawPut("configchange:" + id2, rec2);
    const approve2 = await call(OPERATOR2, "POST", `/admin/config/changes/${id2}/approve`);
    ok("a proposedByGroups-tampered change is refused at approve (4xx, integrity)", approve2.status >= 400);
    ok("the proposedByGroups-tampered change applied nothing", !(await listDownpipes()).some((d) => d.config.id === "dp_grp_tamper"));
    await sched.storage.delete("configchange:" + id2);

    // Positive control: the hash binds exactly those fields, so recomputing over the UNTAMPERED record
    // matches its stored contentHash (the binding is reproducible from the stored record alone).
    const q3 = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_id_ok", "id-ok"));
    const id3 = ((await q3.json()) as { id: string }).id;
    const rec3 = sched.storage.rawGet<PendingConfigChange>("configchange:" + id3)!;
    const recomputed = await changeContentHash(rec3.kind, rec3.params, rec3.proposedBy, rec3.proposedBySubject, rec3.proposedByGroups, rec3.baseVersionId, rec3.baseVersionHash);
    ok("the contentHash recomputes from the stored record (identity folded into the binding)", recomputed === rec3.contentHash);
    await call(OPERATOR2, "POST", `/admin/config/changes/${id3}/reject`);
  }

  // ===========================================================================================
  // PROOF 18: a DRY-RUN PROPOSAL leaves NO side effect at all - the FULL keyspace AND the alarm are
  // unchanged (assert exhaustively, not just the one downpipe, including the alarm rollback).
  // ===========================================================================================
  {
    // Seed a real alarm first (gate off, add a downpipe inline so rearmAlarm sets the alarm), then with
    // the gate ON, PROPOSE a downpipe upsert (which would re-arm the alarm) and assert the dry-run rolled
    // BOTH the keyspace and the alarm back. Snapshot the entire keyspace + the alarm before proposing.
    await setGate(OWNER, false);
    await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_alarm_seed", "alarm-seed", 7200));
    await setGate(OWNER, true);
    const keysBefore = sched.storage.snapshotKeyspace();
    const alarmBefore = sched.storage.rawAlarm();
    // Propose a NEW downpipe with a SOONER cadence (so a real apply would re-arm the alarm earlier).
    const propose = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_dryrun_probe", "dryrun-probe", 60));
    ok("the dry-run proposal queued (202)", propose.status === 202);
    const probeId = ((await propose.json()) as { id: string }).id;
    const keysAfter = sched.storage.snapshotKeyspace();
    const alarmAfter = sched.storage.rawAlarm();
    // EXHAUSTIVE keyspace comparison. The dry-run rolls its OWN config mutation back entirely. The propose
    // request then LEGITIMATELY does request-level bookkeeping that is NOT a config write and NOT dry-run
    // residue: it stores the pending configchange:<id> record, appends ONE audit:<seq> entry (advancing the
    // auditSeq counter and the O(1) auditHead pointer that locates the chain head), and the router advances
    // this caller's ratelimit: window. Everything ELSE - and in particular EVERY config-ish key, the probe's
    // own dp:/hist: keys, and the alarm - must be exactly as before. We permit only those bookkeeping shapes
    // and assert nothing else moved.
    // The audit append itself folds a DIAGNOSTIC counter when it records a human actor with no
    // captured source IP (diag:admincounters, the pack's bounded {closed name -> count, lastAt} aggregate). That
    // is bookkeeping of exactly the same class as the audit entry that caused it -- a count, never a config
    // value, never a key an operator set -- so it belongs in this allowlist and NOT in the config-mutation set
    // this assertion protects. The invariant the test exists for is unchanged and is asserted below: no
    // config-ish key (dp:/role:/notify-/expiry:/policy:/confighist:) may move on a dry run.
    const pendingKey = "configchange:" + probeId;
    // authmethodusage is the auth-method usage diagnostic counter, written OUT OF BAND on a best-effort
    // serialised chain (scheduler-do-idp.ts recordAuthMethodUseSerial), so a pending async bump from an earlier
    // request can flush between these two synchronous snapshots. It is request-level bookkeeping of exactly the
    // same class as auditSeq / ratelimit: / diag:admincounters (a count, never a config value), so it belongs in
    // this allowlist; the invariant the test protects (no config-ish key moved on a dry run) is unaffected.
    const isBookkeepingKey = (k: string): boolean =>
      k === pendingKey || k === "auditSeq" || k === "auditHead" || k.startsWith("audit:") || k.startsWith("ratelimit:") || k === "diag:admincounters" || k === "authmethodusage";
    const newKeys = [...keysAfter.keys()].filter((k) => !keysBefore.has(k));
    ok("the dry-run left NO stray new key (only the pending record + audit/ratelimit bookkeeping)", newKeys.every(isBookkeepingKey) && newKeys.includes(pendingKey));
    ok("the dry-run's probe downpipe key was rolled back (no dp:/hist: probe key survives)", !keysAfter.has("dp:dp_dryrun_probe") && !keysAfter.has("hist:dp_dryrun_probe"));
    // Every pre-existing key is byte-identical EXCEPT the request-level bookkeeping (auditSeq + the caller's
    // ratelimit window); NO config-ish key (dp:/role:/notify-/expiry:/policy:/confighist: ...) may change.
    const changedPreExisting = [...keysBefore.keys()].filter((k) => keysAfter.get(k) !== keysBefore.get(k));
    ok("no pre-existing key changed except audit/ratelimit bookkeeping (no config key moved)", changedPreExisting.every(isBookkeepingKey));
    ok("no pre-existing key was deleted by the proposal", [...keysBefore.keys()].every((k) => keysAfter.has(k)));
    ok("the probe downpipe does NOT exist (the dry-run rolled the upsert back)", !(await listDownpipes()).some((d) => d.config.id === "dp_dryrun_probe"));
    // THE ALARM: a downpipe upsert re-arms it; the dry-run must have restored it to its pre-proposal value.
    ok("the DO alarm is unchanged after the proposal (alarm rollback)", alarmAfter === alarmBefore);
    // Clean up: reject the probe + remove the seed (gate off for the immediate delete).
    await call(OPERATOR2, "POST", `/admin/config/changes/${probeId}/reject`);
    await setGate(OWNER, false);
    await call(OPERATOR, "POST", "/admin/downpipes/delete", { id: "dp_alarm_seed" });
    await setGate(OWNER, true);
  }

  // ===========================================================================================
  // PROOF 19: a CUSTOM-ROLE proposer holding notify.config has a QUEUED notify change APPLY on approval.
  // The replay forwards the proposer's live-resolved capability set, so a legitimate custom-role
  // proposer is NOT refused at apply on their viewer floor - WITHOUT widening authority.
  // ===========================================================================================
  {
    // Define a custom role that bundles notify.config (+ downpipe.read so it can view the inbox), grant it
    // to a fresh email, and have that custom-role caller propose a notify channel under the gate. The
    // approve replays AS the custom-role proposer: a by-role notify.config re-check would previously refuse
    // them on their viewer floor; with the resolved set forwarded, it applies.
    await setGate(OWNER, false);
    const NOTIFIER = "notifier@acme.example";
    const mk = await call(OWNER, "POST", "/admin/custom-roles", {
      name: "notify-manager",
      label: "Notify Manager",
      capabilities: ["downpipe.read", "notify.config"],
      landing: "notify",
    });
    ok("a custom role bundling notify.config is created", mk.status === 200);
    await call(OWNER, "POST", "/admin/roles", { email: NOTIFIER, role: "viewer", customRole: "notify-manager" });
    // Confirm the custom-role caller resolves to the capability set (not a built-in role).
    const who = (await (await call(NOTIFIER, "GET", "/admin/whoami")).json()) as { capabilities?: string[]; role: string };
    ok("the custom-role proposer resolves to notify.config (capability set, viewer floor)", (who.capabilities ?? []).includes("notify.config") && who.role === "viewer");
    await setGate(OWNER, true);
    // The custom-role proposer queues a notify channel under the gate.
    const q = await call(NOTIFIER, "POST", "/admin/notify/channels", { kind: "webhook", name: "custom-sink", url: "https://custom.acme.example/hook" });
    ok("the custom-role proposer can QUEUE a notify change under the gate (202)", q.status === 202);
    const chId = ((await q.json()) as { id: string }).id;
    const rec = (await pendingChanges(NOTIFIER)).find((c) => c.id === chId);
    ok("the queued notify change records the custom-role proposer as maker", rec?.proposedBy === NOTIFIER);
    // A DISTINCT notify.config holder (operator) approves -> the replay runs AS the custom-role proposer and
    // the notify.config re-check consults their RESOLVED set, so it APPLIES (this is the F6 fix).
    const channelsBefore = ((await (await call(OWNER, "GET", "/admin/notify/channels")).json()) as unknown[]).length;
    const approve = await call(OPERATOR, "POST", `/admin/config/changes/${chId}/approve`);
    ok("the custom-role proposer's queued notify change APPLIES on approval (200)", approve.status === 200);
    ok("the applied record is terminal applied", ((await approve.json()) as PendingConfigChange).status === "applied");
    const channelsAfter = ((await (await call(OWNER, "GET", "/admin/notify/channels")).json()) as unknown[]).length;
    ok("the notify channel the custom-role proposer queued now exists", channelsAfter === channelsBefore + 1);

    // NO WIDENING: a custom role WITHOUT notify.config cannot propose a notify change (refused at propose,
    // its dry-run runs the real notify.config re-check against its resolved set and throws). This proves
    // the forwarded set is the proposer's OWN authority, not a blanket pass.
    const READER = "reader@acme.example";
    await setGate(OWNER, false);
    await call(OWNER, "POST", "/admin/custom-roles", { name: "config-reader", label: "Config Reader", capabilities: ["downpipe.read", "audit.read"], landing: "audit" });
    await call(OWNER, "POST", "/admin/roles", { email: READER, role: "viewer", customRole: "config-reader" });
    await setGate(OWNER, true);
    const refused = await call(READER, "POST", "/admin/notify/channels", { kind: "webhook", name: "nope", url: "https://nope.acme.example/hook" });
    ok("a custom role WITHOUT notify.config cannot propose a notify change (refused, no widening)", refused.status >= 400);
  }
}
