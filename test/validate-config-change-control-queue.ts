// PROOF 3/4/5/5b/6/7 of the config change-control validator: queuing under the gate (202 + diff),
// propose-time validation, maker != checker (router + the subject axis), the missing-write-cap refusal,
// and the clean approve that applies via the real path. Split out for size; every
// assertion is byte-identical and runs in order against the shared live DO. PROOF 3 records the queued
// downpipe id in `shared` so the later approve groups operate on it.

import type { Ctx, Shared } from "./validate-config-change-control-harness.ts";
import { OWNER, OPERATOR, OPERATOR2, VIEWER, ACCESS_ADMIN } from "./validate-config-change-control-harness.ts";
import { type PendingConfigChange, canApproveChange } from "../src/admin/change-control.ts";

export async function runQueue(ctx: Ctx, shared: Shared): Promise<void> {
  const { ok, call, readLog, listDownpipes, pendingChanges, pendingKeyCount, dp } = ctx;

  // ===========================================================================================
  // PROOF 3: GATE ON queues a config mutation (202 + id), does NOT apply, with the CORRECT diff
  // ===========================================================================================
  {
    const before = await listDownpipes();
    const r = await call(OPERATOR, "POST", "/admin/downpipes", dp("dp_queued", "queued-pipe"));
    ok("a gate-on config mutation returns 202 (queued, not applied)", r.status === 202);
    const body = (await r.json()) as { queued: boolean; id: string; status: string; contentHash: string };
    ok("the 202 body carries queued:true + the change id + a content hash", body.queued === true && typeof body.id === "string" && body.id.length > 0 && body.contentHash.startsWith("sha384:"));
    shared.queuedDownpipeId = body.id;
    // The state did NOT change: the downpipe does not exist yet.
    const after = await listDownpipes();
    ok("the queued mutation did NOT change state (the downpipe does not exist yet)", after.length === before.length && !after.some((d) => d.config.id === "dp_queued"));
    // The pending record exists, carrying the correct plain-English diff (a downpipe added).
    const inbox = await pendingChanges(OWNER);
    const rec = inbox.find((c) => c.id === shared.queuedDownpipeId);
    ok("the pending change is in the inbox", rec !== undefined);
    ok("the pending change records the proposer (maker)", rec?.proposedBy === OPERATOR);
    ok("the pending change kind is downpipe-upsert", rec?.kind === "downpipe-upsert");
    ok("the pending change carries the config-history diff (the would-be downpipe add)", (rec?.diff ?? []).some((c) => c.area === "downpipe" && c.kind === "added" && /dp_queued|queued-pipe|kv:/.test(c.text)));
    ok("the pending change is bound to a base version + a content hash", typeof rec?.baseVersionId === "number" && rec?.baseVersionHash.startsWith("sha384:") && rec?.contentHash.startsWith("sha384:"));
    // The record captures the proposer's propose-time groups (empty for this per-email-granted operator),
    // which the apply re-resolves authority against so a group-derived proposer keeps the authority they
    // presented without being able to gain groups.
    ok("the pending change records the proposer's propose-time groups", Array.isArray(rec?.proposedByGroups));
  }

  // ===========================================================================================
  // PROOF 4: PROPOSE-TIME VALIDATION - a bad/unauthorised request is rejected NOW, not deferred
  // ===========================================================================================
  {
    // (a) A VIEWER (no downpipe.write) proposing a downpipe upsert is refused at PROPOSE time (403), and
    // NOTHING is queued (the dry-run runs the real method, which throws on the missing capability).
    const before = pendingKeyCount();
    const viewerTry = await call(VIEWER, "POST", "/admin/downpipes", dp("dp_viewer", "nope"));
    ok("a viewer proposing a downpipe write is refused at propose time (403)", viewerTry.status === 403);
    ok("the refused proposal queued NOTHING (not deferred)", pendingKeyCount() === before);

    // (b) A MALFORMED config (an invalid downpipe: reserved binding / bad shape) is rejected at PROPOSE
    // time as a 400 by the SAME validateConfig the inline path runs, not stored as a pending change.
    const bad = await call(OPERATOR, "POST", "/admin/downpipes", { id: "dp_bad", name: "bad", cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "SCHEDULER", include: [], exclude: [] } });
    ok("a malformed config is rejected at propose time (400)", bad.status === 400);
    ok("the malformed proposal queued nothing", pendingKeyCount() === before);
  }

  // ===========================================================================================
  // PROOF 5: MAKER != CHECKER - the proposer cannot approve their OWN change
  // ===========================================================================================
  {
    // The OPERATOR proposed dp_queued (PROOF 3). The SAME operator tries to approve it -> refused, and the
    // downpipe still does not exist (nothing applied).
    const self = await call(OPERATOR, "POST", `/admin/config/changes/${shared.queuedDownpipeId}/approve`);
    ok("the proposer cannot approve their own change (4xx)", self.status >= 400);
    const sb = (await self.json()) as { error?: string };
    ok("the refusal is the maker != checker rule", /cannot approve your own change/.test(sb.error ?? ""));
    ok("the self-approve attempt applied nothing (the downpipe still does not exist)", !(await listDownpipes()).some((d) => d.config.id === "dp_queued"));
    ok("the change is still pending after the self-approve attempt", (await pendingChanges(OWNER)).some((c) => c.id === shared.queuedDownpipeId && c.status === "pending"));
  }

  // ===========================================================================================
  // PROOF 5b: MAKER != CHECKER on the SUBJECT axis (unit) - a self-approval is refused even when the
  // proposer's DISPLAY EMAIL has since changed, the case the email-only floor would have missed.
  // ===========================================================================================
  {
    const base: PendingConfigChange = {
      id: "unit", kind: "downpipe-upsert", params: {}, diff: [],
      proposedBy: "old-name@acme.example", proposedBySubject: "https://team|sub-of-maker", proposedByGroups: [],
      proposedAt: "2026-06-10T00:00:00.000Z", status: "pending",
      contentHash: "sha384:x", baseVersionId: 0, baseVersionHash: "sha384:y",
    };
    // Same subject, DIFFERENT email (the maker renamed/re-addressed): must still be refused.
    const renamed = canApproveChange(base, "new-name@acme.example", "https://team|sub-of-maker", true);
    ok("subject-axis self-approval refused even across an email change", !renamed.ok && /cannot approve your own change/.test((renamed as { reason: string }).reason));
    // Different subject (a genuinely distinct identity that happens to share a display email): allowed.
    const distinct = canApproveChange(base, "old-name@acme.example2", "https://team|sub-of-checker", true);
    ok("a distinct subject may approve", distinct.ok === true);
    // Email floor still catches a legacy record with a null proposedBySubject (pre-re-key).
    const legacy = { ...base, proposedBySubject: null } as PendingConfigChange;
    const legacySelf = canApproveChange(legacy, "old-name@acme.example", "https://team|sub-of-anyone", true);
    ok("legacy null-subject record still refuses an email self-approval (floor holds)", !legacySelf.ok);
  }

  // ===========================================================================================
  // PROOF 6: MISSING WRITE CAP - an approver WITHOUT the original mutation's write cap cannot approve
  // ===========================================================================================
  {
    // An ACCESS_ADMIN can READ the inbox (downpipe.read) but does NOT hold downpipe.write, so it cannot
    // approve the queued downpipe change. (It is also a distinct identity, so this isolates the cap check.)
    ok("the access-admin can see the pending change (downpipe.read)", (await pendingChanges(ACCESS_ADMIN)).some((c) => c.id === shared.queuedDownpipeId));
    const noCap = await call(ACCESS_ADMIN, "POST", `/admin/config/changes/${shared.queuedDownpipeId}/approve`);
    ok("an approver without the write cap cannot approve (4xx)", noCap.status >= 400);
    const ncb = (await noCap.json()) as { error?: string };
    ok("the refusal names the missing write capability", /downpipe\.write/.test(ncb.error ?? "") || /do not hold/.test(ncb.error ?? ""));
    ok("the missing-cap attempt applied nothing", !(await listDownpipes()).some((d) => d.config.id === "dp_queued"));
  }

  // ===========================================================================================
  // PROOF 7: CLEAN APPROVE applies via the REAL path, records BOTH actors, and snapshots
  // ===========================================================================================
  {
    const histBefore = ((await (await call(OWNER, "GET", "/admin/config/history")).json()) as { versions: Array<{ id: number }> }).versions.length;
    // A DISTINCT operator (holds downpipe.write, != the proposer) approves -> the change APPLIES via the
    // same validated addDownpipe the inline path uses.
    const approve = await call(OPERATOR2, "POST", `/admin/config/changes/${shared.queuedDownpipeId}/approve`);
    ok("a distinct approver with the write cap approves (200)", approve.status === 200);
    const ar = (await approve.json()) as PendingConfigChange;
    ok("the change is now applied", ar.status === "applied");
    ok("the change records the checker (approvedBy)", ar.approvedBy === OPERATOR2);
    ok("maker != checker on the applied record", ar.proposedBy === OPERATOR && ar.approvedBy === OPERATOR2 && ar.proposedBy !== ar.approvedBy);
    // The state changed: the downpipe now exists (applied via the real method).
    ok("the approved change APPLIED via the real path (the downpipe now exists)", (await listDownpipes()).some((d) => d.config.id === "dp_queued"));
    // It auto-snapshotted into config history.
    const histAfter = ((await (await call(OWNER, "GET", "/admin/config/history")).json()) as { versions: Array<{ id: number }> }).versions.length;
    ok("the applied change auto-snapshotted a new config version", histAfter === histBefore + 1);
    // It dropped out of the PENDING inbox (terminal).
    ok("the applied change is no longer pending", !(await pendingChanges(OWNER)).some((c) => c.id === shared.queuedDownpipeId));
    // BOTH actors are audited: a propose event (maker) AND an approve event (checker).
    const proposeEvt = (await readLog("action=config-change-propose")).events.find((e) => (e.target as { id?: string }).id === shared.queuedDownpipeId);
    const approveEvt = (await readLog("action=config-change-approve")).events.find((e) => (e.target as { id?: string }).id === shared.queuedDownpipeId);
    ok("a config-change-propose event attributes the maker", proposeEvt?.actorEmail === OPERATOR);
    ok("a config-change-approve event attributes the checker (actor + approverEmail)", approveEvt?.actorEmail === OPERATOR2 && (approveEvt?.target as { approverEmail?: string }).approverEmail === OPERATOR2);
    ok("maker and checker are distinct across the propose/approve events", proposeEvt?.actorEmail !== approveEvt?.actorEmail);
    // (The downpipe-create native audit event is emitted by the ROUTER on the inline path, not by the DO
    // addDownpipe the replay calls, so the queued downpipe write's attribution to the maker is carried by
    // the config-change-propose event above + the config-history snapshot author below, which is the
    // "both actors audited" guarantee. The DO-method-audited families (role/group/custom/posture) DO
    // additionally emit their native event attributing the proposer on apply; PROOF 10 exercises a role
    // grant through the queue, so that native attribution is covered there.)
    // The config-history snapshot the apply produced records the PROPOSER as its author.
    const headVer = ((await (await call(OWNER, "GET", "/admin/config/history")).json()) as { versions: Array<{ author: string | null; summary: string }> }).versions[0];
    ok("the applied change's config-history version records the proposer as author", headVer?.author === OPERATOR);
  }
}
