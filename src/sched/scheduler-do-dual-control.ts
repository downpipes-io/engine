// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the OPT-IN dual-control for the
// HIGH-BLAST-RADIUS OWNER OPERATIONS (same requireConfigApproval toggle, default OFF). Gate OFF (default):
// gatedOwnerAction runs the action INLINE, byte-identically to before. Gate ON: it records a PENDING
// OWNER-ACTION APPROVAL bound to an actionHash over the decision params + the proposer identity, and a SECOND
// owner must approve (maker != checker on the stable subject axis) before the SAME method runs with the
// proposer's authority re-resolved LIVE (owner-action.ts is the pure logic; this DO is the single storage
// authority). Split out of the former dual-control god file alongside the shared org-policy gate state
// (OrgPolicyMixin) and the scheduling core (SchedulerCoreMixin), both reached through `this` over a
// SchedulerDOSurface base. Move-only: the maker!=checker rule, the actionHash binding, the OWNER_ACTION_* keys,
// every storage key, route, status, response and auth gate are unchanged (madge 0 cycles).

import type { ChangeRef } from "../admin/change-ref.ts";
import type { AuthMethod, Role } from "../admin/identity.ts";
import { canApproveOwnerAction, canRejectOwnerAction, canRequesterSeeOwnerAction, isArmedOwnerAction, isChangeControlledOwnerAction, isOwnerActionKind, isRouterExecutedOwnerAction, OWNER_ACTION_PREFIX, OWNER_ACTION_TTL_MS, type OwnerActionKind, ownerActionHash, ownerActionKey, ownerActionParamsScrubbed, ownerActionParamsSpent, ownerActionTimestampUnparseable, type PendingOwnerAction, scrubOwnerActionParams, viewOwnerAction } from "../admin/owner-action.ts";
import { classifyGovernanceOutcome, recordGovernanceFault, recordGovernanceRefusal } from "./sched-fault-ledger.ts";
import { AuthError, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { newULID, nowMillisISO } from "./scheduler-helpers.ts";

export function DualControlMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    async gatedOwnerAction<T>(
      kind: OwnerActionKind,
      params: unknown,
      summary: string,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null; change?: ChangeRef | null } | null,
      execute: (authority: { method: AuthMethod; email: string | null; subject: string | null; groups: string[] } | null) => Promise<T>,
    ): Promise<T | { ownerActionQueued: true; id: string; actionHash: string; status: "pending" }> {
      // CHANGE MANAGEMENT (OWNER OPT-IN, default OFF, independent of dual control): when requireChangeNumber is
      // ON, a change-controlled owner op must carry a valid change reference, which enforceChangeControl
      // validates and records (change-recorded) BEFORE anything runs; an invalid/absent reference THROWS (->
      // 400) so the action does not run. It runs FIRST (before the gate branch below) so the CR is raised the
      // moment the action is initiated, whether it then runs inline or is queued for a second owner. It is a
      // no-op when the policy is OFF (byte-identical to before). dual-control-disable (the OFF switch) is
      // excluded by isChangeControlledOwnerAction so disarming can never be blocked on a change number.
      if (isChangeControlledOwnerAction(kind)) await this.enforceChangeControl(kind, caller);
      // The gate is ON when the opt-in toggle is ON OR this is a high-blast data/sign-in op with a second owner
      // (effectiveOwnerActionGateOn). With one owner a high-blast op stays inline (no deadlock); the step-up is
      // the sole control there. The bare-token break-glass is exempt from the high-blast auto-apply (its method
      // is forwarded so the gate can apply that exemption), so the first-Owner bootstrap can wire the first IdP.
      const gateOn = await this.effectiveOwnerActionGateOn(kind, caller ? caller.method : null);
      if (!gateOn) {
        // Gate OFF: run inline, byte-identical to the prior path.
        return execute(caller);
      }
      // Gate ON: record a pending owner action. recordOwnerAction enforces the attributable-maker rule and
      // returns the stored record; the DO route turns the sentinel into a 202.
      const record = await this.recordOwnerAction(kind, params, summary, caller);
      return { ownerActionQueued: true, id: record.id, actionHash: record.actionHash, status: "pending" };
    }

    // recordOwnerAction persists a PENDING owner action (the shared body of the DO-executed gate and the
    // router-executed propose route). It refuses a bare-token (emailless) proposer (dual control needs an
    // attributable maker), computes the actionHash over the kind + params + router-executed flag + the
    // proposer identity, stores the record with a 24h TTL, and audits the propose with the proposer as actor.
    // It NEVER runs the action; it only records the intent. routerExecuted is DERIVED from the kind, so the
    // consume path knows the flow without re-deriving and the flag is part of the integrity binding.
    async recordOwnerAction(
      kind: OwnerActionKind,
      params: unknown,
      summary: string,
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<PendingOwnerAction> {
      // Dual control needs an attributable maker: the bare-token break-glass has no email, so it cannot PROPOSE
      // (it could otherwise queue an action only it could not then approve). Refuse here, matching the
      // config-change / restore-request rule. (The break-glass owner can still toggle the gate OFF immediately.)
      const proposedBy = caller?.email ? caller.email : null;
      if (proposedBy === null) {
        throw new Error("dual control requires an attributable identity; the bare-token fallback cannot propose an owner action");
      }
      const proposedBySubject = caller ? caller.subject : null;
      const proposedByGroups = caller ? caller.groups : [];
      const routerExecuted = isRouterExecutedOwnerAction(kind);
      const actionHash = await ownerActionHash(kind, params, routerExecuted, proposedBy, proposedBySubject, proposedByGroups);
      const now = Date.now();
      const id = newULID(now);
      const record: PendingOwnerAction = {
        id,
        kind,
        params,
        routerExecuted,
        proposedBy,
        proposedBySubject,
        proposedByGroups,
        // The edge address the PROPOSE arrived from (G346). The approve-time execute replays this action as the
        // proposer and audits it as an attributed human; with no IP on that caller the row landed with sourceIp
        // null and the engine counted its own governed replay as a capture fault.
        proposedBySourceIp: caller?.sourceIp ?? null,
        proposedAt: nowMillisISO(),
        summary: typeof summary === "string" ? summary.slice(0, 1000) : "",
        actionHash,
        status: "pending",
        expiresAt: new Date(now + OWNER_ACTION_TTL_MS).toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
      };
      await this.state.storage.put(ownerActionKey(id), record);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: proposedBy,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "owner-action-propose",
        outcome: "success",
        target: { kind: "owneraction", id, actionKind: kind },
      });
      return record;
    }

    // verifyOwnerActionIntegrity is the shared no-tamper recompute the approve, consume and execute paths run:
    // it re-derives the actionHash from the STORED record alone (kind + params + router-executed flag + the
    // proposer identity the execute re-resolves authority from) and refuses a mismatch. A stored-record tamper
    // of the params (to change what the action does) or of the actor identity (to borrow a more privileged
    // proposer the execute would re-resolve authority from) is caught here, the SAME teeth the config-change
    // gate's contentHash recompute provides. THROWS on a mismatch (mapped to a 400 by the fetch() catch).
    async verifyOwnerActionIntegrity(record: PendingOwnerAction): Promise<void> {
      if (!isOwnerActionKind(record.kind)) throw new Error("the action has an unknown kind and cannot be carried out");
      // THE SCRUB GUARD, and it runs BEFORE the recompute because the recompute cannot survive it. A spent
      // record's params are stripped of their live secret at rest (scrubSpentOwnerActionParams), so its
      // actionHash no longer recomputes BY CONSTRUCTION. Without this branch every duplicate approve and every
      // replayed consume of a SECRET-BEARING spent action would recompute a mismatch and be filed as
      // integrity-failed -- the one governance class whose whole contract is "somebody tampered with a stored
      // record", raised on the commonest benign event there is (an owner clicking approve twice). That is the
      // crying-wolf shape the source-IP capture counter had to be rescued from at G346, and it would be worse
      // here, because the signal it drowns is a real tamper.
      //
      // IT RETURNS RATHER THAN THROWING ITS OWN REFUSAL, and that is deliberate. A new message here would
      // DISPLACE the caller's own state refusal, so a duplicate approve would answer "already carried out" for
      // an action that carried no secret and something else for one that did: the same situation described two
      // ways, decided by whether the params happened to contain a credential. Returning leaves canApprove-
      // OwnerAction / isArmedOwnerAction to give the exact reason they always gave. That is safe because a
      // scrub is only ever written to a record that can NEVER run again, so every caller's next act on this
      // record is an unconditional refusal; the recompute exists to stop a TAMPERED record's state deciding a
      // verdict, and the verdict here is fixed at "refuse" whatever the state says.
      //
      // A scrubbed record that is NOT spent is a different matter and keeps the full integrity refusal. Only
      // the spend paths ever write the marker and only ever to a spent record, and stripping the params is
      // exactly how an attacker would break the binding that pins a consume to one approved action, so a
      // scrubbed record still reading as pending or armed is a tamper and is reported as one.
      if (ownerActionParamsScrubbed(record)) {
        if (ownerActionParamsSpent(record, Date.now())) return;
        await recordGovernanceFault(this.state.storage, "owner-action-execute", "integrity-failed");
        await this.annotateOwnerActionAttempt(record.id, "integrity-failed");
        throw new Error("the action record failed its integrity check and cannot be carried out");
      }
      const recomputed = await ownerActionHash(
        record.kind,
        record.params,
        record.routerExecuted === true,
        record.proposedBy,
        record.proposedBySubject ?? null,
        Array.isArray(record.proposedByGroups) ? record.proposedByGroups : [],
      );
      if (recomputed !== record.actionHash) {
        // G034: a TAMPER on the stored owner-action record. Security-significant. Its own closed class, never
        // conflated with a guard refusal.
        await recordGovernanceFault(this.state.storage, "owner-action-execute", "integrity-failed");
        await this.annotateOwnerActionAttempt(record.id, "integrity-failed");
        throw new Error("the action record failed its integrity check and cannot be carried out");
      }
    }

    // scrubSpentOwnerActionParams strips the live secret from a record whose action can never run again, IN
    // PLACE on the object the caller is about to persist, so the scrub commits in the SAME storage.put as the
    // terminal status and there is no window where a spent record still holds the credential. It returns
    // whether anything was stripped. It stamps paramsScrubbedAt ONLY when the strip actually removed a field
    // (scrubOwnerActionParams returns its input by reference otherwise), so a secret-free action keeps a fully
    // recomputable actionHash and loses none of its tamper detection: the marker means "this binding can no
    // longer be recomputed", and claiming that of a record whose params never changed would be false.
    //
    // The caller decides WHEN; this only decides WHAT. The three terminal transitions call it (the DO-executed
    // approve, the router-executed consume, and any reject), and the lazy expiry sweep calls it for the
    // records nobody ever decided. It deliberately refuses to act on a record that is not spent, so a future
    // call site cannot scrub an ARMED router-executed record out from under its own consume-time recompute.
    scrubSpentOwnerActionParams(record: PendingOwnerAction, now: number): boolean {
      if (ownerActionParamsScrubbed(record)) return false;
      if (!ownerActionParamsSpent(record, now)) return false;
      const scrubbed = scrubOwnerActionParams(record.params);
      if (scrubbed === record.params) return false; // nothing secret to strip; leave the hash recomputable
      record.params = scrubbed;
      record.paramsScrubbedAt = nowMillisISO();
      return true;
    }

    // sweepSpentOwnerActionParams is the LAZY half, for the records the terminal transitions never see: an
    // action proposed and then never approved or rejected sits pending until its TTL lapses, and expiry here
    // is COMPUTED at read (effectiveOwnerActionStatus), never written, so no code path ever visits the record
    // again. That is the longest-lived copy of a live secret in this subsystem and it belongs to the case the
    // support pack already counts as a governance stall (expiredUndecidedCount). There is no alarm to hang the
    // sweep on and adding one to carry it would be a new scheduled surface for a housekeeping job, so it rides
    // the two paths that ALREADY list the whole prefix and pay that cost: the inbox listing and the
    // router-executed gate's armed-match scan. Best-effort and never-throwing in either direction -- a failed
    // sweep must never turn an owner's inbox read or an armed re-submit into an error, and it changes no
    // status, so the record's lifecycle and every refusal above are untouched whether it runs or not.
    async sweepSpentOwnerActionParams(records: Iterable<PendingOwnerAction>, now: number): Promise<void> {
      try {
        for (const record of records) {
          if (!this.scrubSpentOwnerActionParams(record, now)) continue;
          await this.state.storage.put(ownerActionKey(record.id), record);
        }
      } catch {
        /* best-effort housekeeping: the caller's own read must still answer */
      }
    }

    // proposerReplayCaller rebuilds the MutationCaller-shaped authority the execute runs as on approve: the
    // proposer's stored email + STABLE subject + propose-time groups. The execute's own method re-resolves the
    // proposer's LIVE authority from this subject against the role table (owner re-check), so a proposer who
    // lost owner between propose and approve is caught. It is the OWNER-action analogue of approveChange's
    // replayCaller. sourceIp is the PROPOSE-TIME address off the record (G346): the execute audits itself as
    // the proposer, an attributed human, so dropping the address the engine had captured made every approved
    // owner action look like a live source-IP capture failure to the pack's own counter.
    //
    // replay: true marks this as a system replay of the proposer's original request, not a fresh caller
    // action. The stored email flows into roleForCaller, and resolveBoundEntry's bind-on-first-auth matches a
    // pending grant BY EMAIL and writes it onto whatever subject is presented, so without this flag an invite
    // issued at a departed proposer's re-used address could bind to the DEPARTED subject at execute time
    // rather than to the proposer. Since a pending OWNER invite is the one grant an owner-action execute
    // needs, this is the highest-privilege place that binding must be suppressed. The flag suppresses the
    // bind only; the subject-keyed re-resolution and the owner re-check are unchanged.
    proposerReplayCaller(record: PendingOwnerAction): { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp: string | null; replay: true } {
      return {
        method: "access",
        email: record.proposedBy,
        subject: record.proposedBySubject ?? null,
        groups: Array.isArray(record.proposedByGroups) ? record.proposedByGroups : [],
        sourceIp: record.proposedBySourceIp ?? null,
        replay: true,
      };
    }

    // approveOwnerAction is the second-identity approval, ALL inside one read-modify-write so the decision is
    // atomic with the outcome. It enforces, in order: the record exists and has a known kind; the no-tamper
    // actionHash recompute; maker != checker on the stable subject axis + the approver is an owner +
    // attributable + the record is still pending + not expired (canApproveOwnerAction). Then it BRANCHES on the
    // flow:
    //   - DO-EXECUTED kind: it RUNS the real method NOW, AS THE PROPOSER (re-resolved live), via the dispatch
    //     in executeOwnerActionDO, so the proposer's owner ceiling is re-checked at execute time and the action
    //     runs through the SAME method the gate-off path runs. The record goes straight to "executed" (single
    //     use). An owner-action-execute event records the action ran (the maker re-resolved as actor); the
    //     method's own audit event (e.g. dest-config-set) additionally attributes the proposer.
    //   - ROUTER-EXECUTED kind: it does NOT run anything (the privileged op runs in the router with a one-shot
    //     token the DO never holds). It marks the record "approved" (ARMED) and returns; the maker then
    //     re-submits the route WITH the token and the router consumes the armed approval (consumeOwnerAction).
    // Both record the checker. THROWS on any refusal (mapped to a 400 by the fetch() catch); the router returns
    // the first-class owner gate before forwarding, so reaching here means the caller is at least an owner.
    // readOwnerActionRecord is the ONE read every owner-action path now goes through (G312). Its addition is
    // the twin of readApprovalRecord's: a queued owner action whose expiresAt does not PARSE never reads as
    // expired (effectiveOwnerActionStatus guards on Number.isFinite), so an ARMED second-owner approval for a
    // high-blast-radius operation outlives its TTL, silently. Throttled + best-effort; counts only.
    async readOwnerActionRecord(id: string): Promise<PendingOwnerAction | null> {
      const record = (await this.state.storage.get<PendingOwnerAction>(ownerActionKey(id))) ?? null;
      if (record !== null && ownerActionTimestampUnparseable(record)) void this.recordAdminCountersThrottled(["stored-owner-action-unparseable-timestamp"]);
      return record;
    }

    async approveOwnerAction(
      req: { id?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<PendingOwnerAction> {
      if (typeof req.id !== "string" || req.id.length === 0) throw new Error("id required");
      const record = await this.readOwnerActionRecord(req.id);
      if (record === null) throw new Error("no such owner action");
      // No-tamper recompute FIRST (so a tampered record is refused before any state read decides the verdict).
      await this.verifyOwnerActionIntegrity(record);
      // Re-resolve the approver's authority from the DO's OWN tables (never the forwarded role) and run the pure
      // maker != checker / state / owner gate. Every gated op is owner-class, so the approver must be an owner.
      const approver = await this.roleForCaller(caller);
      const checker = caller?.email ? caller.email : null;
      const checkerSubject = caller ? this.normaliseSubject(caller.subject) : null;
      const now = Date.now();
      const verdict = canApproveOwnerAction(record, checker, checkerSubject, approver.role === "owner", now);
      if (!verdict.ok) {
        // G182: the closed reason. An owner action stuck awaiting a second approver, refused because the FIRST
        // owner keeps trying to approve their own proposal (self-approval), is a completely different ticket
        // from one whose TTL lapsed (expired) -- and both arrived as "the approve button does nothing".
        await recordGovernanceRefusal(this.state.storage, "owner-action-approve", verdict.reasonCode);
        throw new Error(verdict.reason);
      }
      if (record.routerExecuted === true) {
        // ROUTER-EXECUTED: ARM the approval only. The router runs the privileged op with the one-shot token on
        // the re-submit and consumes this armed record then.
        record.status = "approved";
        record.approvedBy = checker!;
        record.approverSubject = checkerSubject!;
        record.approvedAt = nowMillisISO();
        await this.state.storage.put(ownerActionKey(record.id), record);
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: checker,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "owner-action-approve",
          outcome: "success",
          target: { kind: "owneraction", id: record.id, actionKind: record.kind, approverEmail: checker! },
        });
        // ML-04 sibling (this echo is a SECOND read path into the same at-rest params the listing redacts):
        // the record still carries whatever live secret the proposer submitted (config.secretAccessKey,
        // config.assumeRole.externalId, top-level secret/token) and this response goes straight back to the
        // CALLER (the approving owner) via a bare this.json(). Reuse the SAME viewOwnerAction projection the
        // listing uses so this echo is redaction-safe too; the STORED record (put above) is untouched, so the
        // token re-submit + consumeOwnerAction still replay the byte-identical, unredacted action.
        return viewOwnerAction(record, now);
      }
      // DO-EXECUTED: run the real method NOW, AS THE PROPOSER (re-resolved live), then mark executed (single
      // use). executeOwnerActionDO dispatches to the same method the gate-off path runs; that method re-checks
      // the proposer's owner ceiling from the live role table by their subject, so a demoted proposer is caught
      // and the action cannot escalate. The method's own audit event attributes the proposer; the
      // owner-action-approve + owner-action-execute events below attribute the checker and that the action ran.
      //
      // CONCURRENCY GUARD (asymmetric with consumeOwnerAction, which already wraps): two concurrent distinct-
      // owner approvals of the SAME pending id could both pass the verdict above and both call execute, double-
      // executing. So the EXECUTE runs inside blockConcurrencyWhile, which RE-READS the record and RE-ASSERTS the
      // effective status is STILL pending (and re-verifies integrity) INSIDE the critical section before
      // executeOwnerActionDO. A loser finds the record already executed/approved/gone and refuses (single use).
      // ASSUMPTION: every DO-executed gated op is IDEMPOTENT (a re-run yields the same end state), true for the
      // current kinds (set destination/default, create/delete/enable an IdP connection, set discovery
      // token/accounts, retire break-glass, disarm dual control). The guard makes a double-execute impossible
      // anyway; this note is so a FUTURE non-idempotent kind is added deliberately (and re-examined here) rather
      // than silently inheriting the read-modify-write race the guard closes.
      //
      // AUTH-46 (DO-reset on a foreseeable auth refusal): executeOwnerActionDO re-resolves the PROPOSER's LIVE
      // authority (setDefaultDest et al re-check owner by subject), so a proposer DEMOTED between propose and
      // approve is refused with an AuthError. That refusal is FORESEEABLE and must NOT escape blockConcurrency-
      // While: an exception thrown inside the critical section RESETS the Durable Object (wiping in-memory
      // scheduler state) and surfaces as a 500, when the correct outcome is a clean 403 with the DO intact -- the
      // action already did NOT run, so security is unaffected either way, only the availability of the DO. So the
      // guarded fn CATCHES the proposer AuthError and returns a sentinel (no state write: the record stays
      // pending, single-use preserved, and no approve/execute audit is committed -- matching the prior throw's
      // rollback); the AuthError is then re-thrown OUTSIDE the guard, where the fetch() catch maps it to 403.
      // This brings the DO-executed path to the shape the ROUTER-executed path already has (consumeOwnerAction
      // re-resolves owner OUTSIDE its critical section). The SAME treatment now covers the two OTHER foreseeable
      // in-guard refusals below (fresh===null and a failed integrity/verdict recheck): each is an ordinary,
      // no-write refusal the outer checks already anticipate (the record vanished, was tampered, or a concurrent
      // distinct-owner approval won the race), not a fault, so each returns the same {ok:false,error} sentinel,
      // re-thrown OUTSIDE the guard and mapped to its normal 400/403 by the fetch() catch. Any OTHER exception --
      // a genuinely unexpected fault, e.g. from the post-execute audit/storage.put below -- still propagates
      // uncaught, unchanged. The approve + execute audits are written only on the SUCCESS path (after the action
      // ran), so a refused execute commits nothing.
      const outcome = await this.blockConcurrencyWhile(async (): Promise<{ ok: true; record: PendingOwnerAction } | { ok: false; error: Error }> => {
        const fresh = await this.readOwnerActionRecord(record.id);
        if (fresh === null) return { ok: false, error: new Error("no such owner action") };
        try {
          await this.verifyOwnerActionIntegrity(fresh);
        } catch (e) {
          return { ok: false, error: e instanceof Error ? e : new Error(String(e)) };
        }
        const innerNow = Date.now();
        // Re-assert the FULL approve verdict inside the critical section (status still pending, maker != checker,
        // approver still owner). A concurrent winner has already flipped it to "executed", so the loser's
        // effective status is no longer pending and canApproveOwnerAction refuses it (single use). This is as
        // FORESEEABLE and as benign as the proposer-AuthError case just below (an ordinary concurrent-approval
        // race, not a fault), so it gets the SAME sentinel treatment instead of a bare throw -- a throw here
        // would reset the DO for the race's loser exactly as the AUTH-46 comment above describes.
        const innerVerdict = canApproveOwnerAction(fresh, checker, checkerSubject, approver.role === "owner", innerNow);
        if (!innerVerdict.ok) {
          await recordGovernanceRefusal(this.state.storage, "owner-action-execute", innerVerdict.reasonCode);
          return { ok: false, error: new Error(innerVerdict.reason) };
        }
        // Run the proposer's action FIRST. Any FORESEEABLE refusal from the replayed method must not escape
        // blockConcurrencyWhile and reset the DO: a proposer who lost owner is refused with an AuthError (-> 403),
        // and a target that changed between propose and approve is refused with a plain Error the method throws
        // (e.g. removeDest "no such destination" / "destination is in use by N downpipes", setDefaultDest on a
        // gone id). Both are ordinary no-write refusals (the method validates before it writes), so sentinel ALL
        // of them with NOTHING written (no audit, no status flip) -- exactly what the prior in-guard throw's
        // rollback left behind -- and re-throw OUTSIDE the guard, where the fetch() catch maps an AuthError to
        // 403 and a plain Error to 400. A genuinely unexpected fault is likewise surfaced as a clean 400 rather
        // than a DO-resetting 500; the record stays pending (single-use preserved) and the caller can retry.
        try {
          await this.executeOwnerActionDO(fresh);
        } catch (e) {
          return { ok: false, error: e instanceof Error ? e : new Error(String(e)) };
        }
        // The action ran: record the approve + execute audits and flip the record to executed (single use).
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: checker,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "owner-action-approve",
          outcome: "success",
          target: { kind: "owneraction", id: fresh.id, actionKind: fresh.kind, approverEmail: checker! },
        });
        fresh.status = "executed";
        fresh.approvedBy = checker!;
        fresh.approverSubject = checkerSubject!;
        fresh.approvedAt = nowMillisISO();
        fresh.executedAt = nowMillisISO();
        // The action has RUN, so its params have no remaining reader: strip the live secret in the SAME write
        // that makes the record terminal, leaving no window where a spent action still holds the credential.
        this.scrubSpentOwnerActionParams(fresh, Date.now());
        await this.state.storage.put(ownerActionKey(fresh.id), fresh);
        await this.appendAudit({
          actorSubject: fresh.proposedBySubject ?? null,
          actorEmail: fresh.proposedBy,
          actorMethod: "access",
          // sourceIp is the PROPOSE-TIME address off the record (G346), the SAME address proposerReplayCaller
          // stamps on the mutation this execute replays, and for the same reason. This event is attributed to the
          // PROPOSER (it runs the proposer's action when the second owner approves), so the CURRENT caller's
          // address (the APPROVER'S) would mislabel where the proposer acted from -- but the record HAS the
          // proposer's address: propose stores it as proposedBySourceIp, so this event is attributed correctly
          // rather than reading as a missing source-IP capture on the commonest owner op there is
          // (appendAudit's source-IP capture fault counter, scheduler-do-audit.ts).
          sourceIp: fresh.proposedBySourceIp ?? null,
          action: "owner-action-execute",
          outcome: "success",
          target: { kind: "owneraction", id: fresh.id, actionKind: fresh.kind, approverEmail: checker! },
        });
        return { ok: true, record: fresh };
      });
      // Surface ANY in-guard refusal OUTSIDE the guard: an AuthError still maps to 403 (e instanceof AuthError
      // in the fetch() catch), a plain Error to 400 -- byte-identical to what each reason mapped to when it
      // threw directly, just without resetting the DO to get there.
      if (!outcome.ok) {
        // G034: every failed owner-action approve/execute attempt passes through here. Closed class only:
        // classifyGovernanceOutcome reads the refusal to SELECT a member and never stores its prose.
        const cls = classifyGovernanceOutcome(outcome.error);
        await recordGovernanceFault(this.state.storage, "owner-action-approve", cls);
        await this.annotateOwnerActionAttempt(record.id, cls);
        throw outcome.error;
      }
      // ML-04 sibling: same reasoning as the router-executed ARM branch above -- redact the echoed params
      // before they reach the caller's this.json() response. The executed record's status is terminal
      // ("executed"), so viewOwnerAction's status projection is a no-op here; only params are redacted.
      return viewOwnerAction(outcome.record, now);
    }

    // executeOwnerActionDO dispatches a DO-EXECUTED owner action to the EXISTING validated method, AS THE
    // PROPOSER (re-resolved live), the same method the gate-off route calls directly. There is no second
    // divergent write: the owner re-check (roleForCaller(...).role === "owner") and every validation live in
    // the methods this delegates to, and they re-resolve the proposer's authority from their immutable subject
    // against the LIVE role table, so a proposer who lost owner between propose and approve cannot have their
    // action executed. The switch is exhaustive over the DO-executed kinds; a router-executed kind (which must
    // never reach here) or an unknown kind throws (fail closed, no write). Each method's params shape matches
    // the params stored at propose time, exactly as applyConfigMutation casts the stored config-change params.
    async executeOwnerActionDO(record: PendingOwnerAction): Promise<void> {
      const authority = this.proposerReplayCaller(record);
      const params = record.params;
      switch (record.kind) {
        case "dest-set":
          await this.setDestConfig(params as { config?: unknown }, authority);
          return;
        case "dest-put":
          await this.putDest(params as { id?: unknown; label?: unknown; config?: unknown }, authority);
          return;
        case "dest-remove": {
          const p = params as { id?: unknown; force?: unknown };
          await this.removeDest(typeof p.id === "string" ? p.id : "", p.force === true, authority);
          return;
        }
        case "dest-default":
          await this.setDefaultDest(typeof (params as { id?: unknown }).id === "string" ? (params as { id: string }).id : "", authority);
          return;
        case "push-dest-set":
          await this.setSiemPushDestination(params as { endpoint?: unknown; format?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown; sink?: unknown; authInUrl?: unknown; s3Target?: unknown; syslog?: unknown }, authority);
          return;
        case "otlp-push-dest-set":
          await this.setOtlpPushDestination(params as { endpoint?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown }, authority);
          return;
        case "idp-conn-create":
          await this.idpConnCreate(params as Record<string, unknown>, authority);
          return;
        case "idp-conn-delete":
          await this.idpConnDelete(params as { connId?: unknown }, authority);
          return;
        case "idp-conn-enabled":
          await this.idpConnSetEnabled(params as { connId?: unknown; enabled?: unknown }, authority);
          return;
        case "idp-conn-cert":
          await this.idpConnSamlCertUpdate(params as { connId?: unknown; addCerts?: unknown; certs?: unknown }, authority);
          return;
        case "break-glass-retire":
          await this.setBreakGlassTokenRetired(params as { retired?: unknown }, authority);
          return;
        case "discovery-token-set":
          await this.setDiscoveryToken(params as { token?: unknown; accountsSeen?: unknown }, authority);
          return;
        case "discovery-accounts-set":
          await this.setDiscoveryAccounts(params as { selected?: unknown; engineAccountId?: unknown }, authority);
          return;
        case "dual-control-disable":
          // DISARM the off switch as the PROPOSER (re-resolved live). setRequireConfigApproval re-checks owner
          // and applies false; the params carry the explicit false so the apply is unambiguous regardless of
          // what was stored. This is the asymmetric off-switch's APPROVED path (arm + break-glass disarm run
          // immediately at the route; only a non-break-glass disarm-when-ON reaches here, behind a second owner).
          await this.setRequireConfigApproval({ requireConfigApproval: false }, authority);
          return;
        case "update-apply":
        case "update-settle":
        case "sources-attach":
        case "support-credential-mint":
          // These are ROUTER-EXECUTED: the privileged op (a one-shot-token deploy, or a one-time secret mint)
          // runs in the router, never the DO. They never reach this dispatch (approveOwnerAction ARMS them and
          // the router consumes the approval, running the op itself). Fail closed if one ever does.
          throw new Error(`owner action ${record.kind} is router-executed and must not run in the DO`);
        default: {
          const _exhaustive: never = record.kind;
          throw new Error(`unknown owner action kind: ${String(_exhaustive)}`);
        }
      }
    }

    // consumeOwnerAction is the ROUTER-EXECUTED flow's atomic single-use gate: the router calls it on the
    // re-submit (the maker re-submitting the route WITH the one-shot deploy token) BEFORE it runs the
    // privileged op, asking "is there a usable ARMED approval for THIS exact action, by a distinct owner?". It
    // re-checks the no-tamper actionHash, then verifies the record is armed (effective status approved, a
    // checker subject recorded, maker != checker) AND not expired, then MARKS IT EXECUTED inside the same
    // read-modify-write (so a concurrent second consume of the same record finds it already executed and is
    // refused, single use). It returns { ok:true } ONLY when it has just consumed a genuinely-armed approval;
    // otherwise it THROWS (mapped to a 400), so the router proceeds with the token ONLY because an approved
    // owner-action record existed and was consumed here. The router supplies the EXPECTED action hash it
    // re-computed from the re-submitted request (so the consume cannot be redirected to a DIFFERENT armed
    // action): the stored record's hash MUST equal it, which (because the hash binds the proposer identity too)
    // also pins the consume to the maker who proposed it. Every refusal INSIDE the guard (below) returns a
    // {ok:false,error} sentinel rather than throwing directly, mirroring approveOwnerAction above: a throw
    // escaping blockConcurrencyWhile resets the Durable Object, and every one of these is an ordinary,
    // foreseeable no-write refusal (a stale/duplicate re-submit, a vanished or tampered record), not a fault.
    // The sentinel is re-thrown OUTSIDE the guard, so the caller-visible contract above (throws, mapped to a
    // 400) is unchanged.
    async consumeOwnerAction(
      req: { id?: unknown; expectedActionHash?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true; id: string; actionHash: string }> {
      const id = typeof req.id === "string" ? req.id : "";
      if (id.length === 0) throw new Error("id required");
      // The router re-submitting MUST be an attributable owner (the proposer re-submitting with the token). The
      // DO re-resolves owner from its own tables (defence in depth over the router's owner gate).
      const resubmitter = await this.roleForCaller(caller);
      if (resubmitter.role !== "owner") throw new AuthError("forbidden: only an Owner may carry out a high-blast-radius owner action");
      const outcome = await this.blockConcurrencyWhile(async (): Promise<{ ok: true; id: string; actionHash: string } | { ok: false; error: Error }> => {
        const record = await this.readOwnerActionRecord(id);
        if (record === null) return { ok: false, error: new Error("no such owner action") };
        if (record.routerExecuted !== true) return { ok: false, error: new Error("this owner action does not use the token-resubmit flow") };
        try {
          await this.verifyOwnerActionIntegrity(record);
        } catch (e) {
          return { ok: false, error: e instanceof Error ? e : new Error(String(e)) };
        }
        // The router re-computed the action hash from the re-submitted request; it MUST match the stored
        // record's hash, pinning the consume to the EXACT armed action (and, via the identity-bound hash, to its
        // proposer). A mismatch means the re-submission's params/identity differ from what was approved.
        const expected = typeof req.expectedActionHash === "string" ? req.expectedActionHash : "";
        if (expected === "" || expected !== record.actionHash) {
          return { ok: false, error: new Error("the resubmitted action does not match the approved one (re-arm-on-change); raise it again") };
        }
        const now = Date.now();
        // G312: the owner-action twin of the restore approval's unenforceable TTL, at the CONSUME -- the call
        // that spends the approval and runs the high-blast-radius operation. effectiveOwnerActionStatus expires
        // a record only on a PARSEABLE expiresAt, so a garbled one never lapses and an armed approval stays
        // armed forever. Recorded whatever the outcome (the fault is the stored record's), counts only.
        if (!Number.isFinite(Date.parse(record.expiresAt))) await this.bumpAdminCounterLocal("stored-owner-action-unparseable-timestamp");
        if (!isArmedOwnerAction(record, now)) {
          // Give the precise reason: still pending (no second owner yet), expired, already executed, or
          // rejected. Every one of these is an ordinary, no-write refusal (a benign re-submit race or a stale
          // request), not a fault, so it is sentinelled like the checks above rather than thrown from the guard.
          const status = record.status;
          if (status === "pending") return { ok: false, error: new Error("owner action not approved: a second Owner must approve it first") };
          if (status === "executed") return { ok: false, error: new Error("the approval was already used") };
          if (status === "rejected") return { ok: false, error: new Error("the action was rejected") };
          return { ok: false, error: new Error("owner action not approved or the approval has expired; raise it again") };
        }
        // Consume: mark executed inside this critical section so a concurrent re-submit cannot double-consume.
        record.status = "executed";
        record.executedAt = nowMillisISO();
        // Spent: the router runs the privileged op from the RE-SUBMITTED request, never from these params (it
        // only had to prove they hash to the approved action), so nothing reads them again. Same write.
        this.scrubSpentOwnerActionParams(record, now);
        await this.state.storage.put(ownerActionKey(record.id), record);
        await this.appendAudit({
          actorSubject: caller ? caller.subject : null,
          actorEmail: caller?.email ? caller.email : null,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "owner-action-execute",
          outcome: "success",
          target: { kind: "owneraction", id: record.id, actionKind: record.kind, ...(record.approvedBy !== undefined ? { approverEmail: record.approvedBy } : {}) },
        });
        return { ok: true, id: record.id, actionHash: record.actionHash };
      });
      // Surface any in-guard refusal OUTSIDE the guard, mapped to its normal 400 by the fetch() catch --
      // byte-identical to the prior direct throw's mapping, just without resetting the DO to get there.
      if (!outcome.ok) {
        // G034: THE REPLAY DETECTOR. consumeOwnerAction is the atomic single-use gate on a router-executed
        // privileged op, and its "the approval was already used" refusal is a DETECTED REPLAY of a one-shot
        // approval -- security-significant, and it recorded nothing anywhere. classifyGovernanceOutcome maps
        // that refusal to replay-detected; every other refusal keeps its own class.
        const cls = classifyGovernanceOutcome(outcome.error);
        await recordGovernanceFault(this.state.storage, "owner-action-execute", cls);
        await this.annotateOwnerActionAttempt(id, cls);
        throw outcome.error;
      }
      return outcome;
    }

    // annotateOwnerActionAttempt stamps the record with its LAST FAILED attempt (G034). Best-effort and
    // never-throwing, and it writes ONLY the annotation field, so it can never disturb the record's status,
    // its integrity hash or the single-use lifecycle it protects. The twin of annotateChangeAttempt.
    async annotateOwnerActionAttempt(id: string, outcomeClass: string): Promise<void> {
      try {
        const rec = (await this.readOwnerActionRecord(id)) ?? undefined;
        if (rec === undefined) return;
        rec.lastAttempt = { at: nowMillisISO(), outcomeClass };
        await this.state.storage.put(ownerActionKey(id), rec);
      } catch {
        /* best-effort: the refusal itself must still surface cleanly */
      }
    }

    // checkOwnerActionGate is the router's question on the FIRST call of a router-executed op: "is dual control
    // ON, and if so, has THIS action already been approved (armed) so the router may run it now, or must it be
    // recorded as a pending approval?". The router computes the action hash from the request + the caller, and:
    //   - gate OFF -> { gate: "off" }: the router runs the op inline, byte-identical to before.
    //   - gate ON, an ARMED approval matching this hash + this proposer exists -> { gate: "armed", id }: this is
    //     the re-submit; the router should CONSUME it (consumeOwnerAction) and run the op with the token.
    //   - gate ON, no armed approval -> the DO RECORDS a pending approval and returns { gate: "pending", id }:
    //     the router answers 202 WITHOUT consuming a token / running the op.
    // This keeps ALL the gate logic in the DO (the router cannot bypass it), and ensures the one-shot token is
    // only ever used on the approved execution. The router passes the kind, the params (decision-relevant,
    // non-secret, NEVER the token), and a redaction-safe summary; the DO derives everything else.
    async checkOwnerActionGate(
      req: { kind?: unknown; params?: unknown; summary?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null; change?: ChangeRef | null } | null,
    ): Promise<{ gate: "off" } | { gate: "pending"; id: string; actionHash: string } | { gate: "armed"; id: string; actionHash: string }> {
      const kind = req.kind;
      if (!isOwnerActionKind(kind)) throw new Error("unknown owner action kind");
      if (!isRouterExecutedOwnerAction(kind)) throw new Error("this owner action is not router-executed");
      // CHANGE MANAGEMENT (OWNER OPT-IN): enforce the change reference exactly ONCE at INITIATION, never on the
      // armed RE-SUBMIT. This router-executed gate is called on BOTH the first call (off => run inline; on =>
      // record pending) AND the re-submit (armed => consume + run). The change-recorded CR is raised on the
      // first call only, so enforceChangeControl is called in the gate-off branch and just before recordOwner-
      // Action below (the two initiation paths), but NOT on the armed return (which would double-record / would
      // demand the change ref again on a re-submit that need not carry it). A no-op when the policy is off.
      // Router-executed kinds (update/attach/mint) are NOT in the high-blast auto-apply set, so this reduces to
      // the opt-in toggle today; routing through effectiveOwnerActionGateOn keeps the two gate sites in lockstep
      // so a future high-blast router-executed kind would be auto-gated identically (and would honour the same
      // bare-token break-glass exemption, the caller method is forwarded for that reason).
      const gateOn = await this.effectiveOwnerActionGateOn(kind, caller ? caller.method : null);
      if (!gateOn) {
        // Gate OFF: the router runs the op inline on this single call. Record the CR now (the inline initiation).
        if (isChangeControlledOwnerAction(kind)) await this.enforceChangeControl(kind, caller);
        return { gate: "off" };
      }
      // The router MUST present an attributable owner here (the maker). Re-resolve owner from the DO's own
      // tables (defence in depth). A bare-token caller has no email and is refused (cannot be a maker).
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may carry out a high-blast-radius owner action");
      const proposedBy = caller?.email ? caller.email : null;
      if (proposedBy === null) {
        throw new Error("dual control requires an attributable identity; the bare-token fallback cannot propose an owner action");
      }
      const proposedBySubject = caller ? caller.subject : null;
      const proposedByGroups = caller ? caller.groups : [];
      const actionHash = await ownerActionHash(kind, req.params, true, proposedBy, proposedBySubject, proposedByGroups);
      // Is there already an ARMED approval for THIS exact action (same hash) that is usable (not expired,
      // executed, rejected; maker != checker)? If so, this call is the re-submit: tell the router to consume it.
      const now = Date.now();
      // Full-prefix scan (no page limit): the armed match is by actionHash, not by key, so every pending
      // record must be examined; a paged limit could skip the very record that arms this action. Owner
      // actions are human-scale approvals, so the prefix stays small in practice.
      const map = await this.state.storage.list<PendingOwnerAction>({ prefix: OWNER_ACTION_PREFIX });
      for (const rec of map.values()) {
        if (rec.actionHash === actionHash && isArmedOwnerAction(rec, now)) {
          return { gate: "armed", id: rec.id, actionHash };
        }
      }
      // The prefix is already listed and the armed match has already been decided, so the lazy sweep of spent
      // records rides this scan for free. It runs AFTER the match so it can never affect the answer above.
      await this.sweepSpentOwnerActionParams(map.values(), now);
      // No armed approval: this is the FIRST call (initiation). Record the CR now (once), then record a fresh
      // pending owner action and tell the router to answer 202. (If an identical PENDING one already exists, the
      // maker called twice before a second owner approved, record a new one; it is harmless, both await the same
      // approval, and the maker != checker + single-use rules still hold. Note a repeated first-call DOES record
      // a second change-recorded, an honest "raised again"; the armed re-submit never does.)
      if (isChangeControlledOwnerAction(kind)) await this.enforceChangeControl(kind, caller);
      const record = await this.recordOwnerAction(kind, req.params, typeof req.summary === "string" ? req.summary : "", caller);
      return { gate: "pending", id: record.id, actionHash };
    }

    // rejectOwnerAction discards a pending OR armed owner action (audited). Like the restore/config reject it
    // does NOT require maker != checker (the proposer may withdraw their own action, and ANY owner may veto an
    // armed one before it executes), but it gates on OWNER (re-resolved live), every gated op is owner-class, 
    // and must not overwrite a terminal state. It records an owner-action-reject event.
    async rejectOwnerAction(
      req: { id?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<PendingOwnerAction> {
      if (typeof req.id !== "string" || req.id.length === 0) throw new Error("id required");
      const record = await this.readOwnerActionRecord(req.id);
      if (record === null) throw new Error("no such owner action");
      if (!isOwnerActionKind(record.kind)) throw new Error("the action has an unknown kind");
      const rejecter = await this.roleForCaller(caller);
      if (rejecter.role !== "owner") throw new AuthError("forbidden: only an Owner may reject an owner action");
      const verdict = canRejectOwnerAction(record, Date.now());
      if (!verdict.ok) {
        await recordGovernanceRefusal(this.state.storage, "owner-action-approve", verdict.reasonCode);
        throw new Error(verdict.reason);
      }
      record.status = "rejected";
      // A vetoed action can never run, so its params are spent the moment the reject commits. This is the
      // arm that matters most for a WITHDRAWN proposal: an owner who realises they pasted the wrong
      // credential into a destination edit withdraws it, and until now that withdrawal left the wrong
      // credential in storage for ever.
      this.scrubSpentOwnerActionParams(record, Date.now());
      await this.state.storage.put(ownerActionKey(record.id), record);
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "owner-action-reject",
        outcome: "success",
        target: { kind: "owneraction", id: record.id, actionKind: record.kind },
      });
      // ML-04 sibling: a reject needs no maker != checker check (any Owner may veto), so this echo is the
      // EASIEST route to a proposer's live secret -- redact it the same way the listing and the approve echo
      // do. The record's status is already the terminal "rejected" set above, so viewOwnerAction only strips
      // params here.
      return viewOwnerAction(record, Date.now());
    }

    // listPendingOwnerActions serves GET /owner-actions: the PENDING and ARMED (approved-but-not-yet-executed)
    // owner actions, so the console can render the owner-approval inbox. A terminal executed/rejected/expired
    // record drops out. The visibility rule (canRequesterSeeOwnerAction) is the restore inbox's "owners see
    // all, the proposer also sees their own": the router forwards whether the caller is an owner + their
    // subject. Each returned record is REDACTION-SAFE: viewOwnerAction STRIPS any live secret from the params
    // (the destination secret access key, the IdP client secret, the discovery token) for the listing, so a
    // proposer's credential is never surfaced to other owners; the approver decides from the summary (which
    // names host/bucket/scope). The full params remain on the AT-REST record (read by id on approve/consume) so
    // the approved execution replays the byte-identical action; only this LISTING projection loses the secret.
    async listPendingOwnerActions(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<PendingOwnerAction[]> {
      const resolved = await this.roleForCaller(caller);
      const callerSubject = caller ? this.normaliseSubject(caller.subject) : null;
      const isOwner = resolved.role === "owner";
      const now = Date.now();
      const map = await this.state.storage.list<PendingOwnerAction>({ prefix: OWNER_ACTION_PREFIX });
      // The inbox is the read an owner performs most often and it already pays for the full prefix list, so
      // the lazy sweep of spent records rides it. It touches only records this listing then FILTERS OUT
      // (executed/rejected/expired never reach the response), so it cannot change what the owner sees.
      await this.sweepSpentOwnerActionParams(map.values(), now);
      return [...map.values()]
        .map((r) => viewOwnerAction(r, now))
        .filter((r) => r.status === "pending" || r.status === "approved")
        .filter((r) => canRequesterSeeOwnerAction(r, callerSubject, isOwner))
        .sort((a, b) => (a.proposedAt < b.proposedAt ? 1 : a.proposedAt > b.proposedAt ? -1 : 0));
    }

    // ownerActionQueueStats is the CALLER-INDEPENDENT aggregate of the dual-control owner-action queue for the
    // support pack (G259/G265). listPendingOwnerActions is caller-scoped (an approver sees only what they may
    // act on); a self-service bundle has no caller, so this reads the whole queue and returns counts only:
    // how many actions are outstanding, the oldest proposal's age, a per-kind breakdown, and how many expired
    // undecided (proposed but nobody approved before the TTL -- a governance stall). No id, summary, actor or
    // param ever crosses; the kind is the closed OwnerActionKind vocabulary. Read-only.
    async ownerActionQueueStats(): Promise<{ pendingCount: number; approvalsOutstanding: number; expiredUndecidedCount: number; oldestProposedAt: string | null; kinds: Record<string, number> }> {
      const now = Date.now();
      const map = await this.state.storage.list<PendingOwnerAction>({ prefix: OWNER_ACTION_PREFIX });
      const views = [...map.values()].map((r) => viewOwnerAction(r, now));
      const outstanding = views.filter((r) => r.status === "pending" || r.status === "approved");
      const kinds: Record<string, number> = {};
      for (const r of outstanding) kinds[r.kind] = (kinds[r.kind] ?? 0) + 1;
      let oldestProposedAt: string | null = null;
      for (const r of outstanding) if (oldestProposedAt === null || r.proposedAt < oldestProposedAt) oldestProposedAt = r.proposedAt;
      return {
        pendingCount: outstanding.length,
        approvalsOutstanding: outstanding.filter((r) => r.status === "pending").length,
        expiredUndecidedCount: views.filter((r) => r.status === "expired").length,
        oldestProposedAt,
        kinds,
      };
    }
  };
}
