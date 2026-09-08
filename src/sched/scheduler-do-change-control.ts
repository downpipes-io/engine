// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the OPT-IN dual-control change-control
// gate for CONFIG mutations (the single apply chokepoint + the propose/dry-run/approve/reject path and the
// pending-change inbox). Split out of scheduler-do-dest-config.ts so neither file exceeds the module-size
// guardrail. ChangeControlMixin layers over a base whose `this` is SchedulerDOSurface, so it still reaches
// every validated DO mutation method through this.applyConfigMutation's dispatch (this.addDownpipe,
// this.setRole, ...) and the destination/policy/audit helpers (this.loadDestinations, this.roleForCaller,
// this.getRequireConfigApproval, this.appendAudit) with the SAME dispatch and `this` binding the single
// class had. Behaviour-preserving move-only: every gate semantic (gate-off inline apply + auto-snapshot,
// gate-on validate-then-queue, the dry-run checkpoint/rollback, the maker != checker + supersede + integrity
// re-checks, the proposer-ceiling re-resolution) is unchanged; no storage key, route, status code, response
// body or auth gate changed. A leaf the assembly depends on, never the reverse (madge 0 cycles).

import { baseMoved, CHANGE_PREFIX, CHANGE_WRITE_CAPABILITY, type ConfigChangeKind, canApproveChange, canRejectChange, changeContentHash, changeKey, configChangeParamsScrubbed, configChangeParamsSpent, isConfigChangeKind, type PendingChangeLine, type PendingConfigChange, scrubConfigChangeParams, viewConfigChange } from "../admin/change-control.ts";
import { CONFIG_GENESIS_PREV_HASH, type ConfigSnapshot, diffConfig } from "../admin/config-history.ts";
import type { AuthMethod, CustomRoleProposal, Role } from "../admin/identity.ts";
import { canRequireDualControl, DUAL_CONTROL_ENABLE_REFUSAL, RESTORE_DUAL_CONTROL_ENABLE_REFUSAL, strandRefusal, wouldStrandDualControl } from "../admin/owner-floor.ts";
import { IF_MATCH_REV_KEY, readPrecondition } from "./downpipe-precondition.ts";
import { classifyGovernanceOutcome, recordGovernanceFault, recordGovernanceRefusal, recordStorageAnomaly } from "./sched-fault-ledger.ts";
import { AuthError, type DownpipeConfig, type MutationCaller, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { newULID, nowMillisISO } from "./scheduler-helpers.ts";

export function ChangeControlMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // setRequireConfigApproval APPLIES the gate value. OWNER-ONLY: the DO RE-RESOLVES the caller's role from
    // its own tables (roleForCaller) and requires role === "owner" (the owner-token break-glass resolves to
    // owner, so it can always toggle), so a router bug cannot let a non-owner flip it. It applies the new value
    // to storage at once and records a config-policy-change audit event. THROWS -> 400 on a non-owner.
    //
    // ASYMMETRIC OFF SWITCH (the dual-control-disable gate). This method is the single APPLY chokepoint both
    // the immediate path and the second-owner-approved path funnel through, so it is NOT where the disarm gate
    // lives (that would re-queue the approved disarm and loop). The DECISION to gate a disarm is made at the
    // route (POST /config/approval-policy): ARM (false->true) and any no-op apply here IMMEDIATELY; a DISARM
    // (true->false) by an attributable owner is routed through gatedOwnerAction("dual-control-disable") and
    // only reaches this method (as the proposer) once a SECOND owner approves; a DISARM by the bare-token
    // break-glass owner reaches this method IMMEDIATELY (the lockout escape, break-glass cannot propose/approve
    // owner actions, so it must keep a direct off switch). See the route for the asymmetry + the no-deadlock
    // argument (arm-immediate + break-glass-disarm-immediate ⇒ the account can never be locked out of disarming).
    //
    // It RETURNS whether this apply was a true->false TRANSITION (disarmed), so the caller, the route on the
    // immediate paths, and the owner-action approve path on the approved disarm, can fire a real-time DISARM
    // ALERT through the notify channels (a disarm of the whole dual-control guarantee must be ALERTED, not just
    // audited). The transition is read BEFORE the write so an idempotent re-apply of the same value reports
    // disarmed:false (no alert spam).
    async setRequireConfigApproval(
      req: { requireConfigApproval?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ requireConfigApproval: boolean; disarmed: boolean }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the config-approval policy");
      if (typeof req.requireConfigApproval !== "boolean") throw new Error("requireConfigApproval must be a boolean");
      // INVARIANT (dual-control deadlock guard, rule a): an ATTRIBUTABLE Owner ENABLING dual control is refused
      // unless a DISTINCT second Owner exists, so a lone Owner can never arm a gate that would deadlock them
      // (with one Owner every change is its own maker and checker, so no queued change could ever be approved).
      // This fires on the RESULTING state being ON (req === true), which is reached only on the immediate ARM
      // path (the asymmetric off switch routes an attributable disarm through gatedOwnerAction, which reaches
      // this method with req === false, so a disarm is never blocked). The count uses the SAME bound + pending
      // Owner tally as the last-Owner guard, so a pending Owner invite already counts; a lapsed Owner grant does
      // not (effectiveRole). FAIL-SAFE: an unreadable role table throws out of countOwners here, so the gate is
      // never silently armed on a count the engine could not compute.
      //
      // THE BARE-TOKEN BREAK-GLASS IS EXEMPT, exactly as it is exempt from the high-blast owner-action auto-gate
      // and the fresh-auth step-up (effectiveOwnerActionGateOn / requireStepUp): its power is all-or-nothing and
      // protected by the token secret, and the route guarantees ARM is always immediate for it and, crucially,
      // that it can ALWAYS disarm (the no-deadlock off-switch escape). A token that could not arm would only
      // lose a reversible power; the realistic solo-Owner deadlock this guards against is an ATTRIBUTABLE
      // Owner, which this still refuses. So the guard applies to an attributable caller only.
      if (req.requireConfigApproval === true && caller?.method !== "token") {
        const owners = this.countOwners(await this.listRoleEntries(), await this.listPendingEntries(), Date.now());
        if (!canRequireDualControl(owners)) throw new Error(DUAL_CONTROL_ENABLE_REFUSAL);
        // THE STRAND INVARIANT (owner-floor.ts wouldStrandDualControl), second entrance. The enable guard
        // above asks whether a second Owner exists NOW. It does not ask whether that Owner can STOP existing
        // on its own, which a time-boxed grant does, nor whether the break-glass off-switch this gate's
        // no-deadlock proof rests on is still there. Arming last is one of the three orders that assembles
        // the unrecoverable combination, and it is refused here rather than discovered later, because later
        // there is nothing left that can act.
        const expiring = await this.expiringOwnerGrantCount();
        if (wouldStrandDualControl("arm-dual-control", { dualControlOn: false, breakGlassRetired: await this.getBreakGlassTokenRetired(), expiringOwnerGrants: expiring })) {
          throw new Error(strandRefusal("arm-dual-control", expiring));
        }
      }
      // Read the prior value FIRST so a genuine true->false transition is distinguished from an idempotent
      // re-apply (false->false / true->true / false->true are NOT disarms and must not fire the disarm alert).
      const wasOn = await this.getRequireConfigApproval();
      const disarmed = wasOn && req.requireConfigApproval === false;
      // MERGE-write so toggling the change-control gate never clears the bootstrap latch or the retire flag.
      await this.writeOrgPolicy({ requireConfigApproval: req.requireConfigApproval });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-policy-change",
        outcome: "success",
        // The access-policy variant (field-less) is the redaction-safe target: the trail records that the
        // governance policy changed, who changed it, and when; the new boolean value is the response, not the
        // immutable log (the standing discipline of never writing the value).
        // G036: the field-less target made "dual control was disarmed at 14:02" INDISTINGUISHABLE from a
        // change-number toggle, and gave no direction at all. policyName + newValue are a closed enum and a
        // boolean (the policy NAME and the DIRECTION, never an operator value), so the redaction class is
        // unchanged and the incident timeline finally has its decisive field.
        target: { kind: "access-policy", policyName: "config-approval", newValue: req.requireConfigApproval === true },
      });
      return { requireConfigApproval: req.requireConfigApproval, disarmed };
    }

    // setRequireRestoreApproval serves the RESTORE half of POST /config/approval-policy. It is a SEPARATE
    // policy from the config gate: an estate may want a second approver on a write-back over live data
    // without wanting one on every config mutation, or the reverse.
    //
    // ARMING IS FLOOR-GUARDED for the reason the whole flag exists. canApprove refuses a same-subject AND a
    // same-email approval, so on a one-identity estate no restore approval can ever be granted; arming there
    // would make restore-apply unreachable, which is exactly the state this flag was added to end. The floor
    // is the same two-identity floor the config gate uses (canRequireDualControl), and it is FAIL-SAFE: an
    // unreadable role table throws out of countOwners rather than arming on a count nobody could compute.
    //
    // DISARM IS NOT YET ASYMMETRIC, and that is a deliberate, recorded difference from the config gate. There,
    // a disarm is queued for a second Owner so one rogue Owner cannot unilaterally drop the guarantee. Here an
    // Owner disarms immediately. The asymmetric path needs a new owner-action kind and its dispatch; it is
    // worth having and is NOT claimed to be present. What is present: a restore apply still requires the apply
    // capability, a fresh WebAuthn step-up, a dry run and a plan-bound hash, and every disarm is audited.
    async setRequireRestoreApproval(
      req: { requireRestoreApproval?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ requireRestoreApproval: boolean; disarmed: boolean }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the restore-approval policy");
      if (typeof req.requireRestoreApproval !== "boolean") throw new Error("requireRestoreApproval must be a boolean");
      // The bare-token break-glass is exempt on the same terms as the config gate: its power is all-or-nothing
      // and protected by the token secret, and it must always retain the off switch.
      if (req.requireRestoreApproval === true && caller?.method !== "token") {
        const owners = this.countOwners(await this.listRoleEntries(), await this.listPendingEntries(), Date.now());
        if (!canRequireDualControl(owners)) throw new Error(RESTORE_DUAL_CONTROL_ENABLE_REFUSAL);
      }
      const wasOn = await this.getRequireRestoreApproval();
      const disarmed = wasOn && req.requireRestoreApproval === false;
      // MERGE-write, so toggling this never clears the bootstrap latch, the retire flag or the sibling gates.
      await this.writeOrgPolicy({ requireRestoreApproval: req.requireRestoreApproval });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-policy-change",
        outcome: "success",
        // policyName + newValue only: the policy NAME and the DIRECTION, never an operator value, so the
        // redaction class matches the config-approval toggle beside it.
        target: { kind: "access-policy", policyName: "restore-approval", newValue: req.requireRestoreApproval === true },
      });
      return { requireRestoreApproval: req.requireRestoreApproval, disarmed };
    }

    // headVersionRef returns the current config-history HEAD as { id, hash } (or the genesis sentinel when
    // no version exists yet), the base a pending change binds its diff + content hash to. The supersede check
    // compares a stored change's base against this at approve time: if the head moved, the change is stale.
    async headVersionRef(): Promise<{ id: number; hash: string }> {
      const versions = await this.listConfigVersions();
      const head = versions.length > 0 ? versions[versions.length - 1]! : null;
      return head !== null ? { id: head.id, hash: head.contentHash } : { id: -1, hash: CONFIG_GENESIS_PREV_HASH };
    }

    // applyConfigMutation is the SINGLE apply code path: it dispatches a (kind, params) pair to the EXISTING
    // validated DO mutation method, the same method the gate-off route calls directly and the same method an
    // approved change replays. There is no second, divergent write: validation, the no-escalation guards
    // (requireGrantWithinAuthority et al.) and the last-Owner guard all run here because they live in the
    // methods this delegates to. The caller passed in is the AUTHORITY for the apply: at propose time it is
    // the PROPOSER (so the proposer's ceiling is enforced); at approve time it is the PROPOSER again
    // (re-resolved live). The switch is exhaustive over the closed ConfigChangeKind; an unknown kind throws
    // (a tampered stored kind cannot reach a write). It returns the method's own result.
    //
    // THE PER-METHOD CAPABILITY RE-CHECK IS NOT UNIVERSAL, and this paragraph exists because the sentence it
    // replaces said it was. Fifteen kinds re-check the caller's live authority inside the method they
    // dispatch to (requireCapabilityResolved on the people/access-policy writes; requireNotifyConfig,
    // requirePostureRiskAccept and requireCapability on the notify, posture and expiry writes). THREE DO NOT.
    // downpipe-upsert reaches addDownpipe, which asks only for the NARROWER scheduledtest.config and only on
    // a cadence change; downpipe-delete reaches removeDownpipe and cf-config-mode-set reaches setCfConfigMode,
    // and BOTH ARE DISPATCHED BELOW WITH NO CALLER ARGUMENT AT ALL. On the gate-off and dry-run paths the
    // router's own gate() is what stands in front of those three. On the APPROVE path nothing did, so a
    // proposer whose authority had lapsed still had their queued downpipe create, downpipe delete or
    // capture-mode change applied on somebody else's approval. That is closed in approveChange by an
    // explicit maker floor over CHANGE_WRITE_CAPABILITY, applied to every kind rather than to a declared
    // list of three, so a kind added here cannot be added into the gap.
    async applyConfigMutation(
      kind: ConfigChangeKind,
      params: unknown,
      caller: MutationCaller | null,
    ): Promise<unknown> {
      switch (kind) {
        // THE OPERATOR'S BASE CHECK ENTERS HERE, on the ONE apply path both branches of the gate reach, so
        // it is enforced identically whether requireConfigApproval is on or off and cannot drift per route.
        // readPrecondition reads `ifMatchRev` off the submitted params with `in`, so a body that OMITS the
        // key and a body that sends `null` are different statements; the key is then STRIPPED, because it
        // is a statement about the request and not a field of the customer's configuration, and it must
        // never land in the stored record or in a config-history diff line.
        case "downpipe-upsert": {
          const stated = readPrecondition(params);
          const { [IF_MATCH_REV_KEY]: _stripped, ...config } = (params ?? {}) as Record<string, unknown>;
          return this.addDownpipe(config as unknown as DownpipeConfig, caller, { stated, guardResurrect: true });
        }
        case "downpipe-delete":
          return this.removeDownpipe(params as { id: string }, { stated: readPrecondition(params), caller });
        case "role-set":
          return this.setRole(params as { email?: string; role?: string; customRole?: string; expiresAt?: string }, caller);
        case "role-delete":
          return this.deleteRole(params as { email?: string }, caller);
        case "group-role-set":
          return this.setGroupRole(params as { group?: string; role?: string; customRole?: string }, caller);
        case "group-role-delete":
          return this.deleteGroupRole(params as { group?: string }, caller);
        case "custom-role-set":
          return this.addCustomRole(params as CustomRoleProposal, caller);
        case "custom-role-delete":
          return this.deleteCustomRole(params as { name?: string }, caller);
        case "notify-channel-set":
          return this.addNotifyChannel(params, caller);
        case "notify-channel-delete":
          return this.deleteNotifyChannel(params as { id?: string }, caller);
        case "notify-rule-set":
          return this.addNotifyRule(params, caller);
        case "notify-rule-delete":
          return this.deleteNotifyRule(params as { id?: string }, caller);
        case "posture-accept":
          return this.acceptPostureRisk(params as { checkId?: string; reason?: string }, caller);
        case "posture-unaccept":
          return this.unacceptPostureRisk(params as { checkId?: string }, caller);
        case "expiry-item-set":
          return this.addExpiryItem(params, caller);
        case "expiry-item-delete":
          return this.deleteExpiryItem(params as { id?: string }, caller);
        case "coverage-inventory":
          return this.setCoverageInventory(params, caller);
        case "cf-config-mode-set":
          return this.setCfConfigMode(params as { id?: unknown; mode?: unknown });
        default: {
          // Exhaustiveness: ConfigChangeKind is closed, so this is unreachable for a valid kind; a tampered
          // stored kind that slipped past isConfigChangeKind would land here and fail closed (no write).
          const _exhaustive: never = kind;
          throw new Error(`unknown config change kind: ${String(_exhaustive)}`);
        }
      }
    }

    // isOwnerConferringRoleSet reports whether a role-set grants the OWNER role -- the one config mutation that
    // mints a fresh maker-checker counterparty able to approve a high-blast OWNER action (a dest repoint/remove
    // or an IdP change). A group mapping and a custom role can NEVER confer owner (capGroupRole clamps below
    // owner; owner-reserved caps are barred from custom roles), so only a built-in role === "owner" reaches it.
    // Pure; kept a method for `this`-consistency with autoGateOwnerMint and reuse by the approveChange guard.
    isOwnerConferringRoleSet(kind: ConfigChangeKind, params: unknown): boolean {
      return kind === "role-set" && params !== null && typeof params === "object" && (params as { role?: unknown }).role === "owner";
    }

    // autoGateOwnerMint auto-arms dual control for an OWNER-minting role-set once a SECOND owner exists,
    // regardless of the requireConfigApproval toggle -- the config-stream sibling of the dest/IdP high-blast
    // auto-gate (effectiveOwnerActionGateOn). Together with the "an owner-conferring change needs an OWNER
    // approver" rule the approve path enforces, it closes the puppet-owner laundering path: a lone compromised
    // owner cannot inline-mint an owner to be the "distinct" checker for its own high-blast op, and cannot route
    // around it by minting an access-admin (which can no longer approve an owner grant). It is deliberately
    // NARROW -- it does not gate access-admin or any other appointment, so ordinary people-management is
    // unchanged; only the appointment of a new Owner (the truly high-blast, checker-minting act) dual-gates.
    // With ONE owner it does NOT engage (the first second-owner grant bootstraps dual control, with no one to
    // approve it -- the owner-action auto-gate's no-deadlock reasoning), and the bare-token break-glass is
    // exempt (the documented bootstrap identity that wires the first Owner).
    async autoGateOwnerMint(kind: ConfigChangeKind, params: unknown, caller: MutationCaller | null): Promise<boolean> {
      if (!this.isOwnerConferringRoleSet(kind, params)) return false;
      if (caller?.method === "token") return false; // bare-token break-glass: exempt, exactly like the owner-action auto-gate
      const owners = this.countOwners(await this.listRoleEntries(), await this.listPendingEntries(), Date.now());
      return owners >= 2;
    }

    // dryRunConfigMutation runs applyConfigMutation under a STORAGE CHECKPOINT and ROLLS IT BACK, so the
    // EXACT validated mutation logic (validation + the no-escalation/last-Owner guards + the per-method
    // capability re-check) executes at PROPOSE time and rejects a bad or unauthorised request NOW, while
    // nothing is committed. It captures the would-be config snapshot AFTER the (rolled-back) mutation by
    // gathering it inside the checkpoint, so the diff the approver reviews is current-config -> would-be-
    // config. The checkpoint is taken over the WHOLE keyspace (list with no prefix) AND the DO ALARM (a
    // downpipe upsert/delete re-arms the real alarm via rearmAlarm/setAlarm, which is NOT a storage key, so
    // it must be captured and restored separately) and restored by overwriting changed keys back to their
    // prior value, deleting keys the mutation added, and resetting the alarm to its pre-dry-run value (or
    // deleting it if none was set); the DO is single-threaded over its own storage, so no concurrent write
    // can interleave with the checkpoint. The upshot is that a mere PROPOSAL leaves NO side effect at all,
    // not even a re-armed alarm. A validation/guard failure THROWS (the method threw), which the caller
    // surfaces as a propose-time 400, exactly as the gate-off route would have. Returns the would-be snapshot.
    async dryRunConfigMutation(
      kind: ConfigChangeKind,
      params: unknown,
      caller: MutationCaller | null,
    ): Promise<ConfigSnapshot> {
      // Checkpoint: snapshot every key's current value. Deep-clone the values so a later in-place restore
      // cannot be perturbed by the mutation mutating a shared object reference. Enumerate the WHOLE keyspace
      // with the paginated full-prefix scan (listAllByPrefix with an empty prefix), NOT a bare list(): a
      // single storage.list() returns at most one page (the platform caps it at ~1000 keys), so a tenant
      // with more keys than the page would have its checkpoint silently TRUNCATED and the rollback would
      // then leave the un-captured tail un-restored (finding engine-src-040-02). The paged scan is complete
      // regardless of tenant scale.
      const before = await this.listAllByPrefix<unknown>("");
      const checkpoint = new Map<string, unknown>();
      for (const [k, v] of before) checkpoint.set(k, JSON.parse(JSON.stringify(v)));
      // Capture the current alarm too (a downpipe upsert/delete re-arms it; it is not a storage key). null
      // means no alarm is set. It is restored in the finally so a proposal cannot leave a re-armed alarm.
      const alarmBefore = await this.state.storage.getAlarm();
      let wouldBe: ConfigSnapshot | undefined;
      // mutationError holds a throw from the REAL mutation (a validation / guard / capability failure -- the
      // ordinary propose-time rejection). It is CAPTURED rather than propagated immediately so the rollback
      // below still runs, and re-thrown at the end. It is deliberately NOT a `finally`: the rollback needs to
      // be able to throw its OWN fault (see below), and a `throw` inside a `finally` silently DISCARDS the
      // exception the try block raised -- so a dry run whose validation rejected AND whose rollback then
      // faulted would have reported only the rollback, losing the reason the proposal was refused at all.
      let mutationError: unknown;
      try {
        // Run the REAL validated mutation. It may throw (validation/guard/capability failure) -> propose-time
        // rejection; it may write to storage -> captured by the would-be snapshot, then rolled back below.
        await this.applyConfigMutation(kind, params, caller);
        // Capture the posture the mutation WOULD have produced (the diff target), read from the live (post-
        // mutation, pre-rollback) storage, so the diff reflects exactly what an apply would yield.
        wouldBe = await this.gatherConfigSnapshot();
      } catch (e) {
        mutationError = e;
      }
      // ROLL BACK unconditionally (even if the mutation threw, so a partial write is undone): restore every
      // checkpointed key to its prior value, and delete any key the mutation introduced that was not in the
      // checkpoint. This is a full-keyspace restore, so a multi-key mutation (e.g. a downpipe upsert that
      // also clears an alert cooldown) is undone completely. Enumerate the post-mutation keyspace with the
      // SAME paginated full-prefix scan (not a bare list(), which would page-truncate and so miss deleting
      // added keys past the page on a large keyspace, finding engine-src-040-02).
      // G105: if the rollback ITSELF faults (a storage error part-way through the restore), the dry run has
      // left REAL, unattributed writes behind: a proposal that was never approved has half-applied itself,
      // and the only statement of that was the exception the operator's browser rendered. Record the class
      // (never the key or the value) and re-throw unchanged, so the caller still fails loud. A half-applied
      // dry run is strictly more serious than the validation rejection it may have displaced, so it takes
      // precedence over mutationError -- which is the behaviour the `finally` had, now stated explicitly.
      try {
        const after = await this.listAllByPrefix<unknown>("");
        for (const k of after.keys()) {
          if (!checkpoint.has(k)) await this.state.storage.delete(k);
        }
        for (const [k, v] of checkpoint) await this.state.storage.put(k, v);
      } catch (e) {
        await recordStorageAnomaly(this.state.storage, "dryrun-rollback-failed");
        throw e;
      }
      // Restore the alarm to its pre-dry-run state (it is not a storage key, so the keyspace restore above
      // does not cover it): a downpipe upsert/delete re-arms it via rearmAlarm, which a mere proposal must
      // not leave behind. Reset to the captured value, or delete it if none was set before.
      const alarmAfter = await this.state.storage.getAlarm();
      if (alarmBefore === null) {
        if (alarmAfter !== null) await this.state.storage.deleteAlarm();
      } else if (alarmAfter !== alarmBefore) {
        await this.state.storage.setAlarm(alarmBefore);
      }
      // The rollback is complete, so the mutation's own rejection can now propagate exactly as it always did.
      if (mutationError !== undefined) throw mutationError;
      return wouldBe as ConfigSnapshot;
    }

    // proposeConfigMutation is the entry point every gated config-mutation route calls (in place of calling
    // the mutation method directly). It reads the gate flag and BRANCHES:
    //  - gate OFF (default): apply INLINE via applyConfigMutation and return { applied: true, result }, so
    //    the route's response and behaviour are byte-identical to before (the caller auto-snapshots after,
    //    exactly as today). No pending record is created.
    //  - gate ON: VALIDATE via dryRunConfigMutation (rejects a bad/unauthorised request at propose time, the
    //    method's own throw surfaces as a 400), RE-CHECK the proposer cannot be the bare-token break-glass
    //    (dual control needs an attributable maker), compute the plain-English diff (current -> would-be) and
    //    the content hash bound to the current head, store a PENDING change, audit the propose with the
    //    proposer as actor, and return { applied: false, pending } so the route answers 202 + the id.
    // The proposer authority is ALREADY enforced by dryRunConfigMutation (it runs the real validated method
    // as the proposer, which re-checks the proposer's capability + the no-escalation ceiling), so a proposer
    // cannot queue a change granting capabilities they lack.
    async proposeConfigMutation(
      kind: ConfigChangeKind,
      params: unknown,
      caller: MutationCaller | null,
    ): Promise<
      | { applied: true; result: unknown }
      | { applied: false; pending: PendingConfigChange }
    > {
      // Resolve the caller's LIVE effective capability set from the DO's OWN tables and run the mutation AS a
      // MutationCaller carrying it (F6). For a CUSTOM-ROLE proposer this is what lets the by-role re-checks
      // (notify.config / expiry.config) honour the capability they legitimately hold instead of refusing them
      // on their "viewer" built-in floor; for a built-in caller capabilitiesOfResolved returns the built-in
      // set, so callerHolds behaves exactly as can(role, cap) and authorisation is unchanged. It is the
      // caller's OWN set, never widened: a proposer still cannot drive a change beyond their resolved ceiling.
      const authoredCaller = await this.withResolvedCaps(caller);
      // Gate ON when the toggle is on OR this mutation would MINT AN APPROVER-CAPABLE identity (a role-set that
      // confers roles.write: owner or access-admin) while a SECOND owner already exists -- the config-stream
      // sibling of the dest/IdP high-blast auto-gate. This closes the puppet-owner laundering path: a lone
      // compromised owner cannot inline-create its OWN colluding approver to then self-approve a high-blast op.
      const gateOn = (await this.getRequireConfigApproval()) || (await this.autoGateOwnerMint(kind, params, caller));
      if (!gateOn) {
        // Gate OFF: inline apply, byte-identical to the prior path. The route auto-snapshots after.
        const result = await this.applyConfigMutation(kind, params, authoredCaller);
        return { applied: true, result };
      }
      // Gate ON. The would-be snapshot doubles as propose-time validation: dryRunConfigMutation runs the real
      // validated mutation as the proposer and rolls it back, so a bad or unauthorised (proposer-ceiling)
      // request THROWS here and the route returns a 400 (NOT a deferred pending), and a clean run yields the
      // posture an apply would produce for the diff.
      const wouldBe = await this.dryRunConfigMutation(kind, params, authoredCaller);
      // Dual control needs an attributable maker: the bare-token break-glass has no email, so it cannot
      // PROPOSE a change (it could otherwise queue a change only it could not then approve). It refuses here,
      // matching the restore-request rule. (The break-glass owner can still toggle the gate OFF immediately.)
      const proposedBy = caller?.email ? caller.email : null;
      if (proposedBy === null) {
        throw new Error("dual control requires an attributable identity; the bare-token fallback cannot propose a config change");
      }
      // The proposer's STABLE subject AT PROPOSE TIME, bound into the hash alongside their email + groups
      // (ASVS V10.3.3 / V10.5.2): the apply re-resolves the proposer's authority by this immutable subject
      // against the LIVE role table, so a stored-record tamper of the actor identity (swapping in a more
      // privileged proposer) is caught at approve by the same recompute that catches a params tamper. An
      // attributable proposer always carries a subject (a subjectless caller is the bare-token break-glass,
      // refused above), so this is non-null on any queued record.
      const proposedBySubject = caller ? caller.subject : null;
      // The proposer's propose-time groups are bound into the hash alongside their email + subject (F4), so a
      // stored-record tamper of the actor identity (swapping in a more privileged proposer the apply would
      // re-resolve authority from) is caught at approve by the same recompute that catches a params tamper.
      const proposedByGroups = caller ? caller.groups : [];
      const current = await this.gatherConfigSnapshot();
      const diff: PendingChangeLine[] = diffConfig(current, wouldBe).map((c) => ({ kind: c.kind, area: c.area, text: c.text }));
      const base = await this.headVersionRef();
      const contentHash = await changeContentHash(kind, params, proposedBy, proposedBySubject, proposedByGroups, base.id, base.hash);
      const now = Date.now();
      const id = newULID(now);
      const record: PendingConfigChange = {
        id,
        kind,
        params,
        proposedBy,
        // The proposer's STABLE subject AT PROPOSE TIME (the role table's authorisation key); the apply
        // re-resolves their LIVE authority from it, so a demoted/revoked proposer is caught and a recycled
        // email never inherits their authority. BOUND into contentHash above (F4), so a stored-record tamper
        // of it is caught at approve by the recompute.
        proposedBySubject,
        // The proposer's verified groups AT PROPOSE TIME, so the apply re-resolves their authority from subject
        // (live role table) + these groups: a group-derived proposer keeps the authority they presented, and
        // cannot gain groups. The SAME value bound into contentHash above (F4), so a tamper of the stored
        // groups is caught at approve by the recompute (the apply re-resolves authority from this field, so
        // it is decision-relevant and must be integrity-bound).
        proposedByGroups,
        // The edge address THIS propose request arrived from (G346). The approve-time replay runs as the proposer
        // and appends a human-attributed audit row; without this it would carry sourceIp null, and the engine
        // would count its own governed replay as a capture failure. Captured here because here is where the
        // request actually is; carried on the record because the approve happens in another request entirely.
        proposedBySourceIp: caller?.sourceIp ?? null,
        proposedAt: nowMillisISO(),
        baseVersionId: base.id,
        baseVersionHash: base.hash,
        diff,
        contentHash,
        status: "pending",
      };
      await this.state.storage.put(changeKey(id), record);
      await this.appendAudit({
        actorEmail: proposedBy,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-change-propose",
        outcome: "success",
        target: { kind: "configchange", id, changeKind: kind },
      });
      return { applied: false, pending: record };
    }

    // approveChange is the second-identity approval. It enforces, ALL inside one read-modify-write so the
    // decision is atomic with the apply:
    //   (a) the approver holds the SAME write capability the original mutation requires (re-resolved live
    //       from the DO's own tables, never a forwarded set);
    //   (b) maker != checker: the approver email differs from proposedBy (a self-approval is refused even
    //       with the capability), and the bare-token fallback (no email) cannot approve;
    //   (c) NO STALE/SUPERSEDED apply: the record still matches its contentHash AND the config-history head
    //       it was computed against has not moved. The hash is recomputed from the stored kind+params+base;
    //       a mismatch (tampered params) is refused. If the base moved, the change is marked SUPERSEDED and
    //       refused (the diff the approver reviewed is stale; a re-proposal is required).
    // On a clean approve it REPLAYS the SAME validated mutation via applyConfigMutation AS THE PROPOSER
    // (re-resolved live), so the apply re-checks the proposer's ceiling at apply time and uses the one apply
    // code path; that replay auto-snapshots into config history. The pending record is then marked applied
    // (single use) with the approver recorded, and a config-change-approve event records BOTH actors (the
    // approver as the audit actor + approverEmail on the target; the replayed mutation's own audit event
    // records the proposer as ITS actor, so the pair captures maker AND checker).
    async approveChange(
      req: { id?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<PendingConfigChange> {
      if (typeof req.id !== "string" || req.id.length === 0) throw new Error("id required");
      const record = (await this.state.storage.get<PendingConfigChange>(changeKey(req.id))) ?? null;
      if (record === null) throw new Error("no such change");
      // Defensive: a tampered stored kind that is not a known change kind can never be replayed.
      if (!isConfigChangeKind(record.kind)) throw new Error("the change has an unknown kind and cannot be applied");
      // (a)+(b): re-resolve the approver's effective authority from the DO's own tables, then run the pure
      // maker != checker / state / capability gate. The capability is the SAME one the original mutation
      // requires (CHANGE_WRITE_CAPABILITY[kind]).
      const approver = await this.roleForCaller(caller);
      const approverCaps = this.capabilitiesOfResolved(approver);
      const checker = caller?.email ? caller.email : null;
      // The checker's STABLE subject is the primary maker != checker axis (ASVS V10.3.3); the email is
      // the belt-and-suspenders floor. normaliseSubject mirrors how roleForCaller keys authority.
      const checkerSubject = caller ? this.normaliseSubject(caller.subject) : null;
      const verdict = canApproveChange(record, checker, checkerSubject, approverCaps.has(CHANGE_WRITE_CAPABILITY[record.kind]));
      if (!verdict.ok) {
        // G182: the reason, not just the refusal. "The console demands an approval I already gave" is a
        // terminal-state; "cannot approve your own change" is a self-approval; a superseded record is a
        // base-moved. All three used to record ONE indistinguishable guard-refused row, or nothing at all.
        await recordGovernanceRefusal(this.state.storage, "change-approve", verdict.reasonCode);
        throw new Error(verdict.reason);
      }
      // An owner-conferring change (role-set -> owner) needs an OWNER approver, not merely a roles.write holder:
      // an access-admin (which holds roles.write) must not be able to approve making someone an Owner -- that is
      // owner escalation via the approval path, and it is the access-admin hop the owner-mint auto-gate
      // (autoGateOwnerMint) would otherwise leave open in the puppet-owner laundering path. The proposer's own
      // owner ceiling is still re-checked at apply (setRole's requireNotOwnerEscalation); this is the checker side.
      if (this.isOwnerConferringRoleSet(record.kind, record.params) && approver.role !== "owner") {
        throw new Error("cannot approve: only an Owner may approve a change that grants the Owner role");
      }
      // (c): no stale/superseded apply. Recompute the binding hash over the stored kind+params+PROPOSER
      // IDENTITY+base; a mismatch means the stored params, the proposer identity (email/subject/groups the
      // apply re-resolves authority from, F4), or the base were tampered. The proposedBySubject + proposedByGroups
      // fed here are the SAME fields the replay below resolves authority against, so an actor-identity tamper
      // cannot pass this check yet drive a different (more privileged) replay. Then re-read the live head: if it
      // moved since the proposal, the reviewed diff is stale -> mark superseded and refuse (require re-proposal).
      const recomputed = await changeContentHash(
        record.kind,
        record.params,
        record.proposedBy,
        record.proposedBySubject ?? null,
        Array.isArray(record.proposedByGroups) ? record.proposedByGroups : [],
        record.baseVersionId,
        record.baseVersionHash,
      );
      if (recomputed !== record.contentHash) {
        // G034: a stored-record TAMPER is the most security-significant thing this machine can detect, and it
        // was seen ONLY by the approver's browser. Counted as its own closed class, so it can never be
        // confused with an ordinary guard refusal.
        await recordGovernanceFault(this.state.storage, "change-approve", "integrity-failed");
        await this.annotateChangeAttempt(record.id, "integrity-failed");
        throw new Error("the change record failed its integrity check and cannot be applied");
      }
      // CONCURRENCY GUARD (mirrors approveOwnerAction in scheduler-do-dual-control.ts; asymmetric with
      // rejectChange / proposeConfigMutation, which need no such guard). The OUTER checks above (record exists,
      // known kind, canApproveChange verdict, contentHash integrity) are only a FAST FAIL; they are NOT enough on
      // their own. Two concurrent DISTINCT-approver approvals of the SAME pending change can both pass them and
      // both reach the apply, because the config-history HEAD only moves at autoSnapshotConfig (which runs AFTER
      // applyConfigMutation, and across the changeContentHash / buildConfigVersion crypto awaits), so the
      // baseMoved guard alone leaves a DOUBLE-APPLY window: both approvals read the same unmoved head, both pass
      // baseMoved, and both apply. For a NON-IDEMPOTENT create-with-generated-id kind (notify-channel-set /
      // notify-rule-set, where addNotifyChannel / addNotifyRule mint a FRESH id per apply) that window creates
      // TWO channels / rules. So the irreversible APPLY runs inside blockConcurrencyWhile, which RE-READS the
      // record fresh and, INSIDE the critical section, RE-ASSERTS the approve verdict (status still pending) and
      // RE-VERIFIES integrity before applying. A losing concurrent approve finds the record no longer pending
      // (a winner already flipped it to applied / superseded) and canApproveChange refuses it (single use), so
      // the apply runs EXACTLY ONCE. (Under the offline validator blockConcurrencyWhile runs fn() directly,
      // because the validator drives the DO serially; the true concurrent input-gate race needs a workerd test.)
      // AUTH-46 (extended to the config-change path): every FORESEEABLE refusal inside blockConcurrencyWhile
      // returns a {ok:false,error} sentinel rather than throwing, exactly as approveOwnerAction does. A throw
      // escaping the guard RESETS the Durable Object (wiping in-memory scheduler state) and surfaces as a 500,
      // when each of these -- a concurrent-approve loser, a superseded/base-moved change, an integrity mismatch,
      // a demoted-proposer replay refusal -- is an ordinary no-write refusal that should be a clean 400/403 with
      // the DO intact. The sentinel is re-thrown OUTSIDE the guard, so the caller-visible mapping is unchanged.
      const outcome = await this.blockConcurrencyWhile(async (): Promise<{ ok: true; record: PendingConfigChange } | { ok: false; error: Error }> => {
        // RE-READ fresh inside the gate: a concurrent winner may have already flipped status to applied/superseded.
        const fresh = (await this.state.storage.get<PendingConfigChange>(changeKey(record.id))) ?? null;
        if (fresh === null) return { ok: false, error: new Error("no such change") };
        if (!isConfigChangeKind(fresh.kind)) return { ok: false, error: new Error("the change has an unknown kind and cannot be applied") };
        // RE-ASSERT the FULL approve verdict (status still pending, maker != checker on the subject + email axes,
        // approver still holds the write cap) against the FRESH record. A concurrent winner already marked it
        // applied, so canApproveChange refuses the loser ("the change was already applied") -> single use. This
        // is the line that closes the double-apply window the baseMoved guard alone leaves open.
        const innerVerdict = canApproveChange(fresh, checker, checkerSubject, approverCaps.has(CHANGE_WRITE_CAPABILITY[fresh.kind]));
        if (!innerVerdict.ok) {
          // The CONCURRENT-APPLY loser. A second approver racing the first is refused here with "the change was
          // already applied", which to that operator is indistinguishable from a broken approval. Recorded as
          // the apply-stage terminal-state it is.
          await recordGovernanceRefusal(this.state.storage, "change-apply", innerVerdict.reasonCode);
          return { ok: false, error: new Error(innerVerdict.reason) };
        }
        // RE-VERIFY integrity against the FRESH record (the same recompute as the outer fast-fail, over the stored
        // kind + params + proposer identity + base), so a tamper landing between the outer read and here is caught.
        const innerHash = await changeContentHash(
          fresh.kind,
          fresh.params,
          fresh.proposedBy,
          fresh.proposedBySubject ?? null,
          Array.isArray(fresh.proposedByGroups) ? fresh.proposedByGroups : [],
          fresh.baseVersionId,
          fresh.baseVersionHash,
        );
        if (innerHash !== fresh.contentHash) {
          await recordGovernanceRefusal(this.state.storage, "change-apply", "hash-mismatch");
          return { ok: false, error: new Error("the change record failed its integrity check and cannot be applied") };
        }
        const liveHead = await this.headVersionRef();
        if (baseMoved(fresh, liveHead.id, liveHead.hash)) {
          // The approved change is superseded because the config head moved under the approver. From the
          // console this reads as "my approved change refuses to apply", which is exactly the ticket.
          await recordGovernanceRefusal(this.state.storage, "change-apply", "base-moved");
          fresh.status = "superseded";
          fresh.supersededAt = nowMillisISO();
          // TERMINAL 1 of 3. A superseded change is the one an operator is likeliest to forget: it was
          // approved, it refused, and it is never coming back, so its submitted credential would otherwise
          // sit in storage for the life of the account. Scrubbed in THIS put, not a later one.
          this.scrubSpentChangeParams(fresh);
          await this.state.storage.put(changeKey(fresh.id), fresh);
          await this.appendAudit({
            actorEmail: checker,
            actorMethod: caller ? caller.method : "access",
            sourceIp: caller?.sourceIp ?? null,
            action: "config-change-supersede",
            outcome: "success",
            target: { kind: "configchange", id: fresh.id, changeKind: fresh.kind },
          });
          return { ok: false, error: new Error("the configuration changed since this change was proposed; it is superseded, please raise it again") };
        }
        // APPLY via the SINGLE validated path, AS THE PROPOSER. The replay caller carries the proposer's email,
        // their STABLE SUBJECT, and their PROPOSE-TIME groups; the DO mutation methods then RE-RESOLVE the
        // proposer's authority from their SUBJECT against the LIVE role table (roleForCaller /
        // requireCapabilityResolved) plus those groups, so the apply enforces the proposer's CEILING at apply
        // time and cannot escalate:
        //   - a proposer who LOST their grant (or whose grant was narrowed) between propose and approve is caught,
        //     because the role table is read LIVE at apply by their subject (their stale authority is gone);
        //   - a recycled email cannot inherit the proposer's authority (the lookup keys on the immutable subject,
        //     not the mutable email, ASVS V10.3.3 / V10.5.2);
        //   - a group-derived proposer keeps exactly the authority they PRESENTED when proposing (the groups
        //     are bounded to the propose-time set; they cannot gain groups they never held);
        //   - replayCaller.role is set to the proposer's live subject-resolved role for the few methods that read
        //     caller.role directly (notify/posture/expiry/webhook), so those too see the proposer's current
        //     ceiling; AND the proposer's live-resolved CAPABILITY SET is forwarded (F6) so a CUSTOM-ROLE
        //     proposer who legitimately holds notify.config / expiry.config has their queued change APPLY (the
        //     by-role re-checks consult the set via callerHolds) instead of being refused on their viewer floor.
        //     The set is the proposer's OWN live authority (re-resolved here, bounded by requireGrantWithinAuthority
        //     and the live ceiling), never widened and never propose-time-frozen.
        // The replay runs the SAME validation + no-escalation (requireGrantWithinAuthority) + last-Owner guards
        // a gate-off apply runs, and auto-snapshots into config history (recording the proposer as the author).
        // sourceIp is the PROPOSE-TIME address, carried on the record (G346). The replayed mutation audits itself
        // as the proposer -- an attributed HUMAN actor -- so a null IP here is not a missing capture, it is a
        // DELIBERATE DROP of an address the engine had, and the audit-human-event-missing-source-ip counter read
        // it as a live capture fault: every approved change under dual control bumped a fault counter on a
        // healthy engine, at the customers who had turned the gate on. The propose row and the replay row now
        // carry the same address, which is the truth: it is the proposer's request, running late.
        // replay: true marks this as a system replay of the proposer's original request, not a fresh caller
        // action, so resolveStoredIdentityAuthority's bind-on-first-auth logic does not bind a pending grant
        // to the replay identity, and a departed proposer's re-used email cannot inherit a different person's
        // authority. It also carries the connection-liveness axis, so a proposer whose IdP connection was
        // deleted or disabled no longer has their queued change applied. The flag rides on the object, so it
        // reaches the downstream requireCapabilityResolved re-checks inside the replayed mutation too, not
        // just the call below.
        const replayCaller = {
          method: "access" as AuthMethod,
          email: fresh.proposedBy,
          subject: fresh.proposedBySubject ?? null,
          groups: Array.isArray(fresh.proposedByGroups) ? fresh.proposedByGroups : [],
          sourceIp: fresh.proposedBySourceIp ?? null,
          replay: true as const,
        };
        const proposerAuthority = await this.roleForCaller(replayCaller);
        // THE APPLY-TIME MAKER FLOOR, and it is here rather than in the dispatched methods because for three
        // of the eighteen kinds there is no method to put it in. applyConfigMutation's own account of this
        // moment says the per-method capability re-check runs "because they live in the methods this
        // delegates to", and for fifteen kinds it does: setRole and its people/access-policy siblings call
        // requireCapabilityResolved, the notify/posture/expiry writes call requireNotifyConfig /
        // requirePostureRiskAccept / requireCapability, and all of them read the LIVE-resolved authority this
        // line just computed. The other three ask nothing at all. addDownpipe re-checks only the NARROWER
        // scheduledtest.config, and only when the cadence actually changes, so downpipe.write is never asked
        // for. removeDownpipe is dispatched with NO CALLER ARGUMENT. setCfConfigMode is dispatched with no
        // caller either, under a comment saying the capability "is enforced by the router gate on POST and
        // re-checked at approve via CHANGE_WRITE_CAPABILITY" -- which is true of the CHECKER (canApproveChange
        // takes approverCaps) and silent about the MAKER. The identity binding, the bind-on-first-auth
        // suppression, and the connection-liveness axis together ensure the maker's live authority is what
        // gates the replayed apply.
        //
        // Reachable by two routes that leave no trace in the config-history snapshot: a JIT EXPIRY (a
        // clock event; nothing is written when a time-boxed grant lapses) and an IdP connection being
        // deleted or disabled. Without the maker floor above, either route could let a downpipe create,
        // downpipe delete or capture-mode change apply for a principal who no longer holds the capability.
        //
        // IT SUSPENDS RATHER THAN VOIDS, like every other axis of the spend-time binding: re-grant the proposer
        // and the SAME queued change applies with no fresh ceremony. And the refusal is recorded as
        // maker-authority-lapsed rather than the generic guard-refused, because the remedy is specific and
        // counter-intuitive: a second approval does not help, since the axis that failed is the MAKER's; the
        // change must be proposed again by somebody who still holds the capability.
        if (!this.capabilitiesOfResolved(proposerAuthority).has(CHANGE_WRITE_CAPABILITY[fresh.kind])) {
          await recordGovernanceRefusal(this.state.storage, "change-apply", "maker-authority-lapsed");
          return {
            ok: false,
            error: new AuthError("the identity that proposed this change no longer holds the capability it requires, so it cannot be applied; somebody who still holds it must propose it again"),
          };
        }
        // A FORESEEABLE apply-time refusal from the replayed mutation -- a proposer demoted between propose and
        // approve (AuthError -> 403), a last-Owner guard or a no-escalation refusal (plain Error -> 400) -- must
        // not escape blockConcurrencyWhile and reset the DO. Sentinel it (nothing below runs: no snapshot, no
        // status flip, no approve audit) and re-throw OUTSIDE the guard. An UNEXPECTED fault from the post-apply
        // commit (snapshot/put/audit below) still propagates uncaught, exactly as before this change.
        try {
          await this.applyConfigMutation(fresh.kind, fresh.params, {
            ...replayCaller,
            role: proposerAuthority.role,
            ...(proposerAuthority.capabilities !== undefined ? { capabilities: proposerAuthority.capabilities } : {}),
          });
        } catch (e) {
          return { ok: false, error: e instanceof Error ? e : new Error(String(e)) };
        }
        await this.autoSnapshotConfig(fresh.proposedBy);
        fresh.status = "applied";
        fresh.approvedBy = checker!;
        fresh.approvedAt = nowMillisISO();
        // TERMINAL 2 of 3, and it runs AFTER applyConfigMutation above, which is the whole reason the scrub
        // is safe here: the replay has already committed the channel with the credential in it, so what is
        // stripped is a second copy the live config now holds properly. The record survives as the forensic
        // account of what a second identity approved.
        this.scrubSpentChangeParams(fresh);
        await this.state.storage.put(changeKey(fresh.id), fresh);
        await this.appendAudit({
          actorEmail: checker,
          actorMethod: caller ? caller.method : "access",
          sourceIp: caller?.sourceIp ?? null,
          action: "config-change-approve",
          outcome: "success",
          target: { kind: "configchange", id: fresh.id, changeKind: fresh.kind, approverEmail: checker! },
        });
        return { ok: true, record: fresh };
      });
      // Surface any in-guard refusal OUTSIDE the guard: an AuthError still maps to 403 and a plain Error to 400
      // (the fetch() catch), byte-identical to the prior direct throw's mapping, just without resetting the DO.
      // G034: this is the ONE place every failed apply attempt passes through, so it is the one place to record
      // it. classifyGovernanceOutcome reads the refusal ONLY to select a closed class and returns it: the
      // guard's operator-facing prose (which interpolates emails, ids and params) is never stored. The count
      // makes the RATE visible; the record annotation makes the pending change explain ITSELF in the inbox.
      if (!outcome.ok) {
        const cls = classifyGovernanceOutcome(outcome.error);
        await recordGovernanceFault(this.state.storage, "change-apply", cls);
        await this.annotateChangeAttempt(record.id, cls);
        throw outcome.error;
      }
      // The approve RESPONSE is a caller-facing echo like the listing, so it goes through the same
      // projection (the ML-04 rule the owner-action store settled: no caller-facing echo carries a
      // credential, whether the caller is listing the queue or arming one entry of it). By this point the
      // stored record has already been scrubbed anyway, so on the notify-channel-set path the two agree; the
      // projection is here so they still agree if the scrub is ever narrowed.
      return viewConfigChange(outcome.record);
    }

    // scrubSpentChangeParams strips the live delivery credential from a change that can never be replayed
    // again, IN PLACE on the object the caller is about to persist, so the scrub commits in the SAME
    // storage.put as the terminal status and there is no window where a spent record still holds it. It
    // returns whether anything was stripped, and stamps paramsScrubbedAt ONLY when something was
    // (scrubConfigChangeParams returns its input by reference otherwise), so the seventeen secret-free kinds
    // are never marked and the marker means exactly "this record's params can no longer reproduce its
    // contentHash". The caller decides WHEN; this only decides WHAT, and it refuses to act on a record that
    // is not terminal, so a future call site cannot strip a still-approvable change out from under its own
    // replay. There is no lazy sweep beside it, unlike the owner-action store: configchange has no clock, so
    // there is no population of records that lapse unvisited, and every route into a terminal status passes
    // through one of the three call sites below.
    scrubSpentChangeParams(record: PendingConfigChange): boolean {
      if (configChangeParamsScrubbed(record)) return false;
      if (!configChangeParamsSpent(record)) return false;
      const scrubbed = scrubConfigChangeParams(record.params);
      if (scrubbed === record.params) return false; // nothing secret to strip; leave the hash recomputable
      record.params = scrubbed;
      record.paramsScrubbedAt = nowMillisISO();
      return true;
    }

    // annotateChangeAttempt stamps the pending record with its LAST FAILED APPLY ATTEMPT (G034): a closed
    // outcome class + the time. It is BEST-EFFORT and never throws: an annotation must never turn a clean
    // refusal (a 400/403 the caller understands) into a 500. It re-reads the record so it cannot resurrect a
    // stale copy, and it writes ONLY the annotation field, so it can never disturb the record's status,
    // integrity hash or lifecycle.
    async annotateChangeAttempt(id: string, outcomeClass: string): Promise<void> {
      try {
        const rec = await this.state.storage.get<PendingConfigChange>(changeKey(id));
        if (rec === undefined) return;
        rec.lastAttempt = { at: nowMillisISO(), outcomeClass };
        await this.state.storage.put(changeKey(id), rec);
      } catch {
        /* best-effort: the refusal itself must still surface cleanly */
      }
    }

    // rejectChange discards a pending change (audited). Like the restore reject, it does NOT require
    // maker != checker (the proposer may withdraw their own change), but it gates on the SAME write
    // capability the change requires (re-resolved live), so only someone who COULD have made the change may
    // reject it, and it must not overwrite a terminal state. It records a config-change-reject event.
    async rejectChange(
      req: { id?: string },
      caller: { method: AuthMethod; email: string | null; subject: string | null; role: Role; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<PendingConfigChange> {
      if (typeof req.id !== "string" || req.id.length === 0) throw new Error("id required");
      const record = (await this.state.storage.get<PendingConfigChange>(changeKey(req.id))) ?? null;
      if (record === null) throw new Error("no such change");
      if (!isConfigChangeKind(record.kind)) throw new Error("the change has an unknown kind");
      const rejecter = await this.roleForCaller(caller);
      const rejecterCaps = this.capabilitiesOfResolved(rejecter);
      if (!rejecterCaps.has(CHANGE_WRITE_CAPABILITY[record.kind])) {
        throw new AuthError(`forbidden: ${CHANGE_WRITE_CAPABILITY[record.kind]} capability required to reject this change`);
      }
      const verdict = canRejectChange(record);
      if (!verdict.ok) {
        await recordGovernanceRefusal(this.state.storage, "change-approve", verdict.reasonCode);
        throw new Error(verdict.reason);
      }
      record.status = "rejected";
      // TERMINAL 3 of 3, and the sharpest human case: an operator who realises they pasted the wrong webhook
      // url withdraws the change, and until now the withdrawal left the url in storage indefinitely.
      this.scrubSpentChangeParams(record);
      await this.state.storage.put(changeKey(record.id), record);
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-change-reject",
        outcome: "success",
        target: { kind: "configchange", id: record.id, changeKind: record.kind },
      });
      // The reject RESPONSE, the third caller-facing echo, projected for the same reason as the other two.
      return viewConfigChange(record);
    }

    // listPendingChanges serves GET /config/changes: the PENDING change requests (newest-first), so the
    // console can render the approver inbox. The router gates it on downpipe.read (the config read cap), so
    // any caller that can view the config sees the queue. It returns only records still in the pending
    // status (a terminal applied/rejected/superseded record drops out of the inbox); each carries its
    // plain-English diff for the approver to review, escaped on render.
    //
    // EVERY RECORD GOES THROUGH viewConfigChange, and the sentence this replaced is why it has to. It read
    // "the records are redaction-safe (params are the customer's own non-secret config)", which is true of
    // seventeen kinds and false of notify-channel-set, whose params are the submitted channel and therefore
    // hold the delivery url, the PagerDuty routing key or the JSM/ServiceNow api key. This route is gated on
    // downpipe.read while the channels route the same value is served from is gated on notify.config, so the
    // sentence was not merely inaccurate: it was the reason nobody noticed that a viewer, a restore-operator
    // and an access-admin could read a credential here that they are refused there. The projection is a pure
    // copy and the stored record is untouched, so the approve-time replay and its hash recompute are
    // unaffected.
    async listPendingChanges(): Promise<PendingConfigChange[]> {
      const map = await this.state.storage.list<PendingConfigChange>({ prefix: CHANGE_PREFIX });
      return [...map.values()]
        .filter((r) => r.status === "pending")
        .sort((a, b) => (a.proposedAt < b.proposedAt ? 1 : a.proposedAt > b.proposedAt ? -1 : 0))
        .map((r) => viewConfigChange(r));
    }

    // getOrgPolicyView serves GET /config/approval-policy: the current governance-policy flags for the console.
    // Any authenticated caller that can read the config may see whether the dual-control gate is on AND whether
    // the OWNER-OPT-IN change-number policy is on (neither is a secret; they shape whether a config write queues
    // and whether a change-controlled action needs a change reference). The router gates it on downpipe.read.
    async getOrgPolicyView(): Promise<{ requireRestoreApproval: boolean; requireConfigApproval: boolean; requireChangeNumber: boolean; notifyNewSignInContext: boolean }> {
      return { requireRestoreApproval: await this.getRequireRestoreApproval(), requireConfigApproval: await this.getRequireConfigApproval(), requireChangeNumber: await this.getRequireChangeNumber(), notifyNewSignInContext: await this.getNotifyNewSignInContext() };
    }
  };
}
