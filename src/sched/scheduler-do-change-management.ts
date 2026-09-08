// Change management (OWNER OPT-IN "Require Change Number", default OFF). This mixin is the Durable Object
// home of the feature: the requireChangeNumber org-policy flag (read + owner-only set), the single
// ENFORCEMENT chokepoint every change-controlled action funnels through (enforceChangeControl), the
// change-recorded audit append, the emergency-change marker the compliance posture check reads, and the
// gather the change-requests report reads. It is a process / compliance control, NOT a security control:
// the change reference is non-authority operator metadata (no gate reads it), recorded as the operator's
// own attestation, the same redaction class as the restore reason.
//
// WHY A SEPARATE MIXIN. The owner-action dual-control gate (scheduler-do-dual-control.ts) and the restore
// apply (router-restore.ts) both need ONE place to ask "does this account require a change number, and if
// so is a valid reference attached?" and to record the CR ledger entry, WITHOUT perturbing the
// security-critical dual-control actionHash binding (the CR is an additive, separate change-recorded event,
// never folded into the binding). So this is a small leaf the gate sites consult, mirroring the
// OrgPolicyMixin / DualControlMixin discipline: the pure validation lives in change-ref.ts; this DO is the
// single storage authority that reads the policy, appends the audit and maintains the emergency marker.
//
// Node 25 strip-types compatible: no enums, no parameter properties, explicit declarations only.
// TypeScript 6 + exactOptionalPropertyTypes: every optional key is included only when it carries a value.

import type { AuditEvent } from "../admin/audit.ts";
import { type ChangeRef, evaluateChangeControl } from "../admin/change-ref.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { POSTURE_ACCEPT_PREFIX } from "../admin/posture.ts";
import { EMERGENCY_CHANGE_CHECK_ID } from "../admin/posture-checks.ts";
import { recordGovernanceRefusal, recordRefusal, recordStorageAnomaly } from "./sched-fault-ledger.ts";
import { AuthError, CHANGE_CONTROL_REFUSAL_KEY, type ChangeControlRefusalState, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

// EMERGENCY_CHANGE_MARKER_KEY holds the cumulative emergency-change tally the compliance posture check
// reads: how many Emergency Changes have been recorded and when the last one was. It is a small
// redaction-safe counter (an integer + a timestamp), never an entry or a value; the durable per-change
// record lives in the audit log + the change-requests report.
const EMERGENCY_CHANGE_MARKER_KEY = "change-emergency-marker";

// EmergencyChangeMarker is the stored shape; both fields read their safe default (0 / null) when absent.
export interface EmergencyChangeMarker {
  count: number;
  lastAt: string | null;
}

export function ChangeManagementMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // getRequireChangeNumber reads the OWNER-OPT-IN policy flag (default OFF when the policy record or the
    // field is absent), so a tenant that never enabled it behaves byte-identically to before. It is the single
    // read point enforceChangeControl + the policy view consult.
    async getRequireChangeNumber(): Promise<boolean> {
      return (await this.readOrgPolicy()).requireChangeNumber === true;
    }

    // setRequireChangeNumber APPLIES the policy flag. OWNER-ONLY: the DO RE-RESOLVES the caller's role from its
    // own tables (roleForCaller) and requires role === "owner" (the owner-token break-glass resolves to owner,
    // so it can always toggle), so a router bug cannot let a non-owner flip it. It MERGE-writes (the
    // dual-control gate + the bootstrap/retire latches are untouched) and records a config-policy-change audit
    // event. Unlike the dual-control gate this is NOT dual-control-gated to disarm: it is a process/compliance
    // control, not a security control (turning it off enables no data theft), so a lone owner may toggle it,
    // applied immediately; the change is audited. THROWS -> 403 on a non-owner (the router gates owner first;
    // this is defence in depth), -> 400 on a non-boolean value.
    async setRequireChangeNumber(
      req: { requireChangeNumber?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ requireChangeNumber: boolean }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the change-management policy");
      if (typeof req.requireChangeNumber !== "boolean") throw new Error("requireChangeNumber must be a boolean");
      await this.writeOrgPolicy({ requireChangeNumber: req.requireChangeNumber });
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "config-policy-change",
        outcome: "success",
        // Field-less access-policy target (redaction-safe): the trail records that a governance policy changed,
        // who changed it and when; the new boolean is the response, never the immutable log (matching the
        // config-approval discipline of never writing the value).
        target: { kind: "access-policy", policyName: "change-number", newValue: req.requireChangeNumber === true }, // G036: name the policy + the direction
      });
      return { requireChangeNumber: req.requireChangeNumber };
    }

    // enforceChangeControl is the SINGLE chokepoint every change-controlled action funnels through (the owner
    // actions via gatedOwnerAction / checkOwnerActionGate, and a restore apply via the router's enforce call).
    // When the policy is OFF it is a no-op (dormant, byte-identical to before). When ON it either records the
    // attached change reference as a change-recorded audit event, or THROWS (-> 400) so the action does NOT run.
    //   - the BARE-TOKEN break-glass (no attributable identity) is NEVER blocked: it is the all-or-nothing
    //     emergency escape (mirrors the dual-control bare-token exemption), so its action is recorded as an
    //     AUTOMATIC emergency change (honestly flagged, never silently exempt).
    //   - an attributable caller must supply a valid reference (a change number, or an Emergency Change + a
    //     justification): evaluateChangeControl decides, and an invalid/absent reference is refused with the
    //     actionable message the console surfaces verbatim.
    // The change-recorded event is recorded at the moment the action is INITIATED (before the gate branch / the
    // apply), so a queued or rejected action still has its CR raise on record; the action's own event (e.g.
    // dest-config-set, owner-action-propose, restore-apply) records the result separately.
    async enforceChangeControl(
      actionKind: string,
      caller: { method: AuthMethod; email: string | null; subject: string | null; sourceIp?: string | null; change?: ChangeRef | null } | null,
    ): Promise<void> {
      if (!(await this.getRequireChangeNumber())) return; // OFF: dormant.
      const method = caller ? caller.method : "token";
      if (method === "token") {
        // The break-glass escape: record as an automatic emergency, never block (no deadlock at bootstrap).
        await this.recordChange(actionKind, { number: null, emergency: true, reason: "performed via the break-glass admin token" }, caller);
        return;
      }
      const verdict = evaluateChangeControl(true, caller?.change ?? null);
      if (!verdict.ok) {
        // OBSERVE the refusal (change-number-required-refusal) WITHOUT touching the CR ledger: a refused
        // change-controlled action deliberately records NO change-recorded entry (the refusal is not a raised
        // CR -- a DELIBERATE, TESTED contract), so this bumps a SEPARATE diagnostic counter, never an audit
        // event, so the compliance/change-requests surfaces are byte-unchanged. Best-effort: a counter hiccup
        // is swallowed so it can never mask the refusal that MUST still throw and stop the action.
        await this.bumpChangeControlRefusal(actionKind);
        // G037: the tally keeps {count, lastAt, lastActionKind}, so "14 refusals" shows only the LAST action
        // kind and support cannot tell one operator hammering one action from a policy that is refusing the
        // whole account. The bounded ring keeps the SEQUENCE of refused action kinds (engine-set closed values,
        // never the operator's change number or the guard's reason prose).
        await recordRefusal(this.state.storage, "change-control", actionKind);
        // G182: the closed REASON, alongside the action kind. changeControlRefusals gives count + lastActionKind
        // and nothing about WHY, so "a change number is required" and "an emergency change requires a
        // justification" -- two different things for the operator to do -- were one undifferentiated tally.
        // The GARBLED and TRUNCATED cases cannot be seen from here (they are already a null by the time the
        // reference reaches this gate); they are classified at the Worker edge, into this same aggregate.
        const emergencyNoJustification = caller?.change?.emergency === true;
        await recordGovernanceRefusal(this.state.storage, "change-ref", emergencyNoJustification ? "change-ref-no-justification" : "change-ref-missing");
        throw new Error(verdict.reason); // -> 400: the action is refused, nothing runs.
      }
      // required=true + ok => a normalised reference; record it. (The null branch is unreachable here but kept
      // explicit so a future evaluateChangeControl change cannot silently skip the record.)
      if (verdict.change !== null) await this.recordChange(actionKind, verdict.change, caller);
    }

    // recordChange appends the change-recorded CR ledger entry and, for an emergency, bumps the emergency
    // marker. The audit target carries the action kind (engine-set), the emergency flag and the operator's
    // (already-bounded) number + reason; no secret can reach it. The actor is the change initiator.
    async recordChange(
      actionKind: string,
      change: ChangeRef,
      caller: { method: AuthMethod; email: string | null; subject: string | null; sourceIp?: string | null } | null,
    ): Promise<void> {
      await this.appendAudit({
        actorSubject: caller ? caller.subject : null,
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "token",
        sourceIp: caller?.sourceIp ?? null,
        action: "change-recorded",
        outcome: "success",
        target: { kind: "change", actionKind, emergency: change.emergency, changeNumber: change.number, reason: change.reason },
      });
      if (change.emergency) await this.bumpEmergencyMarker();
    }

    // bumpEmergencyMarker increments the cumulative emergency tally and stamps the time, AND invalidates any
    // prior acknowledgement of the emergency-change posture check: a risk-accept covered the emergencies known
    // when it was accepted, so a FRESH emergency must re-raise the compliance flag for re-review (correct ITIL
    // semantics). It deletes the risk-accept record for the check id if present; absent, the delete is a no-op.
    async bumpEmergencyMarker(): Promise<void> {
      const cur = await this.readEmergencyChangeMarker();
      await this.state.storage.put(EMERGENCY_CHANGE_MARKER_KEY, { count: cur.count + 1, lastAt: nowMillisISO() } satisfies EmergencyChangeMarker);
      await this.state.storage.delete(POSTURE_ACCEPT_PREFIX + EMERGENCY_CHANGE_CHECK_ID);
    }

    // readEmergencyChangeMarker returns the cumulative emergency tally for the compliance posture check
    // (defaulting to 0 / null when absent or malformed, the safe reading: no marker => no flag).
    async readEmergencyChangeMarker(): Promise<EmergencyChangeMarker> {
      const m = (await this.state.storage.get<{ count?: unknown; lastAt?: unknown }>(EMERGENCY_CHANGE_MARKER_KEY)) ?? null;
      const count = m !== null && typeof m.count === "number" && Number.isFinite(m.count) && m.count > 0 ? Math.floor(m.count) : 0;
      const lastAt = m !== null && typeof m.lastAt === "string" && m.lastAt.length > 0 ? m.lastAt : null;
      // G105: a marker that EXISTS but reads back malformed coerces to zero, which is the compliance posture
      // saying "no emergency changes were raised" about an account that raised them. The safe default is
      // right; the silence is not. Counted only when a record is present (absent = genuinely none raised).
      if (m !== null && count === 0) await recordStorageAnomaly(this.state.storage, "marker-corrupt-defaulted");
      return { count, lastAt };
    }

    // bumpChangeControlRefusal increments the OBSERVE-side refused-change tally (change-number-required-
    // refusal) and stamps the time + the refused action kind. It is DISTINCT from the CR ledger: it appends NO
    // change-recorded audit event (a refusal is not a raised CR, the contract validate-change-management
    // asserts), so it never perturbs the compliance posture, the change-requests report or the tamper chain.
    // The action kind is the closed engine-set label the change target already carries (bounded to 64 chars);
    // no operator free-text can reach it. Best-effort: any storage hiccup is swallowed so the refusal (which
    // MUST throw) is never masked by a bookkeeping fault.
    async bumpChangeControlRefusal(actionKind: string): Promise<void> {
      try {
        const cur = await this.getChangeControlRefusals();
        const rec: ChangeControlRefusalState = {
          count: cur.count + 1,
          lastAt: nowMillisISO(),
          ...(typeof actionKind === "string" && actionKind.length > 0 ? { lastActionKind: actionKind.slice(0, 64) } : {}),
        };
        await this.state.storage.put(CHANGE_CONTROL_REFUSAL_KEY, rec);
      } catch {
        /* observability only: never let a counter hiccup mask the refusal that must still throw */
      }
    }

    // getChangeControlRefusals reads the cumulative refused-change tally (defaulting to 0 / null when absent or
    // malformed, the safe reading: no record => no refusals). Closed shape only (a count, a timestamp, a closed
    // action kind), read by the support pack; it never returns an operator value.
    async getChangeControlRefusals(): Promise<ChangeControlRefusalState> {
      const m = (await this.state.storage.get<{ count?: unknown; lastAt?: unknown; lastActionKind?: unknown }>(CHANGE_CONTROL_REFUSAL_KEY)) ?? null;
      const count = m !== null && typeof m.count === "number" && Number.isFinite(m.count) && m.count > 0 ? Math.floor(m.count) : 0;
      // `lastAt` is gated on PARSING, not merely on being a non-empty string. The writer only ever stores
      // nowMillisISO(), so a value that does not parse did not come from the engine, and this method's own
      // contract two lines up says it never returns an operator value: an unparseable string returned verbatim
      // out of a corrupt record is exactly that. An unreadable instant reads as an absent one.
      const lastAtRaw = m !== null && typeof m.lastAt === "string" && m.lastAt.length > 0 ? m.lastAt : null;
      const lastAt = lastAtRaw !== null && !Number.isNaN(Date.parse(lastAtRaw)) ? lastAtRaw : null;
      const lastActionKind = m !== null && typeof m.lastActionKind === "string" && m.lastActionKind.length > 0 ? m.lastActionKind.slice(0, 64) : undefined;
      // G105: a marker that EXISTS but reads back malformed coerces to zero, the SAME coercion
      // readEmergencyChangeMarker performs thirty lines above and books. The safe default is right; the silence
      // is not, and here the silence is louder because the pack surfaces this block ONLY when count > 0 -- so a
      // corrupt tally and an account that has never refused a change produce a BYTE-IDENTICAL configIntegrity,
      // and the compliance answer "no change was ever refused for want of a change number" is asserted about an
      // account whose record of those refusals is gone. Counted only when a record is PRESENT (absent = none).
      const coerced = m !== null && count === 0;
      if (coerced) await recordStorageAnomaly(this.state.storage, "marker-corrupt-defaulted");
      // A COERCED record's other fields are DROPPED, not carried. They came out of the same record this line
      // has just declared unreadable, so "the last refusal was at T, on action K" would be asserted from
      // evidence that was rejected a statement earlier -- and lastActionKind is bounded in LENGTH but not to a
      // closed set, so on a corrupt record it is 64 arbitrary characters. The count is the safe default; the
      // qualifiers are not, and the coerced flag is what a reader needs instead.
      if (coerced) return { count, lastAt: null, coerced: true as const };
      return { count, lastAt, ...(lastActionKind !== undefined ? { lastActionKind } : {}) };
    }

    // gatherChangeRecordedEvents returns the change-recorded audit events (the CR ledger) for the
    // change-requests report. It reads the retained chain and filters to the one action; the report builder
    // (reports.ts) period-filters + projects to the redaction-safe rows. The events are already
    // redaction-safe; this carries no hash/seq concern (the builder drops the chain fields).
    async gatherChangeRecordedEvents(): Promise<AuditEvent[]> {
      const all = await this.listAuditEntries();
      return all.filter((e) => e.action === "change-recorded");
    }
  };
}
