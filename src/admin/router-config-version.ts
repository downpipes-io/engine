// router-config-version.ts -- the security-centre posture, the coverage/gap view, the config-as-a-source
// version history + diff, the opt-in dual-control change-control gate flag, and the owner-action inbox read.
// The posture.read / posture.riskaccept / access.policy / downpipe.read / keys.ceremony gate on each route
// runs inline per route.

import { callerHeaders, gate, jsonResponse, rateLimited } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";
import { routeDualControlDisarmAlert } from "./router-notify.ts";
import { computePostureViaDO } from "./router-posture.ts";

// handleConfigVersion dispatches the posture / coverage / config-version / approval-policy / owner-actions
// group. Returns the route's Response, or null when no case here matched (the hub falls through to the 404).
export async function handleConfigVersion(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, url, scheduler, caller, sub } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- security centre / posture (contract section 7) -------------------------------------------
    // GET /posture computes the posture report: the router builds the env-derived presence slice (it
    // holds env; the DO does not) plus the account auth posture and the beacon flag, hands them to the DO
    // which adds the state it owns and runs the pure computePosture, then ROUTES any regression the DO
    // detected as a posture-regression notification (fire-and-forget, fail-open). It gates on posture.read
    // (any authenticated role). The two writes gate on posture.riskaccept (owner) and forward the caller
    // so the DO re-checks (defence in depth). NO-CUSTODY: the report carries only redaction-safe checks.
    case "GET /posture": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      // The regression alert is handed the REQUEST'S OWN keep-alive rather than being dropped: this route
      // returns immediately after the computation, so a floating alert promise would otherwise die with the
      // context. Passing waitUntil keeps the read as fast as it was and the alert as durable as its siblings.
      const report = await computePostureViaDO(env, scheduler, caller, ctx.runtime?.waitUntil ? (task: Promise<unknown>) => ctx.runtime?.waitUntil?.(task) : undefined);
      return jsonResponse(report);
    }
    case "POST /posture/accept": {
      const denied = gate(caller, "posture.riskaccept");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Forward the body ({checkId, reason}) + caller so the DO re-checks posture.riskaccept, validates the
      // checkId is a known check, and records the audit event. A validation failure comes back as 400.
      return scheduler.fetch(doURL("/posture/accept"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /posture/unaccept": {
      const denied = gate(caller, "posture.riskaccept");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/posture/unaccept"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }

    // ---- coverage and gap detection (what is and is not backed up) --------------------------------
    // The reference inventory lives in the scheduler DO under a single key, stored as REFERENCE DATA
    // ONLY: it never grants data access and is kept structurally distinct from the backup bindings (a
    // downpipe still reaches a resource only through its own configured source). POST /coverage/inventory
    // gates on access.policy (access-admin/owner): submitting the account's resource inventory is an
    // access-policy-level act (it shapes what the posture view claims), so it sits behind the same gate
    // as the role table and the group mapping; the DO re-checks the forwarded caller (defence in depth).
    // GET /coverage gates on posture.read (any authenticated role), like GET /posture: it is the
    // customer's own redaction-safe coverage view. With no inventory stored the DO returns the honest
    // unknown shape (it never implies full coverage).
    case "POST /coverage/inventory": {
      const denied = gate(caller, "access.policy");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Forward the body + caller so the DO re-checks access.policy, validates + bounds the inventory,
      // and stores it as reference data. A validation failure comes back as 400 { error }.
      return scheduler.fetch(doURL("/coverage/inventory"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "GET /coverage": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/coverage"), { method: "GET", headers: callerHeaders(caller) });
    }

    // ---- config-as-a-source versioning (Phase 4, the DEFAULT self-contained layer) ----------------
    // downpipes versions its OWN governance configuration so an operator gets git-style history plus a
    // plain-English diff over their backup setup. PURELY ADDITIVE observability: a version is captured by
    // the DO AFTER a config mutation commits (auto-snapshot) or by the manual snapshot route here; nothing
    // here gates, blocks or alters how config is applied (an approval/deploy gate is a separate, later
    // item). The version records carry secrets BY NAME ONLY (the DO's snapshotConfig copies a closed
    // named-metadata set, never a secret value), so the whole surface is redaction-safe like GET /status.
    //
    // GATING. The three READS (history list, one version, the plain-English diff) gate on downpipe.read -
    // the SAME capability that lets a caller view the config (every built-in role holds it, from the
    // viewer floor up, so for the six built-ins this matches "any authenticated role may read the config";
    // a custom-role caller that lacks downpipe.read is correctly 403, never a looser path). The MANUAL
    // snapshot (POST /config/snapshot) is a config-policy act, so it gates on access.policy (access-admin/
    // owner), the owner/policy level, exactly like POST /coverage/inventory and the role/group writes; the
    // DO re-checks the forwarded caller (defence in depth) and records the requesting author. Each is wired
    // through gate()/authorise() exactly like the existing endpoints; none bypass the gate.
    case "POST /config/snapshot": {
      // Manual capture at the owner/policy level. The DO de-dupes against the head version, so a manual
      // snapshot of an unchanged posture returns { created:false } rather than churning a version.
      const denied = gate(caller, "access.policy");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Forward the caller so the DO re-resolves access.policy and stamps the author; no body is needed
      // (the DO captures the CURRENT posture, never a client-supplied config - this is observability of
      // what is already stored, not a write of new config).
      return scheduler.fetch(doURL("/config/snapshot"), { method: "POST", headers: callerHeaders(caller) });
    }
    case "GET /config/history": {
      // The version list (id, at, author, parentHash, contentHash, summary) newest-first, plus the chain
      // head and a verify verdict. Readable by any caller that can view the config (downpipe.read).
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/config/history"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "GET /config/version": {
      // One full version (header + the normalised snapshot) by ?id=N. The path uses a query param rather
      // than a dynamic :id segment so it fits the literal switch (matching how GET /history takes ?id=).
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL(`/config/version${url.search}`), { method: "GET", headers: callerHeaders(caller) });
    }
    case "GET /config/diff": {
      // The plain-English (Australian) change list between two versions, ?from=A&to=B. Same read gate as
      // the history list: viewing how the config changed is viewing the config.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL(`/config/diff${url.search}`), { method: "GET", headers: callerHeaders(caller) });
    }

    // ---- OPT-IN dual-control change control: the gate flag + the pending-change inbox ---------------
    // The CONFIG-MUTATION routes themselves dispatch through the gate inside the DO (gatedConfigMutation),
    // so when the gate is ON a config write returns 202 + a pending id rather than applying; these routes
    // administer the gate and its queue. The TOGGLE is OWNER-ONLY and applies IMMEDIATELY (so the gate can
    // never deadlock its own off switch); it gates on the owner-exclusive keys.ceremony capability (the
    // same owner-only gate the audit-intent route uses, deliberately NOT access.policy which access-admin
    // also holds), and the DO re-resolves the caller's role and requires owner (defence in depth). The two
    // reads (the flag, the pending list) gate on downpipe.read (the config read cap, so any caller that can
    // view the config sees them).
    case "GET /config/approval-policy": {
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/config/approval-policy"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /config/approval-policy": {
      // Owner-only toggle of the change-control gate. keys.ceremony is owner-exclusive among the built-ins
      // (access-admin does NOT hold it), so this stays owner-only; the DO additionally re-resolves the role
      // and requires owner. ASYMMETRIC OFF SWITCH (the DO route enforces it): ARMING is immediate; DISARMING
      // by an attributable owner is gated behind a SECOND owner (202 ownerActionQueued), while the BARE-TOKEN
      // break-glass owner can always disarm IMMEDIATELY (no deadlock). On an IMMEDIATE true->false transition
      // the DO returns { disarmed:true } and we fire a real-time DISARM ALERT (fail-open). Audited.
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const resp = await scheduler.fetch(doURL("/config/approval-policy"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
      // On a successful IMMEDIATE disarm (a direct owner toggle OR the break-glass escape), the DO reports
      // disarmed:true; alert. A 202 (queued for a second owner) is NOT yet a disarm, that alert fires from
      // the owner-action approve route when the dual-control-disable action actually executes. Read the body
      // to inspect disarmed, then return a faithful copy so the caller sees the DO's exact status + payload.
      if (resp.status === 200) {
        const text = await resp.text();
        try {
          const parsed = JSON.parse(text) as { disarmed?: unknown };
          if (parsed.disarmed === true) {
            const via = caller.method === "token" ? "the break-glass admin token" : "a direct owner toggle";
            await routeDualControlDisarmAlert(env, scheduler, caller.email ?? null, via);
          }
        } catch {
          // A non-JSON 200 should not happen here; fall through to return the body verbatim.
        }
        return new Response(text, { status: 200, headers: { "content-type": "application/json" } });
      }
      return resp;
    }
    case "POST /config/restore-approval-policy": {
      // OWNER-OPT-IN toggle of the RESTORE-apply dual-control gate, the sibling of the config gate above.
      // Owner-only through the same owner-exclusive keys.ceremony capability; the DO re-resolves the role and
      // additionally enforces the two-identity floor on the ARM direction, because arming on a one-identity
      // estate would leave nobody able to approve a restore. Applies immediately and is audited.
      //
      // NO DISARM ALERT AND NO QUEUED DISARM YET, unlike the config gate: the asymmetric off switch needs its
      // own owner-action kind, and setRequireRestoreApproval records that this is a known, deliberate gap
      // rather than an oversight. Not claimed anywhere as present.
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/config/restore-approval-policy"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /config/signin-context-policy": {
      // OWNER-OPT-IN unusual-location sign-in notify toggle (R6, V6.3.5). Owner-only via the owner-exclusive
      // keys.ceremony capability, the same gate the change-number toggle uses; the DO re-resolves owner.
      // Applies immediately and is audited (config-policy-change); the current value is read via GET
      // /config/approval-policy, whose view now carries notifyNewSignInContext alongside the other flags.
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/config/signin-context-policy"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /config/change-number-policy": {
      // OWNER-OPT-IN "Require Change Number" toggle (change management). Owner-only via the owner-exclusive
      // keys.ceremony capability (the same owner-only gate the approval-policy toggle uses; the DO re-resolves
      // owner). It applies IMMEDIATELY and is audited (config-policy-change); it is NOT dual-control-gated (a
      // process/compliance control, not a security control). The current value is read via GET
      // /config/approval-policy, whose view carries requireChangeNumber alongside requireConfigApproval.
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/config/change-number-policy"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /config/attended-cadence": {
      // The estate-wide attended-verification interval. Same
      // owner-exclusive gate as the two policy toggles above, and the DO re-resolves owner in
      // setAttendedCadenceDays. It applies immediately and is audited; it gates nothing, so there is no
      // dual-control arm here either. 0 clears the cadence.
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/config/attended-cadence"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "GET /config/attended-cadence": {
      // Reading the interval needs only downpipe.read, like the config history: it is one integer, it names no
      // run and carries no proof history, so a viewer rendering the estate's stated rhythm is not a disclosure.
      // Writing it stays owner-only above.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/config/attended-cadence"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "GET /config/changes": {
      // The pending-change inbox (newest-first), each carrying its plain-English diff for the approver to
      // review. Readable by any caller that can view the config (downpipe.read), like the config history.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/config/changes"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "GET /owner-actions": {
      // The OWNER-ACTION approval inbox (pending + armed high-blast-radius owner actions awaiting a second
      // owner). Gated on downpipe.read so any authenticated config-reader may hit it; the DO applies the
      // visibility rule (owners see all; a non-owner proposer sees only their OWN proposals), keyed on the
      // forwarded caller. Each record carries a redaction-safe summary for the approver, and the DO STRIPS any
      // live secret from the listed params (dest secret key / IdP client secret / discovery token), never a
      // credential leaves on this read; the at-rest record keeps the full params for the approved replay only.
      const denied = gate(caller, "downpipe.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/owner-actions"), { method: "GET", headers: callerHeaders(caller) });
    }
    default:
      return null;
  }
}
