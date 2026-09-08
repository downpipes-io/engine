// router-rbac.ts -- the people-and-access administration routes: the role table writes, the IdP
// group->role mapping, the composable custom roles and the audit-trail reads + the owner-only intent
// marker. The roles.write / access.policy / keys.ceremony gate runs inline per route.

import type { AuditTarget } from "./audit.ts";
import { roleInviteEmailSignalName } from "./auth-signals.ts";
import { bumpAdminCounter, recordExportAttempt } from "./diag-counters.ts";
import { callerHeaders, gate, jsonResponse, rateLimited, recordAudit } from "./router-core.ts";
import { doURL, type RouterCtx, recordAuthSignalEdge } from "./router-helpers.ts";
import { routeAuthChangeAlert } from "./router-notify.ts";
import { inviteSenderConfigured, isRoleString, parseRoleEntry, sendRoleInvite } from "./router-sources.ts";

// fireInBackground: see router-identity.ts's identical helper.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}

// EXPORT_FILTER_PARAMS are the query keys that NARROW an audit export. Their presence is the only thing the
// G022 record ever carries about them (a single `filtered` boolean): the VALUES are an actor e-mail, an action,
// a downpipe name and a date range, none of which may enter a diagnostic record. A narrowed export that fails
// while a whole-log export succeeds is a filter/scan fault, not an availability outage, which is the whole
// reason the boolean is worth carrying.
const EXPORT_FILTER_PARAMS = ["actor", "action", "downpipe", "outcome", "from", "to", "before", "afterSeq"] as const;

// handleRbac dispatches the roles / group-roles / custom-roles / audit group. Returns the route's Response,
// or null when no case here matched (the hub falls to the next spoke).
export async function handleRbac(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, url, scheduler, caller, sub, sourceIp, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- role administration: capability roles.write (access-admin or owner) --------------------
    // Section 8: /roles and /roles/delete gate on roles.write. For the four existing roles this is
    // identical allow/deny to the prior "owner" rank gate (only owner holds roles.write among them).
    // access-admin also holds roles.write, and the DO's own authority re-check now honours it: the DO
    // RE-RESOLVES the caller's role from its own tables and reads can(role, "roles.write"), so an
    // access-admin can persist a role end to end. The DO keeps the HARD anti-escalation guard (only an
    // Owner may grant or remove the owner role, so an access-admin cannot mint itself Owner) plus the
    // unchanged last-Owner and bootstrap semantics, inside the same read-modify-write.
    case "POST /roles": {
      const body = (await req.json()) as { email?: string; role?: string; expiresAt?: string };
      const denied = gate(caller, "roles.write");
      if (denied) {
        // Record the refused role write (a caller without roles.write attempting to grant). The DO
        // records the SUCCESS case at the commit point; the router records the DENIED case here because
        // it gates before forwarding. role defaults to viewer for the target when the attempted role is
        // malformed, so the entry is always a valid closed-union target.
        await recordAudit(scheduler, caller, sourceIp, "role-change", "denied", {
          kind: "role",
          email: String(body.email ?? ""),
          role: isRoleString(body.role) ? body.role : "viewer",
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The DO re-checks Owner from the forwarded caller header (defence in depth), enforces the
      // last-Owner guard, AND records the role-change audit event on the successful write (the
      // commit point), so the success entry reflects what actually persisted. A guard/validation
      // failure comes back as 400 { error } and the DO records nothing (nothing changed).
      const roleResp = await scheduler.fetch(doURL("/roles"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
      // On a SUCCESSFUL grant (the DO returns 200 + the persisted RoleEntry), best-effort send the
      // granted person an invite/notification email. This is the ONLY place the role grant is known to
      // have committed (the DO is the authority; a 400 guard/validation failure sent nothing). The send
      // is OFF unless env.EMAIL is bound AND env.INVITE_EMAIL_FROM is set, and any failure is swallowed:
      // it never blocks or fails the grant (email is observability, never a control). The body is read
      // here (consuming roleResp), so the route returns a fresh Response carrying the same status + body.
      const roleBodyText = await roleResp.text();
      if (roleResp.status === 200) {
        const entry = parseRoleEntry(roleBodyText);
        if (entry) {
          // G117: the invite send is fail-open BY DESIGN (email is observability, never a control), and its
          // closed { sent:false, reason } was computed and then DISCARDED -- so "my new admin never received the
          // invite" had no evidence anywhere: the grant COMMITTED, the person HAS access, and nobody could tell
          // whether the engine even tried to email them. The grant path below is unchanged (still fail-open);
          // the skip class is now recorded. Never the grantee's address or the provider's rejection text.
          const invite = await sendRoleInvite(env, entry);
          if (!invite.sent && invite.reason !== undefined) fireInBackground(runtime, recordAuthSignalEdge(scheduler, roleInviteEmailSignalName(invite.reason)));
          // G340: the grant MINTED a registration invite (so this person has no passkey and cannot sign in
          // without the link), a sender IS configured, and the send still did not land. They now hold authority
          // they cannot use, and the only remaining path is the Owner copying the link out of the console modal
          // by hand.
          //
          // THE SENDER-CONFIGURED GATE IS LOAD-BEARING. Without it the counter fired on a
          // LEGITIMATE POSTURE the gap itself names: an org that configures NO invite sender, because the Owner
          // hands the link over out of band. In that deployment sendRoleInvite returns {sent:false} for EVERY
          // grant while the DO mints an inviteToken for every grantee with no passkey, so a fault-named counter
          // climbed without bound on a healthy engine -- inside adminCounters, the section whose documented
          // contract is that any non-zero value means the surface silently went wrong. That is the cry-wolf rule,
          // and it would have taught a reader to ignore the one section that must never be ignored.
          //
          // Gated, the counter asserts only what the code established: a send was ATTEMPTED and was refused. The
          // discrimination the ticket needs survives intact, and is now sound in both directions:
          //   no invite path by design  -> status.inviteSenderConfigured FALSE, counter 0, and the closed auth
          //                                signal role-invite-email-{binding,from}-unconfigured says which half
          //                                is unset. The Owner is expected to copy the link; nothing is wrong.
          //   invite path BROKEN        -> status.inviteSenderConfigured TRUE, counter NON-ZERO, and the signal
          //                                names the refusal (from-invalid / recipient-invalid / send-rejected).
          //   already-enrolled member   -> no invite token is minted, so neither fires.
          //   healthy send              -> silent.
          //
          // The gate reads the SAME inviteSenderConfigured() the pack's status boolean is built from, so the two
          // fields a support engineer joins cannot disagree.
          if (entry.inviteToken !== undefined && !invite.sent && inviteSenderConfigured(env)) {
            fireInBackground(runtime, bumpAdminCounter(scheduler, "role-grant-invite-undeliverable"));
          }
        }
        // V6.3.7: notify the operator's configured channels that a role was granted/changed. The DO audits it
        // (tamper-evident record), but a real-time NOTIFICATION is what lets a human spot an unexpected/takeover
        // grant. Fail-open, redaction-safe (names the affected email + new role + the actor, never a secret).
        fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "role-change", "owner-role-grant", `Role changed${entry ? ` for ${entry.email} to ${entry.role}` : ""}${caller.email ? ` by ${caller.email}` : ""}.`));
      }
      return new Response(roleBodyText, { status: roleResp.status, headers: { "content-type": "application/json" } });
    }
    case "POST /roles/delete": {
      const body = (await req.json()) as { email?: string };
      const denied = gate(caller, "roles.write");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "role-change", "denied", {
          kind: "role",
          email: String(body.email ?? ""),
          role: "viewer",
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The DO records the role-change audit event on a successful removal (offboarding), keyed to
      // the removed member; a last-Owner guard refusal is a 400 and records nothing.
      const delResp = await scheduler.fetch(doURL("/roles/delete"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
      const delText = await delResp.text();
      // V6.3.7: notify on an ACTUAL offboarding (a takeover/insider signal). The DO returns { deleted:true }
      // only when a member was really removed; a no-op delete of an absent member returns { deleted:false }
      // and is not a change worth alerting on.
      if (delResp.status === 200) {
        let removed = false;
        try {
          removed = (JSON.parse(delText) as { deleted?: boolean }).deleted === true;
        } catch {
          removed = false;
        }
        if (removed) fireInBackground(runtime, routeAuthChangeAlert(env, scheduler, "role-change", "offboard", `Member removed (offboarded)${body.email ? `: ${body.email}` : ""}${caller.email ? ` by ${caller.email}` : ""}.`));
      }
      return new Response(delText, { status: delResp.status, headers: { "content-type": "application/json" } });
    }

    // ---- identity-provider group->role mapping: read any role, write capability access.policy --------
    // OPTIONAL and additive: this mapping lets an org that uses Cloudflare Access (federating an IdP)
    // drive downpipe roles from IdP groups instead of per-email grants. It is purely additive: it
    // affects a caller only when their verified Access JWT carried matching groups, and an account
    // that never configures Access has an empty mapping and behaves exactly as the per-email table.
    // GET is any authenticated role (the customer reading their own directory mapping); the two writes
    // gate on access.policy (section 8: the group->role mapping is access policy). For the four existing
    // roles this is identical allow/deny to the prior "owner" rank gate (only owner holds access.policy
    // among them). access-admin also holds access.policy, and the DO's own re-check now honours it: the
    // DO RE-RESOLVES the role from the forwarded email + groups and reads can(role, "access.policy"), so
    // an access-admin can manage the mapping end to end. The owner CAP is unchanged (a group can NEVER
    // be mapped to owner -> 400), so allowing access-admin here never confers owner.
    // "Any authenticated role may read it": roles.read is the capability that says exactly that, and it is
    // the one GET /roles already gates on (router-identity.ts) over the sibling table in the same read
    // family. It sits in the viewer floor, so every built-in holds it and a custom role cannot subtract it:
    // this refuses nobody and turns "any authenticated role" from prose into the check.
    case "GET /group-roles": {
      // Reading the mapping is not a write, so any authenticated role may read it; the console
      // escapes the group names on render (the customer's own directory data, not a secret).
      const denied = gate(caller, "roles.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/group-roles"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /group-roles": {
      const body = (await req.json()) as { group?: string; role?: string };
      const denied = gate(caller, "access.policy");
      if (denied) {
        // Record the refused mapping write (a caller without access.policy mapping a group). The DO records
        // the SUCCESS case at the commit point; the router records the DENIED case here because it
        // gates before forwarding. The target carries only the group NAME + the attempted role
        // (defaulting to viewer when malformed), both redaction-safe.
        await recordAudit(scheduler, caller, sourceIp, "group-role-change", "denied", {
          kind: "grouprole",
          group: String(body.group ?? ""),
          role: isRoleString(body.role) ? body.role : "viewer",
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The DO re-checks Owner from the forwarded email + groups (defence in depth), enforces the
      // owner CAP (a group cannot map to owner -> 400), AND records the group-role-change audit event
      // on the successful write. A cap/validation failure comes back as 400 { error } and records nothing.
      return scheduler.fetch(doURL("/group-roles"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
    }
    case "POST /group-roles/delete": {
      const body = (await req.json()) as { group?: string };
      const denied = gate(caller, "access.policy");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "group-role-change", "denied", {
          kind: "grouprole",
          group: String(body.group ?? ""),
          role: "viewer",
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The DO records the group-role-change audit event on a successful removal, keyed to the
      // removed group; an absent mapping is an idempotent no-op (deleted:false) and records nothing.
      return scheduler.fetch(doURL("/group-roles/delete"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
    }

    // ---- composable custom roles: read any role, write capability access.policy --------------------
    // OPTIONAL and additive: a custom role is an account-defined NAMED capability bundle that sits on
    // top of the six built-ins. It is reachable only by an explicit email grant or a group mapping that
    // references its name, so an account that never defines one behaves exactly as before. GET is any
    // authenticated role (the customer reading their own role catalogue); the two writes gate on
    // access.policy (defining who may hold which authority is access policy, the same gate as the group
    // mapping). The DO re-resolves the caller's effective authority from its own tables and enforces the
    // HARD guardrails (no privilege escalation, owner-reserved caps barred, edit-requires-write-cap)
    // against the creator's OWN resolved capability set, so a creator can never compose a role more
    // powerful than themselves, and a custom role can never be owner nor hold an owner-reserved
    // capability. Every create/update/delete is audited as a redaction-safe custom-role-change.
    // The twin of GET /group-roles above and gated the same way for the same reasons: the DO arm is
    // listCustomRoles() with no caller argument, roles.read is the sibling read's capability (GET /roles),
    // and roles.read is in the viewer floor so nobody is refused.
    case "GET /custom-roles": {
      // Reading the catalogue is not a write, so any authenticated role may read it; the console escapes
      // the names/labels on render (the customer's own data, not a secret).
      const denied = gate(caller, "roles.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/custom-roles"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /custom-roles": {
      // Read the body ONCE (it is needed both for the denied-audit name and to forward to the DO).
      const body = (await req.json()) as { name?: string };
      const denied = gate(caller, "access.policy");
      if (denied) {
        // Record the refused create (a caller without access.policy composing a role). The DO records
        // the SUCCESS case at the commit point; the router records the DENIED case here because it gates
        // before forwarding. The target carries only the proposed name + a 0 count (no role was stored).
        await recordAudit(scheduler, caller, sourceIp, "custom-role-change", "denied", {
          kind: "customrole",
          name: String(body.name ?? ""),
          capabilityCount: 0,
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Forward the proposal (the once-read body) + caller so the DO re-resolves the creator's
      // authority, runs the HARD guardrails (validateCustomRole) against the creator's own capability
      // set, persists the role, and records the custom-role-change audit event. A guardrail/validation
      // failure comes back as 400. The body is JSON.stringify'd (not re-read) so it is consumed once.
      return scheduler.fetch(doURL("/custom-roles"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
    }
    case "POST /custom-roles/delete": {
      const body = (await req.json()) as { name?: string };
      const denied = gate(caller, "access.policy");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "custom-role-change", "denied", {
          kind: "customrole",
          name: String(body.name ?? ""),
          capabilityCount: 0,
        });
        return denied;
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The DO records the custom-role-change audit event on a successful removal; an absent role is an
      // idempotent no-op (deleted:false) and records nothing.
      return scheduler.fetch(doURL("/custom-roles/delete"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
    }

    // ---- audit (D4): reads gate on audit.read. B9: this capability was declared in the contract and
    // shown in the console's roles-builder (a creator could tick or untick it) but no gate()/can()
    // call anywhere ever checked it; the three gates below close that hole, making audit.read a real,
    // live authorisation check rather than a phantom one (proven directly against a hand-built caller
    // lacking it in validate-custom-roles.ts). PRECISE CLAIM: every built-in role holds audit.read
    // from the viewer floor up, and identity-rbac.ts's read floor is additionally folded, unconditionally,
    // into every custom role's resolved capability set (resolveAuthority, scheduler-do-rbac.ts:530-533,
    // "custom roles are additive"), so no custom role composable through the product today can actually
    // be excluded from it -- these gates are correct and future-proofing (they bite the moment a
    // narrower caller becomes constructible), not a live boundary against any caller reachable now. The
    // intent marker is Owner-only -----
    case "GET /audit": {
      // The tamper-evident trail, newest-first paged + filtered, with the chain head. Gated on
      // audit.read. Forwarded to the DO (the chain authority); the query string carries the filters
      // and the before/limit pager.
      const denied = gate(caller, "audit.read");
      if (denied) return denied;
      return scheduler.fetch(doURL(`/audit${url.search}`), { method: "GET" });
    }
    case "GET /audit/verify": {
      // Recompute the chain and report intact / brokenAt. A break is a RESULT (200), the on-screen
      // proof of tamper-evidence. Gated on audit.read.
      const denied = gate(caller, "audit.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/audit/verify"), { method: "GET" });
    }
    case "GET /audit/export": {
      // The full (filtered or whole) log as a download, JSON or ?format=csv, WITH the chain head
      // hash so an external verifier can confirm completeness. The customer's own data; gated on
      // audit.read. The DO sets the content-type and content-disposition.
      const denied = gate(caller, "audit.read");
      if (denied) return denied;
      //
      // G022: RECORD THE ATTEMPT. This forward is the ONLY place that sees both ways an export can fail -- the
      // DO answering a non-2xx (the whole-log scan died), and the round-trip throwing (the DO is unreachable) --
      // and until now it recorded neither, so "we cannot get our audit log out" left no trace anywhere in the
      // engine. That is a customer who cannot PROVE what happened, on the one artefact whose entire purpose is
      // proof; and the failure is by construction the one fact the exported log itself can never carry. The
      // record is three closed enums and a boolean: never the filter, never the chain, never a byte of the log.
      // A throw is recorded and then RE-THROWN, so the Worker's last-resort catch (and its dispatch-fault
      // record) behaves exactly as before.
      const format = url.searchParams.get("format") === "csv" ? "csv" : "json";
      const filtered = EXPORT_FILTER_PARAMS.some((p) => url.searchParams.has(p));
      let resp: Response;
      try {
        resp = await scheduler.fetch(doURL(`/audit/export${url.search}`), { method: "GET" });
      } catch (e) {
        await recordExportAttempt(scheduler, { channel: "admin-download", format, outcome: "do-unavailable", filtered });
        throw e;
      }
      await recordExportAttempt(scheduler, { channel: "admin-download", format, outcome: resp.ok ? "ok" : "do-error", filtered });
      return resp;
    }
    case "POST /audit/intent": {
      // The ONLY audit WRITE the console performs, and it writes an INTENT event only, never a
      // result or a value (F6). When the operator runs the key ceremony or is guided through an
      // Access-policy change, the console records that the ceremony/change HAPPENED; the engine cannot
      // witness the out-of-band step itself. This route is NOT in the section-8 table and bundles two
      // owner actions (key-ceremony-intent + access-policy-change-intent); it is gated on the owner-
      // exclusive keys.ceremony so it stays owner-only for the four existing roles exactly as before
      // (access.policy was not used here because it is held by access-admin too, which must not record a
      // key-ceremony intent). The action is constrained to exactly the two intent markers; else a 400.
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const body = (await req.json()) as { action?: string };
      if (body.action !== "key-ceremony-intent" && body.action !== "access-policy-change-intent") {
        return new Response(JSON.stringify({ error: "action must be key-ceremony-intent or access-policy-change-intent" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const target: AuditTarget = body.action === "key-ceremony-intent" ? { kind: "key-ceremony" } : { kind: "access-policy" };
      const event = await recordAudit(scheduler, caller, sourceIp, body.action, "success", target);
      return jsonResponse(event);
    }
    default:
      return null;
  }
}
