// router-ops.ts -- the operations-and-alerting routes: the drill-evidence log, the notification
// channels/rules/history/test, the credential-expiry tracker, the Access-only posture surface and the
// in-app break-glass-token retire. The notify.config / expiry.config / access.policy / keys.ceremony gate
// runs inline per route.

import { channelPlaintextSecretRejection } from "../notify-routing.ts";
import { deliverToChannel, type NotifyChannel, type NotifyEmission } from "../notify.ts";
import { envFlagEnabled } from "./auth.ts";
import { JSM_SECRET_AAD, loadConfigWrapKey, maybeWrapConfigSecret, SERVICENOW_SECRET_AAD } from "./config-secret.ts";
import { bumpAdminCounter, noteTestOutcome } from "./diag-counters.ts";
import type { PasskeyOwnerEvidence } from "./passkey.ts";
import type { RecoveryBreakGlassReason } from "./recovery.ts";
import { callerHeaders, gate, jsonError, jsonResponse, rateLimited } from "./router-core.ts";
import { doURL, type RouterCtx } from "./router-helpers.ts";

// wrapNotifyChannelSecret seals a jsm/servicenow channel submission's apiKey field BEFORE it reaches the
// DO (the DO holds no env/wrap key, mirroring POST /push's wrap-before-forward discipline in
// router-push.ts). A non-jsm/servicenow kind is returned UNCHANGED (there is nothing to wrap). An absent,
// empty, or WHITESPACE-ONLY apiKey is the KEEP-SECRET / no-value signal the DO's addNotifyChannel splices
// against its prior stored value: it is STRIPPED from the forwarded body so no value ever travels to the
// DO (finding F3: a whitespace-only apiKey was previously forwarded untrimmed and then stored as UNWRAPPED
// plaintext even with CONFIG_WRAP_KEY set; stripping it here agrees with parseChannelSecret's trimmed-empty
// rule at the DO). A NON-string apiKey is left in place so the DO's parseChannelSecret still rejects it
// (400). Exported so it is unit-testable without a full router harness (see test/validate-jsm.ts).
export async function wrapNotifyChannelSecret(body: Record<string, unknown>, wrapKey: Uint8Array | undefined): Promise<Record<string, unknown>> {
  const kind = body.kind;
  if (kind !== "jsm" && kind !== "servicenow") return body;
  const apiKey = body.apiKey;
  if (typeof apiKey === "string" && apiKey.trim().length === 0) {
    // Strip the trimmed-empty apiKey so the forwarded body carries none (an unambiguous KEEP-SECRET); a
    // whitespace-only value can then never be forwarded and stored unwrapped.
    const stripped = { ...body };
    delete stripped.apiKey;
    return stripped;
  }
  if (typeof apiKey !== "string") return body;
  const aad = kind === "jsm" ? JSM_SECRET_AAD : SERVICENOW_SECRET_AAD;
  const wrapped = await maybeWrapConfigSecret(wrapKey, apiKey, aad);
  return { ...body, apiKey: wrapped };
}

// handleOps dispatches the drill-evidence / notify / expiry / policy group. Returns the route's Response,
// or null when no case here matched (the hub falls to the next spoke).
// fireInBackground: see router-identity.ts's identical helper. The
// records below are the LAST action before their route returns, with no awaited work left to give the
// detached promise a scheduling window, so under real workerd the write is abandoned with the request
// context. runtime is undefined only for a direct call with no fetch runtime (a unit test), which falls
// back to the old bare void unchanged.
function fireInBackground(runtime: RouterCtx["runtime"], task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}


export async function handleOps(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, scheduler, caller, sub, runtime } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- drill-evidence: evidence log for drills + rehearsals --------
    // The drill-evidence log is NOT the audit chain; it is a separate, non-hash-chained evidence
    // surface (dates, run ids, operator notes). This route is NOT in the section-8 table; it records
    // drill/rehearsal evidence, so it gates on drill.run. For the four existing roles drill.run is held
    // by operator/approver/owner, identical allow/deny to the prior "operator" gate; restore-operator
    // also holds drill.run (the recovery role records rehearsal evidence). GET is any authenticated
    // role. The router gates and passes the caller header; the DO validates and appends. No audit event
    // is recorded here because drill-evidence is itself the evidence record.
    case "POST /drill-evidence": {
      const denied = gate(caller, "drill.run");
      if (denied) return denied;
      const body = (await req.json()) as { runId?: string; kind?: string; note?: string };
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/drill-evidence"), { method: "POST", body: JSON.stringify(body), headers: callerHeaders(caller) });
    }
    case "GET /drill-evidence":
      // Any authenticated role; no special gate.
      return scheduler.fetch(doURL("/drill-evidence"), { method: "GET" });

    // ---- notifications (contract section 2.4): channels, rules, history, test ----------------------
    // The channel/rule WRITES gate on notify.config (operator/approver/owner); the DO re-checks the
    // forwarded caller holds the capability (defence in depth). The READS (rules/history) are any
    // authenticated role, like GET /downpipes -- EXCEPT channels: a NotifyChannel carries the live
    // Slack/Teams/webhook url or PagerDuty routingKey verbatim (a bearer credential, not read-only
    // metadata, unlike a rule's opaque channelId or a redaction-safe NotifyHistoryEntry), so GET
    // /notify/channels gates on notify.config too, same as its POST siblings. The DO is the storage
    // authority. The
    // test-send is the one route the router delivers itself: it fetches the channel from the DO, then
    // POSTs a redaction-safe test via env (the router holds env; the DO does no network I/O, the same
    // separation as reconcileAlerts).
    case "GET /notify/channels": {
      const denied = gate(caller, "notify.config");
      if (denied) return denied;
      return scheduler.fetch(doURL("/notify/channels"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /notify/channels": {
      const denied = gate(caller, "notify.config");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // jsm/servicenow carry a bearer/basic credential (apiKey) that must be SEALED before the DO ever
      // sees it (the DO holds no env/wrap key). Every other kind's body passes through wrapNotifyChannelSecret
      // unchanged (webhook/slack/teams/pagerduty/email carry no field that needs sealing today). An absent/
      // empty apiKey is forwarded as-is (absent), so the DO's KEEP-SECRET splice (addNotifyChannel) can
      // decide: an edit keeps the prior sealed credential, a first create is rejected.
      const body = (await req.json()) as Record<string, unknown>;
      // The apiKey LENGTH bound must be evaluated HERE, on the plaintext, because sealing it below makes it a
      // WrappedSecret and parseChannelSecret's isWrappedSecret arm returns before its own length test. Without
      // this the declared 512-character bound ran only on the CONFIG_WRAP_KEY-absent floor, which is not the
      // ordinary deployment. Same constant, same rule, read from notify-routing.ts so the two cannot drift.
      const secretReason = channelPlaintextSecretRejection(body);
      if (secretReason !== null) return jsonError(`${String(body.kind)} channel ${secretReason}`, 400);
      let forwardBody: Record<string, unknown>;
      try {
        forwardBody = await wrapNotifyChannelSecret(body, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
      } catch (e) {
        return jsonError(`the engine's CONFIG_WRAP_KEY is misconfigured (${(e as Error).message}); fix it in the Secrets Store before setting a ${String(body.kind)} channel (its secret is encrypted at rest under this key)`, 400);
      }
      // Forward the body + caller so the DO re-checks notify.config, validates per kind, assigns the
      // id/createdAt, and creates the default-on rule on first setup. A validation failure is a 400.
      return scheduler.fetch(doURL("/notify/channels"), { method: "POST", body: JSON.stringify(forwardBody), headers: callerHeaders(caller) });
    }
    case "POST /notify/channels/delete": {
      const denied = gate(caller, "notify.config");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/notify/channels/delete"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    // THE CALLER IS CONVEYED AND THROWN AWAY, WHICH IS WHAT MADE THIS LOOK DEFENDED. This case forwards
    // callerHeaders(caller) exactly like the three notify.config-gated writes beside it, so it reads as
    // "the DO re-checks". It does not: the DO arm is `case "GET /notify/rules": return
    // this.json(await this.listNotifyRules())` (scheduler-do-routing-signals.ts), which takes no caller
    // argument at all. The header is decoded by nothing. Sending a caller and ignoring it is a WORSE
    // resting state than sending none, because the forwarding line is the evidence a reader uses to
    // conclude the route is authorised somewhere else.
    //
    // WHY posture.read AND NOT notify.config, WHICH IS THE TEMPTING ANSWER. GET /notify/channels beside
    // this one gates notify.config, so the obvious move is to match it. That would be WRONG, and not
    // marginally: notify.config is held by operator, approver and owner only, so it refuses a viewer, a
    // restore-operator and an access-admin, and the console renders these rules to all of them. The
    // capability that ALREADY discloses this exact data is posture.read, because GET /admin/support gates
    // posture.read and support-sections-notify.ts fetches doURL("/notify/rules") into the pack. So
    // posture.read is not a taste judgement here, it is the weakest capability under which the engine
    // already hands these rows out, re-derived from the pack's own fetch.
    //
    // WHAT THIS CHANGES: NOTHING ANY CALLER SEES, and that is provable rather than hoped for. posture.read
    // sits in the viewer floor (identity-rbac.ts ROLE_CAPABILITIES: every one of the six built-ins holds
    // it), the resting role for an authenticated caller with no grant is viewer, and custom-role
    // resolution seeds the set from ROLE_CAPABILITIES[builtin.role] and unions on top
    // (scheduler-do-rbac.ts), so a custom role cannot subtract it either. No reachable principal is
    // refused. What changes is that the route now states its floor instead of inheriting it from a table
    // it never mentions, and a later edit that tightens it to notify.config reddens a viewer assertion
    // here rather than blanking a viewer's screen in production.
    case "GET /notify/rules": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/notify/rules"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /notify/rules": {
      const denied = gate(caller, "notify.config");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/notify/rules"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /notify/rules/delete": {
      const denied = gate(caller, "notify.config");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/notify/rules/delete"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    // Same shape as GET /notify/rules above and the same posture.read floor, on the
    // same evidence: the DO arm is listNotifyHistory() with no caller argument, and the delivery history
    // is projected into the posture.read-gated support pack by support-sections-notify.ts (doURL(
    // "/notify/history")). Refuses nobody, for the reason set out on GET /notify/rules.
    case "GET /notify/history": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/notify/history"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /notify/test": {
      // Send a redaction-safe test to one channel (contract section 2.4). notify.config gated. The
      // router fetches the channel from the DO and delivers it itself via env (the DO holds no env and
      // does no network I/O). The test emission carries NO secret: a fixed info-severity line naming
      // only that it is a test from the engine. delivery is fail-open (deliverToChannel never throws);
      // the route reports { ok } so the console can show "test sent" / "test failed". The outcome is
      // ALSO recorded on the history ring flagged test:true (a green test previously left no durable
      // trace that the channel was ever verified); rules and digests never read history, so the test
      // entry can never trigger routing.
      const denied = gate(caller, "notify.config");
      if (denied) return denied;
      // gate -> rate-limit -> body, consistent with the rest of the file: the rate-limit counter is
      // consulted before the body is read, so a stream of malformed bodies cannot bypass the limiter.
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const body = (await req.json()) as { channelId?: string };
      if (typeof body.channelId !== "string" || body.channelId.length === 0) {
        return new Response(JSON.stringify({ error: "channelId required" }), { status: 400, headers: { "content-type": "application/json" } });
      }
      const chResp = await scheduler.fetch(doURL(`/notify/channel?id=${encodeURIComponent(body.channelId)}`), { method: "GET" });
      const { channel } = (await chResp.json()) as { channel: NotifyChannel | null };
      if (channel === null) {
        return new Response(JSON.stringify({ error: "unknown channel" }), { status: 404, headers: { "content-type": "application/json" } });
      }
      const emission: NotifyEmission = {
        event: "backup-success",
        severity: "info",
        downpipeId: null,
        downpipeName: null,
        detail: "downpipe test notification (no action required)",
        at: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
      };
      const result = await deliverToChannel(env, channel, emission);
      // G246: "my Slack test keeps failing." The delivery FAILURE CLASS the channel adapter computed (a 401 on
      // the webhook, a 410 on a deleted Slack app, an unverified sender) went into the response and died with
      // the browser tab, and the one artefact that WAS persisted -- the notify history's test row -- carried
      // delivered:false and NO reason.
      //
      // R7: THE CODE RIDES AS ITSELF, NOT AS `reason`. ChannelDeliveryResult.code is already a member of the
      // CLOSED DELIVERY_FAIL_CODES set; passing it as `reason` fed it to classifyTestFailure, whose text arm
      // coarsened http-bad-request (an engine payload regression: OUR bug), http-gone (the Slack app was
      // DELETED: recreate the webhook) and http-4xx (a wrong path on a live sink) into ONE "rejected" row with
      // three opposite remedies. It also carries the email adapter's shape-gated platformCode, because the same
      // button tests kind:"email" channels through the same Email Service (E_SENDER_DOMAIN_NOT_AVAILABLE /
      // E_SENDER_NOT_VERIFIED / an invalid EMAIL_FROM were likewise one row). ChannelDeliveryResult carries no
      // HTTP status at all, so no statusClass is passed: the closed code IS the status fact here. Never the
      // webhook URL, the recipient or the provider's text (NC-5 placeholder discipline).
      fireInBackground(
        runtime,
        noteTestOutcome(scheduler, "notify-channel", {
          ok: result.ok === true,
          ...(result.code !== undefined ? { reason: result.code, deliveryCode: result.code } : {}),
          ...(result.platformCode !== undefined ? { platformCode: result.platformCode } : {}),
        }),
      );
      // Record the outcome on the history ring, flagged as a test, CARRYING THE SAME CLOSED CODES (the gap's own
      // proposedEvidence: "carry deliveryCode on test:true notify history rows"). The real routing path has
      // recorded them on a failed delivery since G236/G248; the test row, the ONE durable artefact of a Test
      // press, carried a bare delivered:false. The DO re-gates both against the same closed sets.
      // Best-effort: a history fault must never turn a delivered test into an error; the immediate { ok } stays
      // the signal either way.
      try {
        await scheduler.fetch(doURL("/notify/history/test-send"), {
          method: "POST",
          body: JSON.stringify({
            channelId: body.channelId,
            delivered: result.ok,
            detail: emission.detail,
            ...(result.code !== undefined ? { code: result.code } : {}),
            ...(result.platformCode !== undefined ? { platformCode: result.platformCode } : {}),
          }),
          headers: callerHeaders(caller),
        });
      } catch {
        // history is best-effort for a manual test
      }
      return new Response(JSON.stringify({ ok: result.ok }), { headers: { "content-type": "application/json" } });
    }

    // ---- credential and key expiry tracker (contract section 4) ------------------------------------
    // The expiry items live in the scheduler DO under the `expiry:` prefix. The two WRITES gate on
    // expiry.config (operator/approver/owner, like notify.config); the DO re-checks the forwarded
    // caller holds the capability (defence in depth). The READ (GET /expiry) is any authenticated role,
    // like GET /downpipes, and returns the COMPUTED ExpiryStatus[] (daysRemaining + state). The DO is
    // the storage authority and validates each item per the shared validateExpiryItem. No item carries a
    // secret (the type cannot hold one), so the read is the customer's own redaction-safe metadata.
    // CHANGE-CONTROL GATE: the two writes dispatch through the DO's gatedConfigMutation, so with the
    // OPT-IN gate ON an expiry set/delete is QUEUED for a second expiry.config holder to approve (maker !=
    // checker) rather than applying inline, matching the customer's "config changes need two approvers"
    // model; an approved expiry change is versioned into config history with a coherent diff.
    // This one had the floor WRITTEN DOWN IN TWO PLACES AND ENFORCED IN NEITHER.
    // The block above says "The READ (GET /expiry) is any authenticated role"; the DO's own arm says
    // "READS (GET /expiry) are any authenticated role (the router gates)" (scheduler-do-routing-signals
    // .ts). The parenthetical asserted THIS line, and this line called no gate, so the DO was resting on a
    // check the router did not run while the router rested on the DO forwarding it a caller the DO
    // discards (the arm is listExpiryStatuses(), no caller argument). posture.read is used for the same
    // reason as GET /notify/rules and on the same kind of evidence: support-sections-config.ts fetches
    // doURL("/expiry") twice into the posture.read-gated pack, once for the licence expiry status and once
    // for the whole registry. It is a viewer-floor capability, so "any authenticated role" stays exactly
    // true after this and is now the thing the code says rather than the thing two comments claimed.
    case "GET /expiry": {
      const denied = gate(caller, "posture.read");
      if (denied) return denied;
      return scheduler.fetch(doURL("/expiry"), { method: "GET", headers: callerHeaders(caller) });
    }
    case "POST /expiry": {
      const denied = gate(caller, "expiry.config");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Forward the body + caller so the DO re-checks expiry.config, validates the item per kind, and
      // dispatches through gatedConfigMutation (gate OFF -> inline upsert; gate ON -> 202 + a pending id).
      // A validation failure comes back as 400 { error }.
      return scheduler.fetch(doURL("/expiry"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /expiry/delete": {
      const denied = gate(caller, "expiry.config");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/expiry/delete"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }
    case "POST /expiry/cleanup-attest": {
      // The operator attests they DELETED a spent credential (e.g. a one-shot Cloudflare attach token)
      // in Cloudflare, so the registry can mark the pending item "deleted (attested)". expiry.config
      // (the DO re-checks the forwarded caller). This is an ATTESTATION, never a verified deletion, the
      // engine holds no Cloudflare API token and cannot check Cloudflare-side state. It is an operator
      // action, NOT a config mutation, so it does not route through the dual-control change-control gate.
      const denied = gate(caller, "expiry.config");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      return scheduler.fetch(doURL("/expiry/cleanup-attest"), { method: "POST", body: await req.text(), headers: callerHeaders(caller) });
    }

    // ---- access policy: surface the Access-only (token-fallback) posture (P9 / console-access-1) ---
    // POST /policy/require-access reports the token-fallback hardening posture (ADMIN_TOKEN_DISABLED)
    // and the two facts the console's Access-only wizard needs before it offers to flip it: whether
    // Cloudflare Access is configured at all, and how THIS caller authenticated (so the console will
    // not offer "disable the token" to a caller who is itself on the bare-token break-glass, which would
    // lock them out). It is gated on access.policy (access-admin/owner), the people-and-access-policy
    // capability, so this hardened-posture surface sits behind the same gate as the role table, above the
    // general GET /status booleans.
    //
    // It is a SURFACE/ECHO, not a setter: ADMIN_TOKEN_DISABLED is an env var the console cannot write
    // (no-custody; the operator flips it out of band with `wrangler secret`/var, the same way every other
    // engine secret is set), so this route stores nothing and returns nothing the operator did not already
    // configure. CRUCIALLY it reads the posture from env DIRECTLY (envFlagEnabled, the same projection
    // status.ts uses), NOT from a DO override, so it adds NO hot-path DO read to auth: authorise() keeps
    // reading the env flag alone and is unchanged. It answers in the router (like GET /status, /updates,
    // /licence and /whoami) because it reads only env + the resolved verdict, not any DO state, so there
    // is nothing for the DO to re-check or protect. It is a read, so there is no rate-limit pre-check
    // (the GET reads are exempt and this carries no body to mis-parse), and it carries only booleans + the
    // caller's own auth method, never a token, an email or any secret.
    case "POST /policy/require-access": {
      const denied = gate(caller, "access.policy");
      if (denied) return denied;
      const accessConfigured = Boolean(env.CF_ACCESS_TEAM_DOMAIN && env.CF_ACCESS_AUD);
      const tokenFallbackDisabled = envFlagEnabled(env.ADMIN_TOKEN_DISABLED);
      // AUTH-1 lockout pre-flight. Disabling the token (ADMIN_TOKEN_DISABLED) or deleting the secret is an
      // OUT-OF-BAND act the engine cannot intercept (no-custody: the operator flips the env var / runs `wrangler
      // secret delete` themselves), so the only safe guard the engine can offer is an authoritative verdict the
      // console consults BEFORE it advises the operator to do so. The DO owns the passkey / recovery / second-
      // owner facts; CF Access is the env fact read here. secondFactorPresent OR's all four named factors; when
      // it is false, disabling/deleting the token would LOCK THE OPERATOR OUT (the in-app recovery paths all
      // need a working credential too), so safeToDisableToken is false and the console must refuse to advise it.
      let lockout: { passkeyOwnerEnrolled: boolean; passkeyOwnerEvidence: PasskeyOwnerEvidence; passkeyWitnessSince: string | null; recoveryReady: boolean; recoveryReadyReason: RecoveryBreakGlassReason; secondOwner: boolean } = { passkeyOwnerEnrolled: false, passkeyOwnerEvidence: "no-credential", passkeyWitnessSince: null, recoveryReady: false, recoveryReadyReason: "no-recovery-record", secondOwner: false };
      try {
        const lr = await scheduler.fetch(doURL("/policy/lockout-preflight"), { method: "GET", headers: callerHeaders(caller) });
        if (lr.ok) lockout = (await lr.json()) as typeof lockout;
      } catch {
        // Fail SAFE: a DO hiccup leaves lockout all-false, so secondFactorPresent reflects only CF Access and
        // the wizard errs toward "not safe to disable" rather than fabricating a green all-clear.
        // G051: failing safe is right; failing SILENTLY is not. An operator who holds a passkey is told they
        // have no second factor, and the pack could not say the verdict was computed from a degraded read.
        fireInBackground(runtime, bumpAdminCounter(scheduler, "degraded-read-lockout-preflight"));
      }
      const secondFactorPresent = accessConfigured || lockout.passkeyOwnerEnrolled || lockout.recoveryReady || lockout.secondOwner;
      return jsonResponse({
        // tokenFallbackDisabled: the current posture (true = only verified Access is accepted; the
        // shared-token fallback is hardened away). Mirrors status.tokenFallbackDisabled exactly.
        tokenFallbackDisabled,
        // accessConfigured: whether Cloudflare Access is wired (both the team domain and the AUD tag).
        // The console refuses to enable Access-only until Access is configured, so it needs this fact.
        accessConfigured,
        // enforced: the safe-to-rely-on state, true only when the token fallback is disabled AND Access
        // is actually configured (a disabled token with no Access would be a lock-out, which authorise()
        // already fails closed on; reporting enforced=false there keeps the console honest).
        enforced: tokenFallbackDisabled && accessConfigured,
        // callerMethod: how THIS caller authenticated. The wizard only offers to flip the env var to a
        // caller on a verified Access session, never to the bare-token break-glass (which would lock the
        // operator out). It is the caller's own, non-sensitive auth method, never a credential.
        callerMethod: caller.method,
        // AUTH-1: the second-factor breakdown + the pre-flight verdict. secondFactor is the four named factors
        // (a passkey for an owner, CF Access, recovery codes, a second owner); secondFactorPresent OR's them.
        // safeToDisableToken is the guard: a second factor must exist AND the caller must not itself be on the
        // bare token (disabling it mid-session would strand even that caller). The console refuses the disable
        // wizard when safeToDisableToken is false and surfaces lockoutWarning verbatim.
        secondFactor: {
          passkeyOwnerEnrolled: lockout.passkeyOwnerEnrolled,
          accessConfigured,
          recoveryReady: lockout.recoveryReady,
          // recoveryReadyReason names WHICH of the live recovery conditions failed (a closed, redaction-safe
          // enum; never an email, a count or a code). recoveryReady was a write-once latch until
          // LOCKOUT-PREFLIGHT-COUNTS-RECORDS-NOT-USABLE-FACTORS, so a false verdict here is new and
          // an operator who is told a factor they believe they have is not in place needs to know why: "every
          // code has been used" and "your codes cannot verify any more" have different remedies.
          recoveryReadyReason: lockout.recoveryReadyReason,
          // passkeyOwnerEvidence is REPORTED, NEVER OR'd (PASSKEY-OWNER-ENROLLED-COUNTS-CREDENTIALS).
          // passkeyOwnerEnrolled above still counts credential RECORDS, which is why orphaned
          // virtual-authenticator keys can keep secondFactorPresent true. The honest fix needs evidence
          // that a credential can still produce an assertion, and the only such evidence is a verified
          // assertion, which nothing recorded until now. This field carries what IS known, with `unknown`
          // spelled out rather than rounded to a reassuring boolean; passkeyWitnessSince dates the
          // record-keeping so `unknown` can be told apart from `never`. Neither is an input to
          // secondFactorPresent or to safeToDisableToken, and neither should become one until a real fleet
          // has run long enough for "never demonstrated" to mean something other than "we only just started
          // looking".
          passkeyOwnerEvidence: lockout.passkeyOwnerEvidence,
          passkeyWitnessSince: lockout.passkeyWitnessSince,
          secondOwner: lockout.secondOwner,
        },
        secondFactorPresent,
        safeToDisableToken: secondFactorPresent && caller.method !== "token",
        lockoutWarning: secondFactorPresent ? null : "You have no second factor enrolled (no owner passkey, no Cloudflare Access, no recovery codes, no second owner). Disabling or deleting the admin token now would lock you out, and the in-app recovery paths also need a working credential. Enrol a passkey, configure Cloudflare Access, generate recovery codes, or appoint a second owner first.",
      });
    }

    // ---- break-glass token retire (in-app disposal of the one-time bootstrap ADMIN_TOKEN) ----------
    // POST /policy/retire-break-glass-token sets the durable breakGlassTokenRetired latch true, so the
    // engine STOPS honouring the ADMIN_TOKEN bearer immediately (no redeploy): the next bare-token request
    // is refused at the gate exactly as ADMIN_TOKEN_DISABLED refuses it. The engine cannot delete its own
    // Worker secret (it holds no standing Cloudflare token, by design), so this is how the operator disposes
    // of the bootstrap token once their Owner passkey works.
    //
    // OWNER-ONLY, by the owner-EXCLUSIVE keys.ceremony capability (NOT access.policy, which access-admin
    // also holds) so an operator/access-admin is a JSON 403, exactly like the change-control toggle. It is
    // ONE-WAY FROM THE APP: a retired token no longer resolves to owner anywhere (auth.ts refuses it, and
    // the DO whoami fails it closed), so a bare token can never call this to un-retire itself; only a
    // passkey/Access Owner (or a redeploy resetting the DO) can change it back. The DO RE-RESOLVES the
    // caller's role from its own tables and requires owner (defence in depth over this gate) and records the
    // break-glass-token-retired audit event with the actor. It is a mutating POST, so it is rate-limited per
    // caller after the gate. The body is ignored (retire is the only intent; the DO defaults retired:true).
    case "POST /policy/retire-break-glass-token": {
      const denied = gate(caller, "keys.ceremony");
      if (denied) return denied;
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // Forward the caller (so the DO re-resolves owner + attributes the actor) with the retire intent. No
      // client body is trusted: the DO defaults to retired:true, and the route exists only to retire.
      return scheduler.fetch(doURL("/policy/break-glass-retired"), {
        method: "POST",
        body: JSON.stringify({ retired: true }),
        headers: callerHeaders(caller),
      });
    }
    default:
      return null;
  }
}
