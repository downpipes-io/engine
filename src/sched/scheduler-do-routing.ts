// The SchedulerDO's RPC dispatch: route() is the engine's INTERNAL RPC surface (reached only by the
// router's own scheduler.fetch); it contains ZERO gate()/authorise() calls (the router pre-gates every
// public path, and each handler re-checks its own DO-side authority). route() is a thin chain of
// per-subsystem sub-dispatch methods (routeCore, routeRbac, ...), each a switch over the SAME
// `${method} ${pathname}` key that returns the handler Response for a key it owns or null ("not my
// route") so the next link is tried. The key sets are DISJOINT, so the order in which sub-dispatches
// are tried is immaterial to which handler runs; they are grouped only by subsystem for readability.
// RoutingMixin's `this` is SchedulerDOSurface (like every sibling mixin), so each sub-dispatch calls
// the owning handler (this.gatedConfigMutation / this.listDownpipes / this.idpConnCreate / ...) with
// the SAME dispatch and `this` binding.
//
// The 22 sub-dispatch methods are split across four cohesive sibling sub-mixins, all chained by
// route() through `this`:
//   - RoutingMixin (here): route()/notFoundResponse + the CORE data plane (downpipe lifecycle, the
//     ingest-credential store, the runlog lock + rate-check, and the RBAC/audit/restore-approval authority).
//   - RoutingSignalsMixin (./scheduler-do-routing-signals.ts): SRE alerting, notifications, the expiry tracker,
//     and the reporting surfaces (restore-tests, posture, report data, coverage).
//   - RoutingConfigMixin (./scheduler-do-routing-config.ts): demo markers/reset, config-version history, the
//     break-glass/discovery + destination/licence/canary owner-action surfaces, and the dual-control inbox.
//   - RoutingIdentityMixin (./scheduler-do-routing-identity.ts): the passkey IdP, step-up re-auth, the native
//     external IdP (OIDC + SAML), and recovery codes.
// route() lives here and chains all four (every routeX it calls resolves on the composed class via `this`,
// regardless of which sub-mixin owns it).

import type { AuditDraft, StatusObservation } from "../admin/audit.ts";
import { CALLER_HEADER, type CustomRoleProposal, decodeCaller, isScimOffboardCaller } from "../admin/identity.ts";
import { discoveryIsStale, resolveCfConfigMode, sanitiseCfConfigDiscovery } from "../sources/cf-config-discovery.ts";
import { recordContractFault } from "./sched-fault-ledger.ts";
import {
  AuthError,
  type CompleteRunReq,
  type DownpipeState,
  type ReplRecordReq,
  type SchedulerDOCtor,
} from "./scheduler-do-base.ts";
import { notePlanSeen } from "./scheduler-do-restore-approval.ts";
import type { TickReport } from "./types.ts";

// optionalLockKey reads the per-destination RUNLOG-lock key from an OPTIONAL request body (SCALE-3). A
// legacy caller sends no body at all (the default destination slot), so a body that does not parse, or
// carries no string `key`, yields undefined rather than throwing -- both wire shapes reach the handler.
async function optionalLockKey(req: Request): Promise<string | undefined> {
  try {
    const body = (await req.json()) as { key?: unknown };
    return typeof body.key === "string" && body.key.length > 0 ? body.key : undefined;
  } catch {
    return undefined;
  }
}

export function RoutingMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // route() is the thin dispatch chain: parse the key once, then ask each per-subsystem sub-dispatch in
    // turn (each returns its Response for a key it owns, or null to pass). The key sets are DISJOINT, so the
    // FIRST non-null wins and the order does not change which handler runs; an unmatched key falls through to
    // the 404. This reproduces the former single switch's dispatch result for every key, byte-identical.
    async route(req: Request): Promise<Response> {
      const url = new URL(req.url);
      // P3 (caller-header-decode-failclosed): the router-internal caller header is PRESENT but did not decode
      // (a router encode fault or tampering), which the handlers below treat as a null caller -> least privilege
      // / owner-only refusal (a fail-closed 403). Observe it ONCE per request so that cause is diagnosable from
      // the pack, DISTINCT from an absent header (the legitimate bare-token / self path, which decodes to null
      // too but carried nothing). Best-effort + fire-and-forget: the handlers still decode + fail closed exactly
      // as before, and only the closed event name is ever stored (never the header value).
      const rawCaller = req.headers.get(CALLER_HEADER);
      // G271 (R5): the bounding TALLY that used to hang off this decode is gone. decodeCaller re-applies limits
      // every producer of a Caller has already applied (200 / 256, identically), so it drops nothing a real
      // request can carry: the only input that fired those counters was a hand-built header the product cannot
      // emit. The drop is now tallied at the IdP boundary that carried the oversized claim. The fail-closed
      // observation below is unaffected and stays exactly as it was.
      if (rawCaller !== null && rawCaller.length > 0 && decodeCaller(rawCaller) === null) void this.recordAuthSignal("caller-header-undecodable");
      const matched =
        (await this.routeCore(req, url)) ??
      (await this.routeIngestCredential(req, url)) ??
      (await this.routeSiemPush(req, url)) ??
      (await this.routeOtlpPush(req, url)) ??
      (await this.routeRunlogRate(req, url)) ??
      (await this.routeRbac(req, url)) ??
      (await this.routeAudit(req, url)) ??
      (await this.routeRestoreApproval(req, url)) ??
      (await this.routePruneApproval(req, url)) ??
      (await this.routeSreAlerting(req, url)) ??
      (await this.routeNotify(req, url)) ??
      (await this.routeExpiry(req, url)) ??
      (await this.routeDemo(req, url)) ??
      (await this.routeRestoreTests(req, url)) ??
      (await this.routePosture(req, url)) ??
      (await this.routeReports(req, url)) ??
      (await this.routeCoverage(req, url)) ??
      (await this.routeConfigVersion(req, url)) ??
      (await this.routePolicy(req, url)) ??
      (await this.routeDestConfig(req, url)) ??
      (await this.routeConfigChanges(req, url)) ??
      (await this.routePasskey(req, url)) ??
      (await this.routeStepUp(req, url)) ??
      (await this.routeIdp(req, url)) ??
      (await this.routeRecovery(req, url)) ??
      // The CRON + ADMIN diagnostic recorders / pack reads (SupportDiagMixin): the per-downpipe pre-run seal
      // errors (G163), the /metrics scrape health (G049), the structural WebAuthn fault classes (G158) and the
      // recorders' own dropped writes (G100/G331). A disjoint key set, so the position in the chain is immaterial.
      (await this.routeSupportDiag(req, url)) ??
      (await this.routeControlPlane(req, url));
      if (matched !== null) return matched;
      // G221: an unmatched key 404s SILENTLY. After a partial/mixed deploy (a newer console or Worker calling a
      // route this DO build does not have) a console screen 404s on every load and the pack showed nothing at
      // all - "quiet" and "the whole surface is 404ing" were the same picture. Count the fall-through (the route
      // CLASS only; never the path, method, body or header). Best-effort: the 404 itself is unchanged.
      await recordContractFault(this.state.storage, "unmatched-route", "unknown-route");
      return this.notFoundResponse();
    }

    // notFoundResponse is the former switch `default` arm, factored out so route() and every sub-dispatch
    // share the one 404 (an unmatched key yields exactly the "not found"/404 the single switch returned).
    notFoundResponse(): Response {
      return new Response("not found", { status: 404 });
    }

    // setCfConfigMode sets a cf-config downpipe's capture mode (auto = capture the discovered present set;
    // manual = capture the operator's include/exclude). It is a FIRST-CLASS config mutation dispatched by
    // applyConfigMutation: POST /cf-config/mode routes through gatedConfigMutation, so it dual-gates like a
    // downpipe upsert/delete (gate ON queues a pending change for a second approver) and auto-snapshots into
    // config history attributed to the caller (gate OFF). The prior inline write escaped the gate, the audit
    // trail and config-history attribution. Modelled on removeDownpipe (downpipe-delete): the downpipe.write
    // capability is enforced by the router gate on POST, and at approve by BOTH halves of the maker-checker
    // pair -- CHANGE_WRITE_CAPABILITY gates the CHECKER through canApproveChange, and approveChange's maker
    // floor gates the PROPOSER against their live re-resolved authority. That second half is why this method
    // can still take no caller; it did NOT exist when this comment was first written, and the sentence it
    // replaces named only the checker's half while reading as though it covered both, which is exactly how a
    // lapsed proposer's queued mode change applied. See approveChange in scheduler-do-change-control.ts.
    // It validates the mode enum and refuses an unknown downpipe, both as
    // throws surfaced as a 400 by the fetch() catch (an unknown downpipe is a 400 like every other config
    // mutation, no longer a special 404). Idempotent (sets a field), so the replay discipline needs no special case.
    async setCfConfigMode(params: { id?: unknown; mode?: unknown }): Promise<{ ok: true }> {
      const mode = params.mode;
      if (mode !== "auto" && mode !== "manual") throw new Error("mode must be auto or manual");
      const id = typeof params.id === "string" ? params.id : "";
      const ds = await this.state.storage.get<DownpipeState>(`dp:${id}`);
      if (!ds) throw new Error("unknown downpipe");
      ds.config.source.cfConfigMode = mode;
      await this.persistDownpipeState(ds);
      return { ok: true };
    }

    // Core downpipe lifecycle: CRUD, the scheduler hooks (due/trigger/heartbeat/complete), cf-config discovery/mode, history/point-in-time/RTO, replication, and the cron tick.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeCore(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /downpipes":
        // Config mutation routed through the OPT-IN change-control gate (gatedConfigMutation): gate OFF
        // (default) applies inline and auto-snapshots exactly as before; gate ON validates then queues a
        // pending change (202). The caller (forwarded header) is the proposer/applier authority.
        return this.gatedConfigMutation("downpipe-upsert", await req.json(), decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /downpipes/bulk":
        // Many-at-once upsert: each item runs the SAME gated single-upsert path (validation + change
        // control + audit), continue-on-error, capped per request; see bulkUpsertDownpipes.
        return this.bulkUpsertDownpipes((await req.json()) as { downpipes?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "GET /downpipes":
        return this.json(await this.listDownpipes());
      case "GET /beacon-aggregate":
        return this.json(await this.beaconAggregate());
      case "POST /beacon-state":
        // The opt-in vendor-beacon pass records its last POST outcome here (fail-open; the pass swallows any error).
        return this.json(await this.recordBeaconAttempt((await req.json()) as { ok?: unknown; status?: unknown }));
      case "GET /beacon-state":
        // The support pack reads the last beacon attempt outcome (beacon-post-lost); null when never emitted.
        return this.json(await this.getBeaconState());
      case "POST /drive-budget-yield":
        // The cron seal loop records a low-budget yield here (failover-probe-budget-exhaustion); fail-open (the
        // cron swallows any error). INTERNAL (reached only by the cron driver's own scheduler.fetch).
        return this.json(await this.recordDriveBudgetYield((await req.json()) as { carried?: unknown }));
      case "GET /drive-budget-yield":
        // The support pack reads the cumulative seal-loop budget-yield record; null when the loop never yielded.
        return this.json(await this.getDriveBudgetYield());
      case "POST /delete":
        return this.gatedConfigMutation("downpipe-delete", (await req.json()) as { id: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "GET /roster-hygiene":
        // Roster structural integrity (ghost rows + never-ran entries), ids/keys only. Read-only; the
        // router serves it to any authenticated reader (same read class as GET /downpipes itself) and
        // the support pack projects it, so a customer bundle self-diagnoses an orphaned map edge.
        return this.json(await this.rosterHygiene());
      case "POST /roster-reconcile":
        // Heal-to-invariant repair of the ghost classes ONLY (never-ran rows are valid configs and are
        // never touched). Like the roster re-attach, this creates/edits/removes no operator-approved
        // configuration, so it deliberately does NOT route through the change-control gate; the admin
        // router gates it owner-grade (keys.ceremony) and records the audit row.
        return this.json(await this.reconcileRoster());
      case "GET /due":
        return this.json(await this.due());
      case "POST /trigger":
        return this.json(await this.trigger((await req.json()) as { id: string }));
      case "POST /heartbeat":
        return this.json(await this.heartbeat((await req.json()) as { id: string; runId: string; index: number }));
      case "POST /complete":
        return this.json(await this.completeRun((await req.json()) as CompleteRunReq));
      case "POST /cf-config/discovery": {
        // Persist a cf-config surface-discovery result (run by the worker/cron probe, which can make the
        // ~200 subrequests; the DO only stores the partition). The capture path then reads `present`.
        const body = (await req.json()) as { id: string; discovery: unknown };
        const ds = await this.state.storage.get<DownpipeState>(`dp:${body.id}`);
        if (!ds) return this.jsonStatus({ ok: false, error: "unknown downpipe" }, 404);
        // G006: the discovery record now carries a fault-CLASS map and a truncation list, and it rides
        // straight into the support pack via downpipes[].cfConfigDiscovery. Trust is made explicit rather than
        // implicit in the sole-writer assumption: sanitiseCfConfigDiscovery is the REDACTION CHOKEPOINT -- every
        // surface id must be a member of the
        // CLOSED registry vocabulary, every class a member of the closed status set, every count clamped, and
        // nothing else on the posted object is read. A body that is not a discovery result at all is dropped.
        const discovery = sanitiseCfConfigDiscovery(body.discovery);
        if (discovery === null) return this.jsonStatus({ ok: false, error: "malformed discovery" }, 400);
        ds.cfConfigDiscovery = discovery;
        await this.persistDownpipeState(ds);
        return this.json({ ok: true });
      }
      case "POST /cf-config/mode":
        // The capture-mode change is a config mutation routed through the OPT-IN dual-control gate + config
        // history, exactly like a downpipe upsert: gate OFF applies inline via setCfConfigMode and auto-snapshots
        // (attributed to the caller); gate ON queues a pending change (202) a second owner must approve. This
        // replaces the prior inline write that escaped the gate, the audit trail and config-history attribution.
        return this.gatedConfigMutation("cf-config-mode-set", await req.json(), decodeCaller(req.headers.get(CALLER_HEADER)));
      case "GET /cf-config/discovery-due":
        // The daily discovery cron asks which enabled auto-mode cf-config downpipes have a stale/absent
        // discovery cache, so it can re-probe only those (spaced under the cron budget).
        return this.json({
          due: (await this.listDownpipes()).filter(
            (d) => d.config.enabled && d.config.source.type === "cf-config" && resolveCfConfigMode(d.config.source) === "auto" && discoveryIsStale(d.cfConfigDiscovery, Date.now()),
          ),
        });
      case "GET /history":
        return this.json(await this.history(url.searchParams.get("id")));
      case "GET /runs/at":
        // Point-in-time resolution (E4/C1): resolve the run to restore from as of ?at=<rfc3339> for the
        // ?downpipe=, the latest successful run completed at-or-before T from the retained ring. Read-only.
        return this.json(await this.runAt(url.searchParams.get("downpipe"), url.searchParams.get("at")));
      case "GET /rto":
        // RTO estimate (E4/C1, the recovery-time companion to RPO/freshness): the per-downpipe + fleet
        // recovery-time estimate derived from observed drill throughput, or an honest "unknown" with no
        // drill history. ?id= scopes to one downpipe (the fleet roll-up is always included). Read-only.
        return this.json(await this.rtoData(url.searchParams.get("id")));
      case "POST /replication/record": {
        const r = (await req.json()) as ReplRecordReq;
        await this.recordReplicationState(r.id, r);
        return this.json({ ok: true });
      }
      case "GET /replication":
        return this.json(await this.replication(url.searchParams.get("id")));
      case "POST /tick":
        // Record the tick instant FIRST: it is the preflight's affirmative evidence the cron
        // genuinely fires on this deployment (validated, never assumed), independent of what
        // the reconciliation below does.
        await this.state.storage.put("lastTickAt", Date.now());
        await this.alarm();
        return this.json({ ok: true });
      case "GET /tick-info":
        return this.json({ lastTickAt: (await this.state.storage.get<number>("lastTickAt")) ?? null });
      // POST /tick-outcome is the cron driver's END-of-invocation report (the false-green detector): the DO
      // appends the clamped TickReport to the bounded outcome ring, stamping the time + deriving the interval
      // since the prior tick. INTERNAL (reached only by drive() via scheduler.fetch). Fail-safe: a malformed
      // report is clamped in appendTickOutcome, never rejected, so a bad report can never break the ring.
      case "POST /tick-outcome":
        return this.json(await this.recordTickOutcome((await req.json()) as TickReport));
      // GET /scheduler-signals is the support pack's scheduler-liveness read: the per-tick outcome ring, the
      // due-index parity snapshot, and the runlog counter + max history index. Read-only, redaction-safe
      // (counts + flags + clamped timestamps only). The router forwards it into buildSupportBundle.
      case "GET /scheduler-signals":
        return this.json(await this.schedulerSignals());
      // The platform-issued ingest credential store (support diagnostics + SIEM audit feed +
      // the Prometheus-metrics scrape bearer): one credential per scope, the SECRET stored only
      // as its SHA-384, the most recent 50 pulls recorded on the grant (older entries roll over)
      // so the customer sees when the vendor, their SIEM collector, or their metrics scraper read.
      // These are INTERNAL routes (reached only by the router/worker via scheduler.fetch).
        default:
          return null;
      }
    }

    // The platform-issued ingest-credential store (support diagnostics + SIEM audit feed + the
    // Prometheus-metrics scrape bearer, admin/metrics.ts).
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeIngestCredential(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /ingest-credential/set": {
        const body = (await req.json()) as { scope: string; grant: unknown };
        if (body.scope !== "diagnostics" && body.scope !== "audit-feed" && body.scope !== "metrics") throw new Error("unknown credential scope");
        // ENG-SUP-DO-1: the DO re-checks OWNER from the forwarded caller at the commit point
        // (defence in depth, the /roles discipline) rather than trusting the router's gate alone.
        // The role is RE-RESOLVED from the DO's own tables; a non-owner refusal THROWS -> 400
        // like every other DO guard. Support credentials are owner-only by rank (no capability
        // maps to them; the owner bar is explicit, like the role table's owner cap).
        const setCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        if ((await this.roleForCaller(setCaller)).role !== "owner") throw new AuthError("support credentials require the owner role");
        await this.state.storage.put(`ingestcred:${body.scope}`, body.grant);
        // ENG-SUP-AUDIT-1 / NC-3: opening a vendor-readable pull surface is recorded at the
        // commit point with the actor, the scope and the PUBLIC clientId (never the secret or
        // its hash), exactly like a role change records at its commit.
        const grantMeta = (body.grant ?? null) as { clientId?: unknown; expiresAt?: unknown } | null;
        await this.appendAudit({
          actorSubject: setCaller ? setCaller.subject : null,
          actorEmail: setCaller?.email ? setCaller.email : null,
          actorMethod: setCaller ? setCaller.method : "access",
          sourceIp: setCaller?.sourceIp ?? null,
          action: "support-credential-grant",
          outcome: "success",
          target: {
            kind: "supportcredential",
            scope: body.scope,
            ...(typeof grantMeta?.clientId === "string" ? { clientId: grantMeta.clientId } : {}),
            ...(typeof grantMeta?.expiresAt === "string" ? { expiresAt: grantMeta.expiresAt } : {}),
          },
        });
        // Credential lifecycle registry: auto-OBSERVE the minted bearer's expiry. clientId is the PUBLIC
        // id (never the secret or its SHA-384). diagnostics (short cap) is ephemeral; audit-feed and
        // metrics (both long-lived, meant to sit in a collector/scrape config) are functional.
        if (typeof grantMeta?.expiresAt === "string") {
          await this.upsertObservedItem({
            id: `ingest-${body.scope}`,
            label: `${body.scope} bearer${typeof grantMeta?.clientId === "string" ? ` (${grantMeta.clientId})` : ""}`,
            kind: "token",
            lifecycleClass: body.scope === "diagnostics" ? "ephemeral" : "functional",
            expiresAt: grantMeta.expiresAt,
          });
        }
        return this.json({ ok: true });
      }
      case "GET /ingest-credential": {
        const scope = url.searchParams.get("scope") ?? "";
        if (scope !== "diagnostics" && scope !== "audit-feed" && scope !== "metrics") throw new Error("unknown credential scope");
        return this.json({ grant: (await this.state.storage.get(`ingestcred:${scope}`)) ?? null });
      }
      case "POST /ingest-credential/clear": {
        const body = (await req.json()) as { scope: string };
        if (body.scope !== "diagnostics" && body.scope !== "audit-feed" && body.scope !== "metrics") throw new Error("unknown credential scope");
        // ENG-SUP-DO-1: same owner re-check as /set (the revoke closes the surface, but it is
        // still an owner-class custody action and the DO is the authority).
        const clearCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        if ((await this.roleForCaller(clearCaller)).role !== "owner") throw new AuthError("support credentials require the owner role");
        const prior = (await this.state.storage.get<{ clientId?: unknown }>(`ingestcred:${body.scope}`)) ?? null;
        const removed = await this.state.storage.delete(`ingestcred:${body.scope}`);
        // Recorded only when a grant actually existed (the role-delete discipline: a no-op
        // revoke of an absent credential changes nothing and records nothing).
        if (removed) {
          await this.appendAudit({
            actorSubject: clearCaller ? clearCaller.subject : null,
            actorEmail: clearCaller?.email ? clearCaller.email : null,
            actorMethod: clearCaller ? clearCaller.method : "access",
            sourceIp: clearCaller?.sourceIp ?? null,
            action: "support-credential-revoke",
            outcome: "success",
            target: {
              kind: "supportcredential",
              scope: body.scope,
              ...(typeof prior?.clientId === "string" ? { clientId: prior.clientId } : {}),
            },
          });
        }
        // Credential lifecycle registry: drop the auto-observed bearer expiry row on revoke (fail-open).
        await this.deleteObservedItem(`ingest-${body.scope}`);
        return this.json({ ok: true });
      }
      case "POST /ingest-credential/record-pull": {
        const body = (await req.json()) as { scope: string; at: string };
        if (body.scope !== "diagnostics" && body.scope !== "audit-feed" && body.scope !== "metrics") throw new Error("unknown credential scope");
        const grant = (await this.state.storage.get<{ pulls?: { at: string }[] }>(`ingestcred:${body.scope}`)) ?? null;
        if (grant) {
          grant.pulls = [...(grant.pulls ?? []), { at: body.at }].slice(-50);
          await this.state.storage.put(`ingestcred:${body.scope}`, grant);
        }
        return this.json({ ok: true });
      }
        default:
          return null;
      }
    }

    // The SIEM audit-log push destination (SIEM-PUSH-DESIGN.md): the outbound egress config +
    // cursor + bounded delivery trail. GET /push is the REDACTED admin view (no secret); GET /push-config is
    // the INTERNAL full record (drain + test-send resolution, never a public admin route). POST /push is the
    // owner-exclusive set/replace, DUAL-CONTROL GATED via gatedOwnerAction (push-dest-set, DO-executed) so a
    // lone owner cannot repoint an identity-bearing egress once a second owner exists. POST /push/delete is
    // owner-exclusive and NOT DUAL-CONTROL gated (closing an egress is the safe direction) but IS
    // CHANGE-CONTROLLED: those are two different axes and reading "not gated" as "not recorded" is the defect
    // this arm closes (see the enforceChangeControl call below). POST /push-record is the cron drain's
    // internal outcome recorder (never advances the cursor on a test-send).
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link.
    async routeSiemPush(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /push":
        return this.json(await this.getSiemPushView());
      case "GET /push-config":
        return this.json({ record: await this.getSiemPushRecordRaw() });
      case "POST /push": {
        const caller = decodeCaller(req.headers.get(CALLER_HEADER));
        const body = (await req.json()) as { endpoint?: unknown; format?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown; sink?: unknown; authInUrl?: unknown; s3Target?: unknown; syslog?: unknown };
        return this.ownerActionJson(
          await this.gatedOwnerAction("push-dest-set", body, this.summarisePushConfig(body), caller, (auth) => this.setSiemPushDestination(body, auth)),
        );
      }
      case "POST /push/delete": {
        // CHANGE MANAGEMENT (OWNER OPT-IN "Require Change Number"). Clearing the SIEM push destination is a
        // CAB-worthy config change -- it shuts off the forwarding of the hash-chained audit trail, so the
        // customer's SIEM stops receiving it -- and the console has always prompted the operator for a change
        // reference before calling this route. It is NOT an OwnerActionKind (that set is the DUAL-CONTROL set,
        // and clearing is deliberately not dual-controlled: closing an egress is the safe direction), so it
        // never reached enforceChangeControl through gatedOwnerAction and the reference the operator supplied
        // was DISCARDED. Asking for a change number and recording nothing is worse than never asking, because
        // the operator remembers supplying it and believes the clear is on their change. This is the same
        // chokepoint the owner-action gate and the restore apply use, so all three record identically: with the
        // policy OFF it is a no-op, with it ON it records the change-recorded CR or THROWS (-> 400) and the
        // clear does not run. The kind is "push-clear", matching the console's own operation name for this
        // control, exactly as "restore-apply" does for the router-enforced restore.
        const caller = decodeCaller(req.headers.get(CALLER_HEADER));
        await this.enforceChangeControl("push-clear", caller);
        return this.json(await this.clearSiemPushDestination(caller));
      }
      case "POST /push-record":
        return this.json(await this.recordSiemPushOutcome((await req.json()) as { ok?: unknown; httpStatus?: unknown; reason?: unknown; count?: unknown; fromSeq?: unknown; toSeq?: unknown; gen?: unknown; causeDigest?: unknown }));
        default:
          return null;
      }
    }

    // The OTLP/HTTP metrics push destination (mon-otlp, PLAN.md M2): the SNAPSHOT sibling of the
    // SIEM push above. GET /otlp-push is the REDACTED admin view (no secret); GET /otlp-push-config is the
    // INTERNAL full record (the cron drain's own resolution, never a public admin route). POST /otlp-push is
    // the owner-exclusive set/replace, DUAL-CONTROL GATED via gatedOwnerAction (otlp-push-dest-set, DO-
    // executed) exactly like the SIEM push, so a lone owner cannot repoint this telemetry egress once a second
    // owner exists. POST /otlp-push/delete is owner-exclusive and NOT DUAL-CONTROL gated (closing an egress is
    // the safe direction) but IS CHANGE-CONTROLLED, exactly like its SIEM sibling above.
    // GET /otlp-metrics-snapshot is the cron drain's read of the current canonical backup-health
    // facts (otlpMetricsSnapshot). POST /otlp-push-record is the drain's internal outcome recorder. Returns the
    // handler Response for a key this sub-dispatch owns, or null ("not my route") so route() tries the next link.
    async routeOtlpPush(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /otlp-push":
        return this.json(await this.getOtlpPushView());
      case "GET /otlp-push-config":
        return this.json({ record: await this.getOtlpPushRecordRaw() });
      case "POST /otlp-push": {
        const caller = decodeCaller(req.headers.get(CALLER_HEADER));
        const body = (await req.json()) as { endpoint?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown };
        return this.ownerActionJson(
          await this.gatedOwnerAction("otlp-push-dest-set", body, this.summariseOtlpPushConfig(body), caller, (auth) => this.setOtlpPushDestination(body, auth)),
        );
      }
      case "POST /otlp-push/delete": {
        // CHANGE MANAGEMENT: the SIEM sibling's reasoning applies verbatim (see POST /push/delete above).
        // Clearing this destination stops the customer's collector receiving backup-health telemetry, the
        // console prompts for a change reference before calling the route, and until this call the reference
        // was collected and thrown away. Kind "otlp-clear", the console's own name for the control.
        const caller = decodeCaller(req.headers.get(CALLER_HEADER));
        await this.enforceChangeControl("otlp-clear", caller);
        return this.json(await this.clearOtlpPushDestination(caller));
      }
      case "GET /otlp-metrics-snapshot":
        return this.json(await this.otlpMetricsSnapshot());
      case "POST /otlp-push-record":
        return this.json(await this.recordOtlpPushOutcome((await req.json()) as { ok?: unknown; httpStatus?: unknown; reason?: unknown; downpipeCount?: unknown; truncated?: unknown; droppedCount?: unknown; rejectedDataPoints?: unknown; gen?: unknown; causeDigest?: unknown }));
        default:
          return null;
      }
    }

    // The account-wide RUNLOG lock and the per-caller anti-automation rate-check.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeRunlogRate(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /runlog-lock/acquire":
        // The acquire body is OPTIONAL: a legacy unkeyed caller sends none (default destination slot), a
        // per-destination caller sends { key }. Tolerate a missing/blank body so both wire shapes work.
        return this.json(await this.acquireRunlogLock(await optionalLockKey(req)));
      case "POST /runlog-lock/release":
        return this.json(await this.releaseRunlogLock((await req.json()) as { token: string; key?: string }));
      // The cron driver's SINGLE-FLIGHT tick lease (C3-07): drive() takes it at the top of a scheduled()
      // invocation and releases it at the end, so two OVERLAPPING */15 cron ticks do not both run the pass
      // sequence (the per-run in-flight lease already coalesces a duplicate seal; this spares the one tail an
      // overlap could otherwise double, the digest flush, plus the wasted reachability probes). INTERNAL
      // (reached only by the cron driver's own scheduler.fetch), and acquired fail-open (a DO blip proceeds).
      case "POST /tick-lease/acquire":
        return this.json(await this.acquireTickLease());
      case "POST /tick-lease/release":
        return this.json(await this.releaseTickLease((await req.json()) as { token?: string }));
      // Per-caller anti-automation rate limiting (OWASP ASVS V2.4.1). The router calls this on every
      // MUTATING admin route AFTER it has resolved the caller, keyed by the verified caller identity.
      // The DO maintains a fixed-window counter per key and reports whether the request is within the
      // limit plus how long until the window resets (so the router can set Retry-After). This is an
      // INTERNAL route reached only by the router's own scheduler.fetch (like the audit/role routes).
      case "POST /rate-check":
        return this.json(await this.rateCheck((await req.json()) as { key?: string; cost?: number; max?: number }));
      // RBAC (D3). The role table is keyed by the verified Access email; the DO is the single
      // authority, so it re-checks the roles.write CAPABILITY on every write from the caller the
      // router forwarded (see CALLER_HEADER) rather than trusting the router's gate alone: it
      // RE-RESOLVES the caller's role from its own tables and reads can(role, "roles.write") (owner OR
      // access-admin). The HARD anti-escalation guard holds inside the same read-modify-write (only an
      // Owner may grant or remove the owner role, so an access-admin cannot mint itself Owner), as does
      // the last-Owner guard (never remove the sole Owner), so there is no race.
        default:
          return null;
      }
    }

    // RBAC (D3): whoami, the role table, the group->role mapping, and composable custom roles.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeRbac(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /whoami":
        // The router resolves method/email/subject/exp; the DO supplies the role + roleSource +
        // isOnlyOwner. The first authenticated caller bootstraps as Owner (keyed on their stable subject)
        // so a fresh tenant is never locked out of role administration. The subject is the forwarded
        // stable principal the role table keys on; the OPTIONAL verified groups are forwarded as a
        // `groups` query param (a JSON array) so the DO folds the group mapping over the subject grant.
        // sourceIp (G346) is the router's OWN read of the edge CF-Connecting-IP header, forwarded like the
        // other params on this internal DO fetch. It is used for ONE thing: the audit row the first-Owner
        // bootstrap appends. No authority is derived from it.
        return this.json(await this.whoami(url.searchParams.get("email"), url.searchParams.get("subject"), url.searchParams.get("method"), url.searchParams.get("groups"), url.searchParams.get("sourceIp")));
      case "GET /roles":
        return this.json(await this.listRoles());
      case "POST /roles":
        return this.gatedConfigMutation("role-set", (await req.json()) as { email?: string; role?: string; customRole?: string; expiresAt?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /roles/delete": {
        const rdCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const rdParams = (await req.json()) as { email?: string };
        if (isScimOffboardCaller(rdCaller)) {
          // HI-07 (ASVS V7.4.1/V7.4.2): the SCIM facade's own internal caller bypasses the human
          // dual-control queue entirely and applies straight through the SAME validated deleteRole every
          // other path uses (roles.write, the last-Owner guard, the owner-escalation guard, the
          // session-epoch bump and the audit event all still run) -- only the SECOND-APPROVER QUEUE is
          // skipped. See isScimOffboardCaller (admin/identity.ts) for why: this caller can only ever
          // reach role-delete (a pure revocation, never a grant), and queuing it produced a WORSE,
          // previously-impossible stuck state (a pending change nobody could ever approve). Any OTHER
          // caller -- including the bare ADMIN_TOKEN break-glass, which is also method:"token" but
          // carries no email/subject -- does not match isScimOffboardCaller and falls through to the
          // unchanged gated path below.
          return this.json(await this.deleteRole(rdParams, rdCaller));
        }
        return this.gatedConfigMutation("role-delete", rdParams, rdCaller);
      }
      // Identity-provider group->role mapping (OPTIONAL, additive). The mapping lives under the
      // `grouprole:` prefix in this same DO (the single authority). GET is readable by any
      // authenticated role, which the router now enforces as roles.read, the sibling GET /roles gate
      // (GATE-GAP-2026-08-05b: the read arm below takes no caller, so before that gate landed the "any
      // authenticated role" rule was written in three places and run in none); the two writes
      // gate on the access.policy CAPABILITY (owner OR access-admin). The DO RESOLVES the caller's role
      // itself from the forwarded email + groups (roleForCaller) and reads can(role, "access.policy")
      // rather than trusting the asserted role, so a router bug cannot grant a mapping write, and it
      // re-applies the owner CAP (a group can never map to owner, so allowing access-admin here never
      // confers owner) inside the same storage read-modify-write.
      case "GET /group-roles":
        return this.json(await this.listGroupRoles());
      case "POST /group-roles":
        return this.gatedConfigMutation("group-role-set", (await req.json()) as { group?: string; role?: string; customRole?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /group-roles/delete":
        return this.gatedConfigMutation("group-role-delete", (await req.json()) as { group?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      // Composable custom roles (OPTIONAL, additive). The records live under the `customrole:` prefix in
      // this same DO (the single authority). GET is readable by any authenticated role, enforced by the
      // router as roles.read like GET /group-roles above (GATE-GAP-2026-08-05b: the read arm below takes
      // no caller either); the two writes gate on the access.policy
      // CAPABILITY (owner OR access-admin OR a custom role that itself holds access.policy). The DO
      // RESOLVES the caller's effective capability set itself from the forwarded email + groups
      // (requireCapabilityResolved over the recomputed set) and applies the HARD guardrails inside
      // validateCustomRole against the CREATOR's OWN resolved capabilities, so a creator can never put a
      // capability they do not hold (no escalation) nor an owner-reserved capability into a custom role.
      case "GET /custom-roles":
        return this.json(await this.listCustomRoles());
      case "POST /custom-roles":
        return this.gatedConfigMutation("custom-role-set", (await req.json()) as CustomRoleProposal, decodeCaller(req.headers.get(CALLER_HEADER)));
      case "POST /custom-roles/delete":
        return this.gatedConfigMutation("custom-role-delete", (await req.json()) as { name?: string }, decodeCaller(req.headers.get(CALLER_HEADER)));
      // Audit (D4). The chain lives in this DO (the single storage authority). The router records
      // first-class events by forwarding a redaction-safe draft to POST /audit; the DO appends it
      // inside one read-modify-write so the chain is gap-free and ordered. The reads (GET /audit,
      // /audit/verify, /audit/export) are served from the stored, ordered list. POST /audit-status
      // is the internal hook the router calls during GET /status so the DO can diff the status
      // snapshot and append engine-observed events. None of these accept a free-form value: the
      // recorder takes only the closed AuditDraft, which carries only the closed AuditTarget union.
        default:
          return null;
      }
    }

    // Audit (D4): the hash-chained event log append/read/verify/export and the status-diff hook.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeAudit(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /audit":
        return this.json(await this.appendAuditFromRouter((await req.json()) as AuditDraft));
      case "GET /audit":
        return this.json(await this.readAudit(url.searchParams));
      case "GET /audit/verify":
        return this.json(await this.verifyAudit());
      case "GET /audit/export":
        return this.exportAudit(url.searchParams);
      case "POST /audit-status":
        return this.json(await this.observeStatus((await req.json()) as StatusObservation));
      case "GET /status-baseline":
        // The support pack reads the deploy-identity marker recorded at the last status-snapshot baseline
        // (engine-version-change-baseline-suppressed / same-version-redeploy-double-blind); null until the
        // first observation. INTERNAL (the router's own scheduler.fetch, like the other pack reads).
        return this.json(await this.getStatusBaseline());
      // Dual control (D2). The approval state machine lives in this DO (the single authority), so
      // maker != checker and the requested -> approved -> consumed transitions are enforced inside
      // the storage read-modify-write, not at the router alone. Records are keyed by the request's
      // plan-binding hash so a re-plan that changes a decision field simply has no matching record.
      // The caller (the verified actor the router forwarded via CALLER_HEADER) drives requestedBy,
      // approvedBy and the maker != checker refusal; an absent/malformed caller fails closed.
        default:
          return null;
      }
    }

    // Dual control (D2) for restore + the drill-evidence log.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeRestoreApproval(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /restore/request":
        return this.json(await this.requestRestore((await req.json()) as { planHash?: string; runId?: string; isLatest?: boolean; plannedWrites?: number; bytes?: number; redirectBinding?: string | null; reason?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /restore/plan-seen":
        // THE PLAN ANCHOR. The dry-run route calls this with the plan hash it just previewed, so the
        // approval's TTL can start at the PLAN rather than at the request. That is what makes the dry run's
        // lapsed-KV warning a superset of what the sink will drop: the plan publishes an applyDeadline, and
        // an approval anchored here cannot authorise a write past it. Put-if-absent and self-sweeping; it
        // carries a plan hash and nothing else.
        return this.json(await notePlanSeen(this.state.storage, (await req.json()) as { planHash?: string; plannedAt?: number }));
      case "POST /restore/approve":
        return this.json(await this.approveRestore((await req.json()) as { planHash?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /restore/reject":
        return this.json(await this.rejectRestore((await req.json()) as { planHash?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "GET /restore/approvals":
        // The pending inbox: Approver/Owner see all; a requester also sees their own. The router
        // passes the caller via the header and ?approver=1 when the caller is Approver+.
        return this.json(await this.listApprovals(decodeCaller(req.headers.get(CALLER_HEADER)), url.searchParams.get("approver") === "1"));
      case "POST /restore/gate":
        // Read-only apply-time gate: is there a USABLE approval (effective status approved, not
        // expired/rejected/consumed/applying, approver != requester) for this planHash? The router
        // calls this BEFORE running the restore, so an unapproved apply never touches live data. It
        // does not mutate; the router's own exclusive reservation is POST /restore/reserve, taken
        // immediately before the write, and consuming happens only after a successful apply
        // (POST /restore/consume).
        return this.json(await this.gateRestore((await req.json()) as { planHash?: string }));
      case "POST /restore/reserve":
        // HI-03 / ASVS 2.1.6: the atomic gate-to-write reservation. The router calls this immediately
        // before the write (nothing else runs in between), flipping approved -> applying in one
        // read-modify-write so a concurrent second apply for the SAME plan hash cannot also reserve it
        // -- this, not the read-only gate above, is what makes the apply exclusive (the single-use TOCTOU fix).
        return this.json(await this.reserveRestore((await req.json()) as { planHash?: string }));
      case "POST /restore/release":
        // The failure-path counterpart to reserve: called when the reserved apply did not succeed (or
        // threw), reverting applying -> approved so a failed apply still leaves the approval usable
        // for a retry, unchanged from the pre-reservation UX.
        return this.json(await this.releaseRestore((await req.json()) as { planHash?: string }));
      case "POST /restore/consume":
        // Atomic single-use consume: flip THIS request's own reservation (raw status "applying") to
        // consumed in one read-modify-write. Called by the router AFTER a successful apply, so a
        // failed apply (which releases instead) leaves the approval usable for a retry, and a consumed
        // approval cannot authorise a second apply. Returns the consumed record (with the checker
        // email) or { consumed: false } if it was no longer this request's reservation.
        return this.json(await this.consumeApproval((await req.json()) as { planHash?: string }));
      // Drill-evidence. A separate, non-hash-chained evidence log that
      // records dated drill outcomes and operator-entered offline-rehearsal records. The log is
      // NOT an audit chain (it is evidence; evidence and chain serve different purposes); it follows
      // the same redaction discipline (no key material, no secret, no plaintext value).
      // POST is Operator+ (the DO re-checks via the caller the router forwarded); GET is any role.
      case "POST /drill-evidence":
        return this.json(await this.recordDrillEvidence((await req.json()) as { runId?: string; kind?: string; note?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "GET /drill-evidence":
        return this.json(await this.listDrillEvidence());
      // SRE alerting (the on-call persona). POST /reconcile-alerts is the INTERNAL hook the
      // cron driver calls each tick: the DO computes the transition-based, cooldown-throttled alerts
      // from state it already holds (config + history + the per-downpipe last-alerted record) and
      // returns them for the Worker to deliver out-of-band, keeping the network I/O out of the DO (the
      // same separation as the seal, design F11).
        default:
          return null;
      }
    }

    // Dual control (prune-approvals.ts): the PruneApproval request -> approve -> reject ->
    // gate -> reserve -> release/consume routes, mirroring routeRestoreApproval's shape exactly over
    // the leaner prune-shaped record. A separate sub-dispatch (not folded into routeRestoreApproval)
    // so the two mechanisms stay independently reviewable.
    async routePruneApproval(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /prune-approval/request":
        return this.json(await this.requestPruneApproval((await req.json()) as { planHash?: string; downpipeId?: string; retainedRuns?: number; supersededRuns?: number; reason?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /prune-approval/approve":
        return this.json(await this.approvePruneApproval((await req.json()) as { planHash?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /prune-approval/reject":
        return this.json(await this.rejectPruneApproval((await req.json()) as { planHash?: string; rejectReason?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "GET /prune-approval/list":
        return this.json(await this.listPruneApprovals(decodeCaller(req.headers.get(CALLER_HEADER)), url.searchParams.get("approver") === "1"));
      case "POST /prune-approval/gate":
        // Read-only apply-time gate, mirroring POST /restore/gate: is there a USABLE approval for this
        // plan hash? The router calls this BEFORE any delete, so an unapproved apply never touches the
        // archive. The exclusive reservation is POST /prune-approval/reserve, taken immediately before
        // the delete; consuming happens only after a successful apply.
        return this.json(await this.gatePruneApproval((await req.json()) as { planHash?: string }));
      case "POST /prune-approval/reserve":
        // HI-03/ASVS 2.1.6 parity: the atomic gate-to-write reservation, flipping approved -> applying
        // in one read-modify-write so a concurrent second apply for the SAME plan hash cannot also
        // reserve it.
        return this.json(await this.reservePruneApproval((await req.json()) as { planHash?: string }));
      case "POST /prune-approval/release":
        // The failure-path counterpart to reserve: reverts applying -> approved so a failed/errored
        // apply still leaves the approval usable for a retry with no fresh round of dual control.
        return this.json(await this.releasePruneApproval((await req.json()) as { planHash?: string }));
      case "POST /prune-approval/consume":
        // Atomic single-use consume, called AFTER a successful apply.
        return this.json(await this.consumePruneApproval((await req.json()) as { planHash?: string }));
      default:
        return null;
      }
    }
  };
}
