// The CONFIG-GOVERNANCE half of the SchedulerDO's RPC dispatch (the route() dispatcher, sub-mixin 3
// of 4). This sub-mixin owns the per-subsystem sub-dispatch methods for the demo-only markers/reset,
// the config-as-a-source version history, the break-glass/discovery and the archive-destination/
// licence/canary owner-action surfaces, and the dual-control pending-change + owner-action approval
// inbox. Each method is a switch over the SAME `${method} ${pathname}` key that returns the handler
// Response for a key it owns or null ("not my route"); route() (in scheduler-do-routing.ts) chains
// these among the other sub-dispatches. This sub-mixin's `this` is SchedulerDOSurface (like every
// sibling mixin), so each sub-dispatch calls the owning handler (this.setDestConfig /
// this.gatedOwnerAction / this.approveOwnerAction / ...) with the SAME dispatch and `this` binding.

import { CALLER_HEADER, decodeCaller } from "../admin/identity.ts";
import {
  DEMO_FRESH_FIRST_RUN_KEY,
  DEMO_MODE_MARKER_KEY,
  type SchedulerDOCtor,
  type UpdateLast,
  type UpdatePending,
} from "./scheduler-do-base.ts";

// Maximum keys per Cloudflare DO storage delete() call.
const DELETE_BATCH_SIZE = 128;

// DEMO_RESET_MAX_PAGES bounds the demo-reset wipe loop. At 1000 keys per page this is a 100M-key ceiling,
// far beyond any real DO; it is only a runaway guard so a buggy list never spins forever.
const DEMO_RESET_MAX_PAGES = 100_000;

export function RoutingConfigMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // Demo-only markers and the destructive demo reset (router hard-gates them on DEMO_MODE upstream).
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeDemo(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /demo/mark": {
        // engine-src-037-M1: the router persists the in-DO demo marker on a DEMO_MODE-gated path (it
        // calls this from GET /setup-state when env DEMO_MODE is on, read on every guided-setup load).
        // The DO cannot read DEMO_MODE from env, so this marker is how a genuine demo instance proves
        // itself to its OWN /demo/reset guard. Idempotent; never written on a production engine because
        // the router only ever calls it under DEMO_MODE.
        await this.state.storage.put(DEMO_MODE_MARKER_KEY, true);
        return this.json({ ok: true });
      }
      case "POST /demo/reset": {
        // INTERNAL demo-only reset, reached ONLY via the router's own scheduler.fetch, and the router has
        // already hard-gated it on DEMO_MODE + the ADMIN_TOKEN break-glass bearer (production has no reset
        // surface). Wipe ALL storage in THIS DO back to first-run (identity/passkeys/roles, downpipes,
        // destinations, sources, the credential registry, canary, audit chain, config history, IdP
        // connections, the licence, everything) + clear any pending alarm. Uses list+delete (the
        // backing-agnostic KV path, identical on SQLite-backed storage and the test mock) rather than
        // deleteAll() so the wipe is deterministic everywhere. DESTRUCTIVE by design.
        // engine-src-037-M1: FAIL-CLOSED defence in depth. Refuse unless THIS DO carries the demo marker
        // (persisted by POST /demo/mark on a DEMO_MODE-gated router path). The router already checks
        // DEMO_MODE + the ADMIN_TOKEN bearer upstream; this is an ADDITIONAL in-DO gate so a misrouted or
        // forged reset against a non-demo instance wipes NOTHING. 403 (an authorisation refusal), no wipe.
        const demoMarked = (await this.state.storage.get<boolean>(DEMO_MODE_MARKER_KEY)) === true;
        if (!demoMarked) {
          return this.jsonStatus({ ok: false, error: "forbidden", reason: "this instance is not marked as a demo; refusing to wipe" }, 403);
        }
        let cleared = 0;
        for (let guard = 0; guard < DEMO_RESET_MAX_PAGES; guard++) {
          const batch = await this.state.storage.list<unknown>({ limit: 1000 });
          if (batch.size === 0) break;
          // Batch-delete: the DO storage delete() API accepts an array of keys (up to DELETE_BATCH_SIZE
          // at a time), turning ~1000 awaited round-trips into a handful, so a populated demo wipe stays
          // within the invocation budget.
          const keys = [...batch.keys()];
          for (let i = 0; i < keys.length; i += DELETE_BATCH_SIZE) {
            cleared += await this.state.storage.delete(keys.slice(i, i + DELETE_BATCH_SIZE));
          }
        }
        await this.state.storage.deleteAlarm();
        // A DO reset wipes this DO's storage but CANNOT remove the engine's signer/break-glass WORKER
        // SECRETS (the engine holds no standing CF token to delete its own secrets), so keysReady would
        // stay true and the guided setup would skip the ceremony. Write a marker (after the wipe, so it
        // survives it) that GET /setup-state honours to force keysReady:false, so "Reset to fresh"
        // genuinely restarts the wizard at step 1; the re-run key ceremony (POST /keys/install) clears it.
        await this.state.storage.put(DEMO_FRESH_FIRST_RUN_KEY, true);
        // engine-src-037-M1: re-persist the demo marker AFTER the wipe (the list+delete above cleared it),
        // so a legitimate demo instance stays marked and a subsequent reset is not refused. The router also
        // re-marks on the next /setup-state load, but re-writing it here keeps the DO self-consistent.
        await this.state.storage.put(DEMO_MODE_MARKER_KEY, true);
        return this.json({ ok: true, cleared });
      }
      // GET /demo/first-run, the marker the router's /setup-state reads to force a fresh first run after a
      // demo reset (true only between a reset and the next key-ceremony install). Absent => not forced.
      case "GET /demo/first-run":
        return this.json({ forceFirstRun: (await this.state.storage.get<boolean>(DEMO_FRESH_FIRST_RUN_KEY)) === true });
      // POST /demo/first-run/clear, drop the marker once the operator re-runs the ceremony (called by the
      // router's keys-install on success), so keysReady reflects the freshly-installed keys again.
      case "POST /demo/first-run/clear": {
        await this.state.storage.delete(DEMO_FRESH_FIRST_RUN_KEY);
        return this.json({ ok: true });
      }
      // Scheduled restore tests (contract section 5). The downpipe config carries
      // restoreTestCadenceSeconds (defaulted to weekly on create); the scheduler exposes which
      // downpipes are DUE for a restore test (last test older than the cadence) so the cron driver runs
      // the in-account drill out of the DO (the same seal-stays-out-of-the-DO separation as runs), and a
      // callback records the outcome onto the downpipe state. POST /restore-tests-due returns the due
      // list; POST /restore-test-complete records lastRestoreTestAt/Ok. Both are INTERNAL (reached only
      // by the cron driver's own scheduler.fetch, like /due and /complete).
        default:
          return null;
      }
    }

    // Config-as-a-source versioning (Phase 4) + the OPT-IN dual-control gate's own administer routes.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeConfigVersion(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "POST /config/snapshot":
        return this.json(await this.manualConfigSnapshot(decodeCaller(req.headers.get(CALLER_HEADER))));
      case "GET /config/history":
        return this.json(await this.configHistoryList());
      case "GET /config/version":
        return this.json(await this.configVersionById(url.searchParams.get("id")));
      case "GET /config/diff":
        return this.json(await this.configDiff(url.searchParams.get("from"), url.searchParams.get("to")));
      case "GET /config-snapshot-health":
        // The support pack reads the cumulative config auto-snapshot failure tally (config-snapshot-best-effort-
        // gap): a count + last time, so an un-versioned config change (a swallowed capture) is visible.
        return this.json(await this.getConfigSnapshotHealth());
      case "GET /config-history-health":
        // The support pack reads the LIGHTWEIGHT config-history integrity verdict + signingKeyRotated flag
        // (config-history-session-key-regen), distinguishing a rotated in-DO signing key from content tamper,
        // WITHOUT serialising the whole version list.
        return this.json(await this.configHistoryHealth());
      case "GET /change-control/refusals":
        // The support pack reads the cumulative change-controlled-action refusal tally (change-number-required-
        // refusal): a count + last time + last action kind, WITHOUT touching the CR ledger (a refusal records
        // no change-recorded entry). INTERNAL (the router's own scheduler.fetch, like the other pack reads).
        return this.json(await this.getChangeControlRefusals());
      // OPT-IN dual-control change control (default OFF). The gate flag and the pending-change inbox live in
      // THIS DO. The TOGGLE is OWNER-ONLY and the DO RE-RESOLVES the caller's role and requires owner. It is
      // IMMEDIATE IN THE ARM DIRECTION ONLY, which is what stops it deadlocking its own off switch; an
      // attributable owner's DISARM is queued for a second owner by the asymmetric block twenty-odd lines
      // below, and reading "the toggle is never queued" off this sentence is wrong. The pending-change
      // lifecycle (approve/reject) re-resolves the approver's authority and enforces maker != checker + the
      // same write capability the original mutation requires + the no-stale/superseded base check, then
      // REPLAYS the one validated apply path. The reads (the flag, the pending list) are router-gated on
      // downpipe.read (the config read cap). The config-mutation routes themselves dispatch through the gate
      // inline (gatedConfigMutation above); these routes administer the gate and its queue.
      case "GET /config/approval-policy":
        return this.json(await this.getOrgPolicyView());
      // POST /config/restore-approval-policy administers the RESTORE-apply gate, the sibling owner-opt-in
      // policy. It is a separate route from the config one because the two policies are independent and a
      // single body carrying both would make "arm one" and "arm both" the same request shape.
      //
      // NO ASYMMETRIC OFF SWITCH HERE YET (setRequireRestoreApproval says so in full): an Owner disarms
      // immediately. The arm direction IS floor-guarded, which is the direction that can strand an operator:
      // arming on a one-identity estate would leave nobody able to approve a restore, and that lockout is the
      // whole reason this policy exists.
      case "POST /config/restore-approval-policy": {
        const rapCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const rapBody = (await req.json()) as { requireRestoreApproval?: unknown };
        return this.json(await this.setRequireRestoreApproval(rapBody, rapCaller));
      }
      case "POST /config/approval-policy": {
        // ASYMMETRIC OFF SWITCH (the gate covers its own off switch, mirroring break-glass-retire which gates
        // only retire:true). ARM (false->true) and any no-op apply IMMEDIATELY (turning a control ON, or
        // re-stating it, is safe and must never need a second owner). DISARM (true->false) is the one
        // dangerous direction, a single compromised owner could otherwise flip the gate OFF, run every gated
        // op inline, and flip it back, a one-owner bypass of the whole guarantee, so:
        //   - a BARE-TOKEN break-glass owner disarms IMMEDIATELY (it cannot propose/approve owner actions by
        //     design, so it MUST keep a direct off switch; this is the deadlock/lockout escape);
        //   - any OTHER (attributable) owner's disarm is routed through gatedOwnerAction("dual-control-disable")
        //     so, when the gate is ON, it records a pending owner action (202) and only flips OFF on a DISTINCT
        //     second owner's approve.
        // NO DEADLOCK: ARM is always immediate and the break-glass owner can always disarm immediately, so the
        // account can never be locked out of its own off switch. On EVERY true->false transition (whichever
        // path) the route fires a real-time disarm ALERT (handled in the router, which holds the notify env).
        const acpCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const acpBody = (await req.json()) as { requireConfigApproval?: unknown };
        const isBreakGlass = acpCaller !== null && acpCaller.method === "token"; // the bare-token owner (no attributable identity)
        const isDisarm = acpBody.requireConfigApproval === false && (await this.getRequireConfigApproval());
        if (isDisarm && !isBreakGlass) {
          // Attributable-owner disarm: gate it behind a second owner (immediate when the gate is already OFF, 
          // but isDisarm is false then, so this branch is only reached with the gate ON).
          return this.ownerActionJson(
            await this.gatedOwnerAction("dual-control-disable", {}, "Turn OFF dual control (disarm the second-owner-approval gate over high-blast-radius config and owner operations)", acpCaller, (auth) => this.setRequireConfigApproval({ requireConfigApproval: false }, auth)),
          );
        }
        // Immediate path: ARM, any no-op, or a break-glass disarm. setRequireConfigApproval reports whether
        // this was a true->false transition so the result carries the disarmed flag the router alerts on.
        return this.json(await this.setRequireConfigApproval(acpBody, acpCaller));
      }
      case "POST /config/signin-context-policy": {
        // OWNER-OPT-IN unusual-location sign-in notify toggle (R6, V6.3.5). Owner-only (the router gates
        // keys.ceremony; the DO re-resolves owner in setNotifyNewSignInContext). Applies immediately and is
        // audited as config-policy-change; a notify preference is not dual-control-gated.
        const scCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const scBody = (await req.json()) as { notifyNewSignInContext?: unknown };
        return this.json(await this.setNotifyNewSignInContext(scBody, scCaller));
      }
      case "POST /config/change-number-policy": {
        // OWNER-OPT-IN "Require Change Number" toggle. Owner-only (the router gates keys.ceremony; the DO
        // re-resolves owner in setRequireChangeNumber). Unlike the dual-control gate this is NOT dual-control-
        // gated to disarm: it is a process/compliance control, not a security control (turning it off enables no
        // data theft), so a lone owner applies it immediately; the change is audited as config-policy-change.
        const cnCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const cnBody = (await req.json()) as { requireChangeNumber?: unknown };
        return this.json(await this.setRequireChangeNumber(cnBody, cnCaller));
      }
      case "POST /config/attended-cadence": {
        // The estate-wide attended-verification interval.
        // Owner-only, re-resolved inside setAttendedCadenceDays exactly as the change-number toggle is: it gates
        // nothing, but lengthening a proof interval weakens the estate's stated assurance, so it is an owner
        // decision. 0 clears the cadence. Audited as config-policy-change, and unlike the boolean policies the
        // new interval IS recorded, because an integer of days is redaction-safe and a longer interval is
        // exactly what a reviewer needs to see.
        const acCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const acBody = (await req.json()) as { attendedCadenceDays?: unknown };
        return this.json(await this.setAttendedCadenceDays(acBody, acCaller));
      }
      case "GET /config/attended-cadence": {
        // Read-only, so the console can render the current interval without an owner gate. It carries one
        // integer and no proof history, so there is nothing here a viewer must not see.
        return this.json({ attendedCadenceDays: await this.getAttendedCadenceDays() });
      }
      case "POST /change-control/enforce": {
        // The restore apply (and any future router-run change-controlled op) asks the DO to enforce the change
        // policy + record the CR BEFORE it runs the op. enforceChangeControl reads the policy, validates the
        // forwarded caller's change reference and records the change-recorded event on a pass (or is a no-op when
        // the policy is off); an invalid/absent reference THROWS (-> 400) so the router refuses the action. It is
        // the SAME chokepoint the owner-action gate uses, so the two paths record identically. INTERNAL route
        // (reached only by the router's own scheduler.fetch, like /audit), so there is no client abuse vector.
        const ecCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const ecBody = (await req.json()) as { actionKind?: unknown };
        await this.enforceChangeControl(typeof ecBody.actionKind === "string" ? ecBody.actionKind : "", ecCaller);
        return this.json({ ok: true });
      }
      // BREAK-GLASS TOKEN RETIRE (in-app disposal of the one-time bootstrap ADMIN_TOKEN). GET reports the
      // durable breakGlassTokenRetired latch (read by the router for auth.ts wiring AND GET /admin/status);
      // it is reached by the router's own scheduler.fetch on the bare-token path (and the status read), not
      // a public route. POST sets it true: OWNER-ONLY and re-resolved from the DO's own tables (defence in
      // depth over the router's owner gate), one-way from the app (a retired token never resolves to owner,
      // so it can never un-retire itself). Both consult the single ORG_POLICY_KEY record; the setter
      // MERGE-writes so the config-approval gate + the bootstrap latch are untouched.
        default:
          return null;
      }
    }

    // Break-glass-token disposal latches + the account-discovery config (the customer's read-only token).
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routePolicy(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /policy/break-glass-retired":
        return this.json({ breakGlassTokenRetired: await this.getBreakGlassTokenRetired() });
      case "POST /policy/break-glass-retired": {
        // GATED owner op (break-glass-retire): RETIRING the ADMIN_TOKEN bearer removes the way back in, so it
        // takes a second owner's approval. UN-retiring (retired:false) only RE-ENABLES a path and is NEVER
        // gated (gating it could deadlock recovery), matching the method's own asymmetry. The router only
        // ever sends retired:true, so the gate covers the dangerous direction.
        const bgCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const bgBody = (await req.json()) as { retired?: unknown };
        if (bgBody.retired === false) {
          return this.json(await this.setBreakGlassTokenRetired(bgBody, bgCaller));
        }
        return this.ownerActionJson(
          await this.gatedOwnerAction("break-glass-retire", bgBody, "Retire the break-glass admin token (removes the token way back in)", bgCaller, (auth) => this.setBreakGlassTokenRetired(bgBody, auth)),
        );
      }
      // BOTH break-glass-disposal latches together, for the GET /admin/status surface (the console renders the
      // dispose-bootstrap-token finding + the retire control from these). One round-trip; presence-only
      // booleans, never a secret. Reached only by the router's own scheduler.fetch on the status read.
      case "GET /policy/break-glass-disposal":
        return this.json({ bootstrapConsumed: await this.getBootstrapConsumed(), breakGlassTokenRetired: await this.getBreakGlassTokenRetired() });
      // AUTH-1 lockout pre-flight: the DO-owned second-factor facts the require-access wizard OR's with CF Access
      // (an env fact) before advising the operator to disable/delete the ADMIN_TOKEN. Presence-only booleans,
      // never a secret. Reached only by the router's own scheduler.fetch on the require-access read.
      case "GET /policy/lockout-preflight":
        return this.json(await this.lockoutPreflight());
      // ACCOUNT-DISCOVERY config (the customer's own read-only API token, SET FROM THE CONSOLE, no
      // CLI, no redeploy). The config route (with the token) is INTERNAL-ONLY for the router's
      // discovery fetches; status is presence-only and never carries the token. Set/clear and the
      // account selection are owner-exclusive (re-resolved HERE, defence in depth) and audited.
      case "GET /sources/discovery-config":
        return this.json({ config: await this.getDiscoveryConfig() });
      case "GET /sources/discovery-status":
        return this.json(await this.getDiscoveryStatus());
      case "POST /sources/discovery-token": {
        // GATED owner op (discovery-token-set): SETTING the customer's read-only account API token hands the
        // engine an account-read CF credential, so it takes a second owner's approval. CLEARING (token:null)
        // only REMOVES a credential and is NOT gated (it reduces, never expands, what the engine can read).
        // The token VALUE is in the replay params (like the webhook url / dest secret), never the summary or
        // the audit; the summary names the account fingerprint the router verified.
        const dtCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const dtBody = (await req.json()) as { token?: unknown; accountsSeen?: unknown };
        if (dtBody.token === null) {
          return this.json(await this.setDiscoveryToken(dtBody, dtCaller));
        }
        const seen = Array.isArray(dtBody.accountsSeen) ? dtBody.accountsSeen : [];
        const acctIds = seen
          .map((a) => (a && typeof a === "object" && typeof (a as { id?: unknown }).id === "string" ? (a as { id: string }).id : ""))
          .filter((s) => s !== "");
        const dtSummary = `Set the account-discovery read-only token (account-read credential) for ${acctIds.length} account(s)${acctIds.length > 0 ? `: ${acctIds.slice(0, 3).join(", ")}${acctIds.length > 3 ? ", …" : ""}` : ""}`;
        return this.ownerActionJson(
          await this.gatedOwnerAction("discovery-token-set", dtBody, dtSummary, dtCaller, (auth) => this.setDiscoveryToken(dtBody, auth)),
        );
      }
      case "POST /sources/discovery-accounts": {
        // GATED owner op (discovery-accounts-set): changes WHICH accounts the engine browses + which is its
        // own (the backup scope), so it takes a second owner's approval.
        const daCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const daBody = (await req.json()) as { selected?: unknown; engineAccountId?: unknown };
        const selIds = Array.isArray(daBody.selected) ? daBody.selected.filter((x): x is string => typeof x === "string") : [];
        const daSummary = `Change the browsed accounts (backup scope) to ${selIds.length} account(s)${selIds.length > 0 ? `: ${selIds.slice(0, 3).join(", ")}${selIds.length > 3 ? ", …" : ""}` : ""}`;
        return this.ownerActionJson(
          await this.gatedOwnerAction("discovery-accounts-set", daBody, daSummary, daCaller, (auth) => this.setDiscoveryAccounts(daBody, auth)),
        );
      }
      case "POST /sources/enable": {
        // Owner op (NOT dual-control): adding/removing which token-authenticated source types are
        // available to protect only changes what the create-downpipe wizard offers; it touches no
        // binding and no running downpipe, so it is additive and reversible. setEnabledSources
        // re-checks the owner (defence in depth) and filters to the known types.
        const esCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const esBody = (await req.json()) as { sources?: unknown };
        return this.json(await this.setEnabledSources(esBody, esCaller));
      }
      // engine-account verification (LICENCE-BINDING-ON-CLAIM follow-up,): the STATUS read is
      // presence-only, reached by the router's own scheduler.fetch on GET /admin/status; RECORD is the
      // router's post-write bookkeeping after a proven attach or update-apply succeeds, never a caller-
      // supplied body an outside request can reach directly. Neither is owner-gated (see
      // recordVerifiedEngineAccount's own comment: this is the engine recording a fact it just proved to
      // itself, not an operator handing it a credential or a choice).
      case "GET /sources/engine-account-verified":
        return this.json(await this.getVerifiedEngineAccount());
      case "POST /sources/engine-account-verified": {
        const vaBody = (await req.json()) as { accountId?: unknown; via?: unknown };
        return this.json(await this.recordVerifiedEngineAccount(vaBody));
      }
        default:
          return null;
      }
    }

    // The archive destination(s), the assurance licence, the safe-apply update lifecycle, and the canary.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeDestConfig(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /dest-config": {
        // INTERNAL-ONLY full record (including the secret access key): reached exclusively by the
        // router's own scheduler.fetch when building the effective destination. Never an admin route.
        // An optional ?id= resolves a SPECIFIC destination (per-downpipe routing); absent = default.
        const id = new URL(req.url).searchParams.get("id");
        return this.json({ config: await this.getDestConfigById(id) });
      }
      case "GET /dest-status":
        return this.json(await this.getDestStatus());
      case "POST /dest-config": {
        // GATED owner op (dest-set): set/repoint the single archive destination. The router has already
        // verified the submitted destination live; under dual control this records a pending approval (202)
        // instead of repointing where backups land. The redaction-safe summary names the host/bucket only,
        // never the secret access key (which IS in the replay params, like the webhook url, but never the
        // summary or the audit target). setDestConfig's own owner re-check runs on the inline + replay paths.
        const dcCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const dcBody = (await req.json()) as { config?: unknown };
        return this.ownerActionJson(
          await this.gatedOwnerAction("dest-set", dcBody, this.summariseDestConfig("Set the archive destination", dcBody.config), dcCaller, (auth) => this.setDestConfig(dcBody, auth)),
        );
      }
      case "GET /destinations":
        return this.json(await this.listDestStatus());
      case "POST /destinations": {
        // GATED owner op (dest-put): add a new destination or edit one (where future backups can land).
        const pdCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const pdBody = (await req.json()) as { id?: unknown; label?: unknown; config?: unknown; envDestConfigured?: unknown };
        const pdVerb = typeof pdBody.id === "string" && pdBody.id.trim() !== "" ? "Edit a destination" : "Add a destination";
        return this.ownerActionJson(
          await this.gatedOwnerAction("dest-put", pdBody, this.summariseDestConfig(pdVerb, pdBody.config), pdCaller, (auth) => this.putDest(pdBody, auth)),
        );
      }
      case "POST /destinations/remove": {
        // GATED owner op (dest-remove): delete a destination (force drops the only proven copies).
        const rmCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const rmBody = (await req.json()) as { id?: string; force?: boolean };
        const rmParams = { id: rmBody.id ?? "", force: rmBody.force === true };
        const rmSummary = `Remove destination ${rmParams.id || "(unspecified)"}${rmParams.force ? " (force: drops copies)" : ""}`;
        return this.ownerActionJson(
          await this.gatedOwnerAction("dest-remove", rmParams, rmSummary, rmCaller, (auth) => this.removeDest(rmParams.id, rmParams.force, auth)),
        );
      }
      case "POST /destinations/default": {
        // GATED owner op (dest-default): repoint which destination is the default seal target.
        const ddCaller = decodeCaller(req.headers.get(CALLER_HEADER));
        const ddId = ((await req.json()) as { id?: string }).id ?? "";
        const ddParams = { id: ddId };
        return this.ownerActionJson(
          await this.gatedOwnerAction("dest-default", ddParams, `Make destination ${ddId || "(unspecified)"} the default`, ddCaller, (auth) => this.setDefaultDest(ddId, auth)),
        );
      }
      // Assurance licence (console-activated; DO-stored; fail-open). GET is INTERNAL-ONLY (carries the
      // token; reached only by the router's readLicence resolution, never an admin route). POST set/clear
      // is owner-exclusive (re-resolved in the method) and audited; the router has verified the token live
      // against the pinned signer before forwarding here (verify-before-store).
      case "GET /licence-token": {
        const rec = await this.getLicenceRecord();
        return this.json(rec ? { token: rec.token, setAt: rec.setAt, setBy: rec.setBy } : { token: null });
      }
      case "POST /licence-token":
        return this.json(await this.setLicenceToken((await req.json()) as { token?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      // Licence-activation refusal counter (failed-activation-no-trace). POST records a verify-before-store
      // refusal (the router posts the closed reason code on its refusal branch, fail-open); GET reads the
      // cumulative tally for the support pack (null until an activation is first refused). INTERNAL (the
      // router's own scheduler.fetch), like /licence-token itself.
      case "POST /licence-activation-refusal":
        return this.json(await this.recordLicenceActivationRefusal((await req.json()) as { reasonCode?: unknown }));
      case "GET /licence-activation-refusal":
        return this.json(await this.getLicenceActivationRefusal());
      // Safe-apply update lifecycle (bookkeeping; internal, the router gates + tokens the real deploy).
      case "GET /update-status":
        return this.json(await this.getUpdateRecord());
      case "POST /update-pending":
        return this.json(await this.setUpdatePending((await req.json()) as UpdatePending));
      case "POST /update-settled":
        return this.json(await this.setUpdateSettled((await req.json()) as UpdateLast));
      // Background confirmation: the hourly canary clears confirmationPending on the
      // engine's `last` record when it next sings on the SAME recommendedVersion a self-check keep recorded.
      // Bookkeeping only (needs no token); wrapped in blockConcurrencyWhile like the claim routes below, so a
      // concurrent read-modify-write on the same update-lifecycle record cannot race itself. Internal (the
      // cron driver calls it).
      case "POST /update-confirm":
        return this.json(await this.blockConcurrencyWhile(async () => this.confirmUpdateSettled((await req.json()) as { recommendedVersion?: unknown })));
      // W3 one-shot "new version available" claim: alert ONLY when the recommended version differs from the
      // last-alerted one, recording it atomically so the alert fires once per version. Internal (the cron
      // driver calls it); wrapped in blockConcurrencyWhile so two ticks cannot both claim the same version.
      case "POST /update-alert-claim":
        return this.json(await this.blockConcurrencyWhile(async () => this.claimUpdateAlert((await req.json()) as { recommendedVersion?: unknown })));
      // FOLD 1: the canary cron claims a one-shot CRITICAL "rollback needed" alert when a promoted-but-
      // unsettled new version is found unhealthy. Wrapped in blockConcurrencyWhile so two ticks cannot both
      // page; records the rollbackNeeded flag the console surfaces. Internal (the cron driver calls it).
      case "POST /update-rollback-needed-claim":
        return this.json(await this.blockConcurrencyWhile(async () => this.claimRollbackNeeded((await req.json()) as { recommendedVersion?: unknown; toVersion?: unknown; canaryVerdict?: unknown })));
      case "GET /downpipes/dest-for-run":
        // Internal: resolve which destination a run's downpipe writes to, so a restore/drill reads
        // from the run's OWN bucket. Redaction-safe (an opaque destination id only, never a credential).
        return this.json({ destinationId: await this.destinationForRun(new URL(req.url).searchParams.get("runId") ?? "") });
      // Canary backup: the on-by-default known-answer flight the Worker runs hourly. GET is the
      // redaction-safe console view; /config is the owner-set surface; /due and /complete are the
      // INTERNAL two-phase hooks the cron driver calls (the DO owns the schedule + lease + state, the
      // Worker does the heavy seal/read/restore I/O); /run-now arms an immediate flight.
      case "GET /canary":
        return this.json(await this.getCanaryView());
      // The lightweight support-pack view: the aggregate liveness + the bounded transition ring (canary-
      // transition-only-pages-once), so a standing "paged once" death stays observable without the heavy
      // flight bodies of GET /canary. Read-only, redaction-safe (enums / ints / clamped times / dest ids).
      case "GET /canary/transitions":
        return this.json(await this.getCanaryTransitions());
      case "POST /canary/config":
        return this.json(await this.setCanaryConfig((await req.json()) as { enabled?: unknown; destinationIds?: unknown; intervalSeconds?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /canary/due":
        return this.json(await this.canaryDue(Number(((await req.json()) as { nowMs?: unknown }).nowMs) || Date.now()));
      case "POST /canary/complete":
        return this.json(await this.canaryComplete((await req.json()) as { run?: unknown; results?: unknown }));
      case "POST /canary/run-now":
        return this.json(await this.canaryRunNow());
      case "GET /downpipes/dests-for-run":
        // Internal: EVERY destination a run was written to (primary + replicas), so a restore can fall
        // back to a replica when the primary is lost. Redaction-safe (opaque ids only).
        return this.json({ destinationIds: await this.destinationsForRun(new URL(req.url).searchParams.get("runId") ?? "") });
        default:
          return null;
      }
    }

    // The pending config-change inbox + the high-blast-radius owner-action approval gate.
    // Returns the handler Response for a key this sub-dispatch owns, or null ("not my route") so route()
    // tries the next link. The arms are verbatim from the original single switch.
    async routeConfigChanges(req: Request, url: URL): Promise<Response | null> {
      switch (`${req.method} ${url.pathname}`) {
      case "GET /config/changes":
        return this.json(await this.listPendingChanges());
      case "POST /config/changes/approve":
        return this.json(await this.approveChange((await req.json()) as { id?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /config/changes/reject":
        return this.json(await this.rejectChange((await req.json()) as { id?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      // OPT-IN dual control for the HIGH-BLAST-RADIUS OWNER OPERATIONS (the same requireConfigApproval toggle
      // arms it). These are the DO-side authority the router cannot bypass:
      //  - GET /owner-actions: the owner-approval inbox (pending + armed actions the caller may see).
      //  - approve/reject: a SECOND owner approves (maker != checker; a DO-executed action RUNS here as the
      //    proposer; a router-executed action is ARMED) or any owner vetoes.
      //  - gate-check / consume: the router-executed flow's two DO hooks, gate-check records a pending
      //    approval on the FIRST call (and tells the router 202) and reports an existing armed approval on the
      //    re-submit; consume atomically single-uses an armed approval so the router runs the privileged op
      //    with the one-shot token ONLY because an approved record existed. Both re-resolve owner from the
      //    DO's own tables, so the router cannot skip the gate. Reached only by the router's own scheduler.fetch.
      case "GET /owner-actions":
        return this.json(await this.listPendingOwnerActions(decodeCaller(req.headers.get(CALLER_HEADER))));
      // The caller-independent queue aggregate for the support pack (G259/G265): counts + oldest age + kinds,
      // never an id/summary/actor. Read-only; no caller needed (the self-service bundle has none).
      case "GET /owner-actions/queue-stats":
        return this.json(await this.ownerActionQueueStats());
      case "POST /owner-actions/approve":
        return this.json(await this.approveOwnerAction((await req.json()) as { id?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /owner-actions/reject":
        return this.json(await this.rejectOwnerAction((await req.json()) as { id?: string }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /owner-actions/gate-check":
        return this.json(await this.checkOwnerActionGate((await req.json()) as { kind?: unknown; params?: unknown; summary?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      case "POST /owner-actions/consume":
        return this.json(await this.consumeOwnerAction((await req.json()) as { id?: unknown; expectedActionHash?: unknown }, decodeCaller(req.headers.get(CALLER_HEADER))));
      // WebAuthn / passkey: the engine's OWN identity provider (free, self-contained, multi-user),
      // independent of Cloudflare Access. The DO is the storage authority for the passkey user,
      // credential and challenge records (`passkeyUser:`/`passkeyCred:`/`passkeyChallenge:` prefixes),
      // alongside the role/group/custom-role tables. The four routes mirror the WebAuthn ceremonies:
      // begin/finish for registration, begin/finish for login. The DO issues + single-use CONSUMES the
      // challenge inside the same read-modify-write as the verification (atomic, no replay), runs the
      // REAL verifier in passkey.ts, and on a first registration BOOTSTRAPS the email to Owner exactly
      // like the Access whoami bootstrap (the same `role:` table, the same empty-table check). These are
      // reached only by the router's own scheduler.fetch; rp.id and origin are passed in by the router
      // (the DO has no env). On any verification fault the DO logs the precise reason to console.error
      // with an opaque error id and returns a COARSE reason, matching the engine's errId discipline.
        default:
          return null;
      }
    }
  };
}
