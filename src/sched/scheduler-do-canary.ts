// The canary backup subsystem: the on-by-default known-answer integrity flight across destinations.
// CanaryMixin layers these methods over a base whose `this` is SchedulerDOSurface.

import type { AuthMethod } from "../admin/identity.ts";
import { aggregateLiveness, CANARY_DEFAULT_INTERVAL_SECONDS, CANARY_HISTORY_CAP, CANARY_LEASE_MS, CANARY_MAX_DESTS, CANARY_TRANSITION_CAP, type CanaryCheck, type CanaryCheckResult, type CanaryConfig, type CanaryDestState, type CanaryDestView, type CanaryFlight, type CanaryFlightPlan, type CanaryLiveness, type CanaryRunDescriptor, type CanaryState, type CanaryTransition, type CanaryView } from "../canary/types.ts";
import { recordAdminRefusal, recordCanaryLoss, recordDestResolveFallback } from "./sched-fault-ledger.ts";
import { AuthError, CANARY_KEY, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { newULID, nowMillisISO } from "./scheduler-helpers.ts";

export function CanaryMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- canary backup (on-by-default known-answer integrity flight; multi-destination) ----------

    // ensureCanaryState reads the canary record, defaulting an ABSENT record to the ON-BY-DEFAULT bird:
    // enabled, ALL destinations (destinationIds null), the 60-minute cadence, pending, due on the next
    // tick. It MIGRATES an old single-destination record (config.destinationId, top-level deadSince/
    // lastRunId, history of CanaryCheck) into the multi-destination shape: a pinned single destination
    // keeps flying to exactly that one; an old default (null) becomes the new all-destinations default.
    async ensureCanaryState(): Promise<CanaryState> {
      const stored = await this.state.storage.get<CanaryState>(CANARY_KEY);
      if (stored) {
        const cfg = (stored as { config?: { destinationIds?: unknown } }).config;
        if (cfg && cfg.destinationIds === undefined) return this.migrateCanaryState(stored as unknown);
        return stored;
      }
      return {
        config: { enabled: true, destinationIds: null, intervalSeconds: CANARY_DEFAULT_INTERVAL_SECONDS },
        status: "pending",
        lastRunAt: null,
        nextRunAt: null,
        inFlight: false,
        runSeq: 0,
        dests: [],
        history: [],
      };
    }

    // migrateCanaryState upgrades a pre-multi-destination record. A pinned destination keeps exactly
    // that one; an old default (null) becomes the all-destinations default. The old single liveness +
    // cleanup id seed that destination's per-destination state so its prior cell is still cleaned up.
    migrateCanaryState(stored: unknown): CanaryState {
      const old = stored as {
        config: { enabled: boolean; destinationId?: string | null; intervalSeconds: number };
        status: CanaryLiveness;
        lastRunAt: string | null;
        nextRunAt: number | null;
        runSeq: number;
        deadSince?: string | null;
        lastRunId?: string | null;
        consecutivePasses?: number;
        history?: CanaryCheck[];
      };
      const pinned = typeof old.config.destinationId === "string" ? old.config.destinationId : null;
      const oldHistory = Array.isArray(old.history) ? old.history : [];
      const dests: CanaryDestState[] = old.lastRunId
        ? [{
            destinationId: pinned,
            status: old.status,
            lastRunAt: old.lastRunAt,
            lastRunId: old.lastRunId,
            deadSince: old.deadSince ?? null,
            consecutivePasses: old.consecutivePasses ?? 0,
            lastCheck: oldHistory.length > 0 ? oldHistory[oldHistory.length - 1]! : null,
          }]
        : [];
      const history: CanaryFlight[] = oldHistory.map((c) => ({ at: c.at, runSeq: c.runSeq, status: c.status, results: [c] }));
      return {
        config: { enabled: old.config.enabled, destinationIds: pinned !== null ? [pinned] : null, intervalSeconds: old.config.intervalSeconds },
        status: old.status,
        lastRunAt: old.lastRunAt,
        nextRunAt: old.nextRunAt,
        inFlight: false,
        runSeq: old.runSeq,
        dests,
        history,
      };
    }

    async saveCanaryState(s: CanaryState): Promise<void> {
      await this.state.storage.put(CANARY_KEY, s);
    }

    // resolveEffectiveDests turns the config into the concrete list of destination ids this flight flies
    // to. null (the default) means EVERY configured destination, auto-including newly-added ones; a pin
    // is the named subset (dangling ids dropped). With no console destinations the canary flies to the
    // env-default (the null id). Capped at CANARY_MAX_DESTS so a huge collection cannot blow the budget.
    async resolveEffectiveDests(s: CanaryState): Promise<(string | null)[]> {
      const { list, defaultId } = await this.loadDestinations();
      let ids: (string | null)[];
      if (s.config.destinationIds === null) {
        ids = list.length > 0 ? list.map((d) => d.id) : [null];
      } else {
        const known = new Set(list.map((d) => d.id));
        const valid = s.config.destinationIds.filter((id) => known.has(id));
        // G090: EVERY pinned destination has been deleted, so the flight silently goes to the DEFAULT instead.
        // The bird then proves a destination nobody pinned it to while the pinned ones go unproven -- and the
        // canary view reports a healthy status for a destination the operator never asked about. Closed class
        // only (never a bucket or an endpoint); throttled, since this resolver is on the view/flight read path.
        if (valid.length === 0 && list.length > 0) await recordDestResolveFallback(this.state.storage, "canary-pin-dangling");
        ids = valid.length > 0 ? valid : list.length > 0 ? [defaultId] : [null];
      }
      // G091: a destination collection larger than CANARY_MAX_DESTS is TRUNCATED here, so the destinations past
      // the cap are NEVER FLOWN -- while support (and the console) read the canary's aggregate as total
      // coverage. Record the truncation and NAME the uncovered destinations (the customer's own labels), so a
      // dead destination that the canary was never even asked to check stops looking like a proven one.
      if (ids.length > CANARY_MAX_DESTS) {
        const uncovered = ids.slice(CANARY_MAX_DESTS).filter((id): id is string => id !== null);
        await recordCanaryLoss(this.state.storage, "dest-excluded-by-cap", uncovered);
      }
      return ids.slice(0, CANARY_MAX_DESTS);
    }

    // getCanaryView is the redaction-safe console view: the aggregate state, a per-destination view (the
    // destinations the canary currently flies to, with their liveness + latest eight-aspect result), the
    // recent flights, and the whole destination collection for the settings picker. A disabled canary
    // reads as disabled.
    async getCanaryView(): Promise<CanaryView> {
      const s = await this.ensureCanaryState();
      const { list, defaultId } = await this.loadDestinations();
      const enabled = s.config.enabled;
      const labelOf = (id: string | null): { label: string; isDefault: boolean } => {
        if (id === null) return { label: "Default destination", isDefault: true };
        const d = list.find((x) => x.id === id);
        return { label: d?.label ?? id, isDefault: id === defaultId };
      };
      const effective = await this.resolveEffectiveDests(s);
      // The pins that no longer resolve. resolveEffectiveDests drops them silently (correctly: it must
      // still fly somewhere), so this is the only place the fact survives to a reader. Computed from the
      // same two inputs that function uses, both already loaded here, so it costs no extra read.
      const knownIds = new Set(list.map((d) => d.id));
      const danglingPins = s.config.destinationIds === null ? [] : s.config.destinationIds.filter((id) => !knownIds.has(id));
      const byId = new Map(s.dests.map((d) => [d.destinationId, d]));
      const dests: CanaryDestView[] = effective.map((id) => {
        const ds = byId.get(id);
        const { label, isDefault } = labelOf(id);
        return {
          destinationId: id,
          label,
          isDefault,
          status: enabled ? ds?.status ?? "pending" : "disabled",
          lastRunAt: ds?.lastRunAt ?? null,
          deadSince: ds?.deadSince ?? null,
          lastCheck: ds?.lastCheck ?? null,
        };
      });
      return {
        config: s.config,
        status: enabled ? s.status : "disabled",
        lastRunAt: s.lastRunAt,
        nextRunAt: s.nextRunAt,
        inFlight: s.inFlight,
        runSeq: s.runSeq,
        dests,
        history: s.history,
        allDestinations: list.map((d) => ({ id: d.id, label: d.label, isDefault: d.id === defaultId })),
        destinationCount: list.length,
        flyingToAll: s.config.destinationIds === null,
        danglingPins,
      };
    }

    // setCanaryConfig applies the owner's changes (enable/disable, which destinations to fly to, the
    // cadence), audits the change (who + when, never a value), and recomputes the schedule. destinationIds
    // null = all destinations; a non-empty array pins exactly those, and every pinned id must name a real
    // destination, else the change is refused (400), the fail-loud discipline a downpipe's destinationId
    // takes. The router has already gated this owner-only; the DO records the actor.
    async setCanaryConfig(
      req: { enabled?: unknown; destinationIds?: unknown; intervalSeconds?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<CanaryView> {
      // DO-side owner re-check (defence in depth), matching setDestConfig / setRequireConfigApproval: the router
      // gates this owner-only, but the DO RE-RESOLVES the caller's role from its own tables so a router bug
      // cannot let a non-owner change the canary configuration. THROWS -> 400 on a non-owner.
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may change the canary configuration");
      const s = await this.ensureCanaryState();
      // The PRIOR config, captured BEFORE any mutation: canaryOpOf compares prior-vs-next, and s.config is
      // reassigned to `next` below, so reading it after the assignment would make every change read "cadence".
      const prior: CanaryConfig = { ...s.config };
      const next: CanaryConfig = { ...s.config };
      if (typeof req.enabled === "boolean") next.enabled = req.enabled;
      if (req.destinationIds === null) {
        next.destinationIds = null; // all destinations
      } else if (Array.isArray(req.destinationIds)) {
        const { list } = await this.loadDestinations();
        const ids = req.destinationIds.map((x) => String(x));
        for (const id of ids) {
          if (!list.some((d) => d.id === id)) {
            await recordAdminRefusal(this.state.storage, "canary-config", "not-found"); // G146: the refusal the operator saw once
            throw new Error(`destinationId "${id}" is not a known destination`);
          }
        }
        // An empty selection cannot fly to nothing; treat it as the all-destinations default.
        next.destinationIds = ids.length > 0 ? [...new Set(ids)] : null;
      }
      if (typeof req.intervalSeconds === "number" && Number.isFinite(req.intervalSeconds)) {
        next.intervalSeconds = Math.min(86_400, Math.max(300, Math.floor(req.intervalSeconds)));
      }
      s.config = next;
      if (!next.enabled) {
        s.status = "disabled";
        s.nextRunAt = null;
      } else {
        if (s.status === "disabled") s.status = aggregateLiveness(s.dests.map((d) => d.status));
        s.nextRunAt = s.lastRunAt ? Date.now() + next.intervalSeconds * 1000 : null;
      }
      await this.saveCanaryState(s);
      await this.appendAudit({
        actorEmail: caller ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action: "canary-config",
        outcome: "success",
        // G036: enable and disable used to write the SAME event, so "prove the canary was switched off before
        // the incident" was unanswerable from the trail. canaryOp is a closed enum naming WHICH control moved
        // (a disable is ranked over a pin/cadence change: it is the one that stops all proving). No value rides.
        target: { kind: "access-policy", canaryOp: this.canaryOpOf(prior, next) },
      });
      return this.getCanaryView();
    }

    // canaryOpOf names WHICH canary control an owner's change actually moved (G036). PURE. Ordering is the
    // diagnostic ranking, not the field order: a DISABLE is the fact that matters most (it stops every
    // destination being proven), then an ENABLE, then the coverage pin, then the cadence.
    canaryOpOf(prior: CanaryConfig, next: CanaryConfig): "enable" | "disable" | "pin" | "cadence" {
      if (prior.enabled && !next.enabled) return "disable";
      if (!prior.enabled && next.enabled) return "enable";
      if (JSON.stringify(prior.destinationIds ?? null) !== JSON.stringify(next.destinationIds ?? null)) return "pin";
      return "cadence";
    }

    // canaryDue is the INTERNAL first phase of a flight: the cron driver asks "is the canary due?" and,
    // if so, the DO atomically allocates the flight (a fresh runId PER DESTINATION + a sequence), takes
    // the in-flight lease, and hands the Worker a descriptor per destination. The Worker flies each in
    // turn and posts the results to canaryComplete. A disabled bird is never due; a flight still in
    // flight within the lease is not re-flown; a stale lease (an evicted worker) is reclaimed.
    async canaryDue(nowMs: number): Promise<{ due: boolean; run?: CanaryFlightPlan }> {
      const s = await this.ensureCanaryState();
      if (!s.config.enabled) return { due: false };
      if (s.inFlight && s.inFlightSince !== undefined && nowMs - s.inFlightSince < CANARY_LEASE_MS) {
        return { due: false };
      }
      if (s.nextRunAt !== null && s.nextRunAt > nowMs) return { due: false };
      // G091: we are about to ALLOCATE a flight while the PREVIOUS one is still marked in flight -- i.e. its
      // lease expired and its completion never arrived. The old flight is silently abandoned and re-allocated,
      // which is exactly why "canary lastRunAt keeps sliding" had no cause anywhere. Count the abandonment.
      if (s.inFlight) await recordCanaryLoss(this.state.storage, "lost-flight");
      const effective = await this.resolveEffectiveDests(s);
      const runSeq = s.runSeq + 1;
      const byId = new Map(s.dests.map((d) => [d.destinationId, d]));
      const dests: CanaryRunDescriptor[] = effective.map((destinationId, i) => ({
        runId: newULID(nowMs + i),
        runSeq,
        destinationId,
        cleanupRunId: byId.get(destinationId)?.lastRunId ?? null,
      }));
      s.inFlight = true;
      s.inFlightSince = nowMs;
      s.runSeq = runSeq;
      await this.saveCanaryState(s);
      return { due: true, run: { runSeq, dests } };
    }

    // canaryComplete is the INTERNAL second phase: the Worker posts ONE result PER DESTINATION, the DO
    // clears the lease, updates each destination's liveness and cleanup id, folds the whole flight into
    // the history ring, recomputes the AGGREGATE liveness (worst across destinations), re-bases the next
    // flight, and reports the per-destination threshold crossings (which destination fell dead, which
    // recovered) so the Worker fires exactly one alert per transition. A death is sticky per destination:
    // a later inconclusive (ailing) flight does not clear it; only an alive flight resurrects it.
    async canaryComplete(req: { run?: unknown; results?: unknown }): Promise<{ transitions: Array<{ destinationId: string | null; label: string; transitioned: "dead" | "recovered" }> }> {
      const run = req.run as CanaryFlightPlan | undefined;
      const results = req.results as CanaryCheckResult[] | undefined;
      if (!run || !Array.isArray(run.dests) || !Array.isArray(results)) {
        // G091: an unusable completion body throws past EVERY destination's liveness update in that flight, so
        // the whole flight's evidence is lost and the lease stays taken until it expires. Count it (never the body).
        await recordCanaryLoss(this.state.storage, "malformed-completion");
        throw new Error("canary completion requires a run and results");
      }
      const s = await this.ensureCanaryState();
      const { list } = await this.loadDestinations();
      const labelOf = (id: string | null): string => (id === null ? "the default destination" : list.find((x) => x.id === id)?.label ?? id);
      const at = nowMillisISO();
      const runIdByDest = new Map(run.dests.map((d) => [d.destinationId, d.runId]));
      const byId = new Map(s.dests.map((d) => [d.destinationId, d]));
      const flightResults: CanaryCheck[] = [];
      const transitions: Array<{ destinationId: string | null; label: string; transitioned: "dead" | "recovered" }> = [];
      for (const result of results) {
        if (!result || typeof result.status !== "string") {
          // G091: ONE destination's result row was unusable and is skipped, so THAT destination's bird FREEZES
          // on its last verdict forever while the aggregate keeps reporting. Count the skip (never the row).
          await recordCanaryLoss(this.state.storage, "malformed-result");
          continue;
        }
        const destId = result.destinationId ?? null;
        const check: CanaryCheck = {
          at,
          ok: result.status === "alive",
          status: result.status,
          durationMs: typeof result.durationMs === "number" ? result.durationMs : 0,
          destinationId: destId,
          runSeq: run.runSeq,
          aspects: Array.isArray(result.aspects) ? result.aspects : [],
          byteDelta: typeof result.byteDelta === "number" ? result.byteDelta : null,
          deadReason: result.deadReason ?? null,
          // ailingCause folds through only when the Worker actually set one (the "ailing" override branch
          // of finalise()); absent on every dead/alive/pending result, and on any pre-this-field record.
          ...(result.ailingCause ? { ailingCause: result.ailingCause } : {}),
        };
        flightResults.push(check);
        let ds = byId.get(destId);
        const prev = ds?.status ?? "pending";
        if (!ds) {
          ds = { destinationId: destId, status: "pending", lastRunAt: null, lastRunId: null, deadSince: null, consecutivePasses: 0, lastCheck: null };
          byId.set(destId, ds);
        }
        ds.lastRunAt = at;
        ds.lastRunId = runIdByDest.get(destId) ?? ds.lastRunId;
        ds.lastCheck = check;
        if (result.status === "dead") {
          if (prev !== "dead") transitions.push({ destinationId: destId, label: labelOf(destId), transitioned: "dead" });
          if (!ds.deadSince) ds.deadSince = at;
          ds.status = "dead";
          ds.consecutivePasses = 0;
        } else if (result.status === "alive") {
          if (prev === "dead") transitions.push({ destinationId: destId, label: labelOf(destId), transitioned: "recovered" });
          ds.deadSince = null;
          ds.status = "alive";
          ds.consecutivePasses = prev === "alive" ? ds.consecutivePasses + 1 : 1;
        } else {
          ds.status = prev === "dead" ? "dead" : result.status;
          ds.consecutivePasses = 0;
        }
      }
      // Keep per-destination state only for the destinations the canary currently flies to (so removing a
      // destination drops its bird), and recompute the aggregate liveness from that set.
      const effective = new Set(await this.resolveEffectiveDests(s));
      s.dests = [...byId.values()].filter((d) => effective.has(d.destinationId));
      const flightStatus = aggregateLiveness(flightResults.map((c) => c.status));
      s.history = [...s.history, { at, runSeq: run.runSeq, status: flightStatus, results: flightResults }].slice(-CANARY_HISTORY_CAP);
      // Append each threshold crossing this flight to the bounded transition ring (canary-transition-only-
      // pages-once): the durable record of WHEN each destination flipped dead/recovered, so a standing
      // "paged once" death stays observable in the pack long after the single page. Newest-last, capped.
      if (transitions.length > 0) {
        const priorRing = Array.isArray(s.transitions) ? s.transitions : [];
        const newRing: CanaryTransition[] = transitions.map((t) => ({ at, destinationId: t.destinationId, to: t.transitioned, runSeq: run.runSeq }));
        s.transitions = [...priorRing, ...newRing].slice(-CANARY_TRANSITION_CAP);
      }
      s.inFlight = false;
      s.lastRunAt = at;
      s.status = aggregateLiveness(s.dests.map((d) => d.status));
      s.nextRunAt = Date.now() + s.config.intervalSeconds * 1000;
      await this.saveCanaryState(s);
      return { transitions };
    }

    // canaryRunNow arms an immediate flight (the console "fly now" control): it makes the canary due and
    // reclaims a stale lease, so the next cron tick (or the router's canaryNow hook) flies it at once. It
    // refuses on a disabled bird. It does not itself do the I/O (the DO never does).
    //
    // G091: THIS IS THE SECOND PLACE AN EXPIRED LEASE IS RECLAIMED, and until now only the first one said so.
    // canaryDue counts the same abandonment as `lost-flight` -- the record that exists, in the ledger's own
    // words, because "a flight allocated under a lease that then expired is silently re-allocated on the next
    // tick, so 'lastRunAt keeps sliding' has no cause". Reclaiming it HERE instead cleared `inFlight`, so the
    // count canaryDue would have taken on the next tick was never taken and the flight was lost with nothing
    // saying so. The route this sits behind is POST /admin/canary/run, the console "Fly now" button: the
    // action an operator takes BECAUSE the bird looks stuck is exactly the action that erased the evidence of
    // why it was stuck. Booked through the same closed vocabulary rather than a second mechanism.
    //
    // The two sites also disagreed at the boundary EXACTLY, which is the "each branch correct about its own
    // case" trap: canaryDue holds the lease while `elapsed < CANARY_LEASE_MS`, so elapsed === the lease is
    // EXPIRED there; this one reclaimed only past `> CANARY_LEASE_MS`, so at that one instant the cron path
    // reclaimed-and-counted while the operator path left the bird wedged. They now share one edge.
    async canaryRunNow(): Promise<{ ok: boolean }> {
      const s = await this.ensureCanaryState();
      if (!s.config.enabled) {
        await recordAdminRefusal(this.state.storage, "canary-run", "disabled"); // G146
        throw new Error("the canary is disabled");
      }
      s.nextRunAt = 0;
      if (s.inFlight && (s.inFlightSince === undefined || Date.now() - s.inFlightSince >= CANARY_LEASE_MS)) {
        s.inFlight = false;
        // Counted only on a lease this call actually RECLAIMS. A bird that is not in flight has lost nothing,
        // and a lease still inside its window is a flight that may yet complete, so neither books anything:
        // the over-fix here would be to count a loss every time the operator pressed the button.
        await recordCanaryLoss(this.state.storage, "lost-flight");
      }
      await this.saveCanaryState(s);
      return { ok: true };
    }

    // getCanaryTransitions is the LIGHTWEIGHT support-pack view of the canary's liveness + its bounded
    // transition ring (canary-transition-only-pages-once). It returns the closed aggregate status, whether the
    // bird is enabled, the count of destinations CURRENTLY dead, and the newest-last transition ring (each a
    // clamped time + destination id + closed to-state + flight number). It is far lighter than getCanaryView
    // (no flight bodies, no per-destination aspect results), so the pack can carry "the canary paged once at T
    // and has been dead since" cheaply. Redaction-safe: enums / ints / clamped timestamps / the customer's own
    // destination ids; never a byte value, a key, or an object key. Best-effort read (never mutates state).
    async getCanaryTransitions(): Promise<{ enabled: boolean; status: CanaryLiveness; deadDestinations: number; transitionCount: number; transitions: CanaryTransition[]; nextRunAt: number | null; deadDetail: Array<{ destinationId: string | null; at: string | null; deadReason: string | null; byteDelta: number | null; failedAspects: string[] }> }> {
      const s = await this.ensureCanaryState();
      const ring = Array.isArray(s.transitions) ? s.transitions : [];
      const deadRows = s.dests.filter((d) => d.status === "dead");
      // deadDetail (support-pack Wave A2, G035/G058/G290): the WHY of each current death, from the destination's
      // latest flight (lastCheck). Without it the pack carried only that a bird flipped dead, never the coarse
      // reason or which aspect failed, so the console fabricated fallbacks the customer then reported. Every
      // field here is already redaction-safe by the CanaryCheck contract (a coarse reason line that never
      // carries a key/value/object-key, the closed aspect keys, an int byte-delta); the pack re-clamps it.
      const deadDetail = deadRows.map((d) => {
        const lc = d.lastCheck;
        const failedAspects = lc && Array.isArray(lc.aspects) ? lc.aspects.filter((a) => a.outcome === "fail" || a.outcome === "skip").map((a) => a.key) : [];
        return {
          destinationId: d.destinationId,
          at: lc?.at ?? null,
          deadReason: lc?.deadReason ?? null,
          byteDelta: lc?.byteDelta ?? null,
          failedAspects,
        };
      });
      return {
        enabled: s.config.enabled,
        status: s.config.enabled ? s.status : "disabled",
        deadDestinations: deadRows.length,
        transitionCount: ring.length,
        transitions: ring.slice(-CANARY_TRANSITION_CAP),
        nextRunAt: typeof s.nextRunAt === "number" ? s.nextRunAt : null,
        deadDetail,
      };
    }
  };
}
