// OTLP/HTTP metrics push destination (mon-otlp, PLAN.md M2): the outbound egress config + bounded
// delivery trail for pushing the canonical backup-health metric snapshot to a customer OTLP/HTTP collector
// (Datadog, New Relic, Dynatrace, Elastic, Splunk Observability), zero-agent, no scraper. Architecturally a
// SNAPSHOT sibling of the SIEM audit-log push (scheduler-do-siem-push.ts): console-set, owner-exclusive, and
// the engine must reconstruct the live secret on every delivery (unlike the ingest-credential grant, which
// only ever stores a one-way hash). UNLIKE the SIEM push there is no cursor (scheduler-do-limits.ts's OTLP
// push types explain why: every cron tick re-reads the CURRENT state and pushes a fresh snapshot, so a
// missed tick is a gap in the customer's own time series, never a backlog). This mixin owns the storage
// read/write + validation + redaction + audit + the metrics-snapshot READ; the outbound fetch itself lives
// OUTSIDE the DO (cron/otlp-push-pass.ts, design rule F11 -- the DO never makes a network call to a
// customer-controlled host).

import { isWrappedSecret, type WrappedSecret } from "../admin/config-secret.ts";
import type { AuthMethod } from "../admin/identity.ts";
import { isAllowedWebhookUrl } from "../notify.ts";
import { allDestinationIds } from "./destinations.ts";
import { recordConfigCoercion } from "./sched-fault-ledger.ts";
import {
  AuthError,
  type DestReplState,
  isForbiddenPushHeaderName,
  isValidPushHeaderValue,
  OTLP_PUSH_CONFIG_KEY,
  OTLP_PUSH_TRAIL_CAP,
  OTLP_PUSH_TRAIL_KEY,
  type OtlpDestinationHealth,
  type OtlpDownpipeMetrics,
  type OtlpPushDeliveryAttempt,
  type OtlpPushDestinationRecord,
  type OtlpPushDestinationView,
  type RunHistoryEntry,
  type SchedulerDOCtor,
} from "./scheduler-do-base.ts";
import { nowMillisISO } from "./scheduler-helpers.ts";

// OTLP_PUSH_HEADER_NAME_RE mirrors the SIEM push destination's own header-name shape guard (RFC 7230 token
// character set), 1..100 chars. This is shape defence only; the value it names is the secret.
const OTLP_PUSH_HEADER_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,100}$/;

// classifyOtlpPushRejectReason maps a buildOtlpPushRecord throw to a CLOSED reject-reason class for the
// audit (never the submitted endpoint/header name/secret), mirroring classifyPushRejectReason. There is no
// format/sink selector here (OTLP push is always one OTLP/HTTP JSON shape), so only endpoint-invalid or
// missing-fields apply.
export function classifyOtlpPushRejectReason(e: unknown): "endpoint-invalid" | "missing-fields" {
  const msg = e instanceof Error ? e.message : "";
  return msg.includes("endpoint") ? "endpoint-invalid" : "missing-fields";
}

// countTrailingOtlpFailures derives the CONSECUTIVE failed-attempt count from the tail of the (already
// capped) trail, mirroring countTrailingFailures: no separate storage key, a pure read of the trail's own tail.
function countTrailingOtlpFailures(trail: OtlpPushDeliveryAttempt[]): number {
  let n = 0;
  for (let i = trail.length - 1; i >= 0; i--) {
    if (trail[i]!.ok) break;
    n++;
  }
  return n;
}

// runTimestampSeconds is the newest-OK-run completion time (epoch SECONDS): startedAt + durationMs when the
// duration is known, falling back to startedAt alone (legacy rows lacking durationMs) or Date.now() on a
// malformed ts (should be impossible; the DO always stamps a valid RFC-3339 string), mirroring the same
// "malformed ts falls back to now" idiom cron/siem-push-shape.ts's wireParts uses. Pure and structural (no
// dependency on the full RunHistoryEntry shape), so it is directly unit-testable without a DO.
export function runTimestampSeconds(entry: { startedAt: string; durationMs?: number }): number {
  const startedMs = Date.parse(entry.startedAt);
  const anchorMs = Number.isFinite(startedMs) ? startedMs : Date.now();
  return (anchorMs + (entry.durationMs ?? 0)) / 1000;
}

// runSizeBytes prefers the STORED archive byte total (archiveBytesWritten: what actually landed at the
// destination) over the plaintext bytes total (bytes: the pre-write logical size), falling back to the
// latter only when the former is absent (an older row). undefined when the entry itself is undefined (no
// resolved run yet) or neither field was ever recorded (a legacy row).
export function runSizeBytes(entry: { archiveBytesWritten?: number; bytes?: number } | undefined): number | undefined {
  if (entry === undefined) return undefined;
  return entry.archiveBytesWritten !== undefined ? entry.archiveBytesWritten : entry.bytes;
}

export function OtlpPushMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // getOtlpPushRecordRaw is the INTERNAL full record (including the sealed secret): reached only by
    // GET /otlp-push-config (the drain's own resolution), never a public admin route.
    async getOtlpPushRecordRaw(): Promise<OtlpPushDestinationRecord | null> {
      return (await this.state.storage.get<OtlpPushDestinationRecord>(OTLP_PUSH_CONFIG_KEY)) ?? null;
    }

    async getOtlpPushTrail(): Promise<OtlpPushDeliveryAttempt[]> {
      return (await this.state.storage.get<OtlpPushDeliveryAttempt[]>(OTLP_PUSH_TRAIL_KEY)) ?? [];
    }

    // getOtlpPushView is the REDACTED admin view: the secret and its ciphertext NEVER appear here.
    async getOtlpPushView(): Promise<OtlpPushDestinationView> {
      const record = await this.getOtlpPushRecordRaw();
      const trail = await this.getOtlpPushTrail();
      if (!record) return { present: false, trail };
      return {
        present: true,
        endpoint: record.endpoint,
        authHeaderName: record.authHeaderName,
        enabled: record.enabled,
        setBy: record.setBy,
        setAt: new Date(record.setAt).toISOString(),
        trail,
      };
    }

    // buildOtlpPushRecord validates a client-supplied submission into a stored record (throws -> a 400 /
    // a closed reject-reason class), mirroring buildPushRecord minus the format/sink branching (OTLP push
    // is always one shape, one http-like transport).
    buildOtlpPushRecord(
      req: { endpoint?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown },
      caller: { email: string | null } | null,
    ): OtlpPushDestinationRecord {
      if (typeof req.enabled !== "boolean") throw new Error("OTLP push destination enabled must be a boolean (missing fields)");
      const endpoint = typeof req.endpoint === "string" ? req.endpoint.trim() : "";
      const v = isAllowedWebhookUrl(endpoint);
      if (!v.ok) throw new Error(`OTLP push destination endpoint invalid: ${v.reason}`);
      const authHeaderNameRaw = typeof req.authHeaderName === "string" ? req.authHeaderName.trim() : "";
      const authHeaderName = authHeaderNameRaw === "" ? "Authorization" : authHeaderNameRaw;
      if (!OTLP_PUSH_HEADER_NAME_RE.test(authHeaderName)) {
        throw new Error("OTLP push destination auth header name must be a valid HTTP header name");
      }
      if (isForbiddenPushHeaderName(authHeaderName)) {
        throw new Error("OTLP push destination auth header name must not be content-type or a runtime-controlled header");
      }
      const authHeaderValue: string | WrappedSecret =
        typeof req.authHeaderValue === "string" ? req.authHeaderValue : isWrappedSecret(req.authHeaderValue) ? req.authHeaderValue : "";
      if (authHeaderValue === "") throw new Error("OTLP push destination needs an auth header value (missing fields)");
      // Defence in depth for the plaintext no-wrap-key floor (finding F3): a wrapped value was screened by the
      // router before sealing; a plaintext value is re-checked here so a control char / over-long value can
      // never be stored on any path.
      if (typeof authHeaderValue === "string" && !isValidPushHeaderValue(authHeaderValue)) {
        throw new Error("OTLP push destination auth header value must be within the length cap and free of control characters");
      }
      const setAt = Date.now();
      const setBy = caller?.email ? caller.email : null;
      // A fresh generation id on every set/replace (the straggler guard, see OtlpPushDestinationRecord.gen).
      const gen = crypto.randomUUID();
      return { endpoint: v.url, authHeaderName, authHeaderValue, enabled: req.enabled, setAt, setBy, gen };
    }

    // summariseOtlpPushConfig builds the REDACTION-SAFE inbox-style summary line: the endpoint HOST only,
    // NEVER the auth header value, mirroring summarisePushConfig.
    summariseOtlpPushConfig(req: unknown): string {
      if (req === null || typeof req !== "object") return "Set the OTLP metrics push destination";
      const c = req as { endpoint?: unknown };
      const hostOf = (u: unknown): string => {
        if (typeof u !== "string") return "";
        try {
          return new URL(u).host;
        } catch {
          return ""; // a malformed endpoint never leaks; buildOtlpPushRecord rejects it at execute time
        }
      };
      return `Set the OTLP metrics push destination: ${hostOf(c.endpoint) || "(host)"}`;
    }

    // auditOtlpPushChange records an otlp-push-destination-set/-cleared event with the REUSED
    // push-destination target shape (op + a closed reject-reason class only; the SAME closed shape the SIEM
    // push uses, generic enough to describe either egress feature), mirroring auditPushChange. The ACTION
    // NAME is distinct (otlp-push-destination-set/-cleared, not push-destination-set/-cleared) so an
    // operator's audit trail can tell the two egress features apart.
    async auditOtlpPushChange(
      caller: { method: AuthMethod; email: string | null; sourceIp?: string | null } | null,
      action: "otlp-push-destination-set" | "otlp-push-destination-cleared",
      detail: { op: "set" | "clear"; rejectReason?: "endpoint-invalid" | "missing-fields" },
    ): Promise<void> {
      await this.appendAudit({
        actorEmail: caller?.email ? caller.email : null,
        actorMethod: caller ? caller.method : "access",
        sourceIp: caller?.sourceIp ?? null,
        action,
        outcome: detail.rejectReason ? "failed" : "success",
        target: { kind: "push-destination", op: detail.op, ...(detail.rejectReason ? { rejectReason: detail.rejectReason } : {}) },
      });
    }

    // setOtlpPushDestination is the OWNER-EXCLUSIVE set/replace. KEEP-SECRET (mirroring setSiemPushDestination
    // exactly): an ABSENT/empty authHeaderValue on a set that has an EXISTING record means "keep the currently
    // sealed secret unchanged"; the FIRST-ever create still requires one (buildOtlpPushRecord's "needs an auth
    // header value" 400s). FRESH-CREATE RESET: a set that CREATES a config where none existed resets the
    // trail to empty; an in-place REPLACE leaves it intact (a new gen alone invalidates any in-flight straggler).
    async setOtlpPushDestination(
      req: { endpoint?: unknown; authHeaderName?: unknown; authHeaderValue?: unknown; enabled?: unknown },
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<OtlpPushDestinationView> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may set the OTLP metrics push destination");
      const existing = await this.getOtlpPushRecordRaw();
      const incomingValue = typeof req.authHeaderValue === "string" ? req.authHeaderValue : isWrappedSecret(req.authHeaderValue) ? req.authHeaderValue : "";
      const effectiveReq: typeof req = incomingValue === "" && existing ? { ...req, authHeaderValue: existing.authHeaderValue } : req;
      // G297: THE KEEP-SECRET PATH IS A SILENT NARROWING. An absent-or-unusable authHeaderValue on a set that
      // has an existing record RETAINS THE PRIOR SEALED SECRET and reports success -- which is exactly "we
      // rotated the Datadog key but the engine kept pushing with the old one" (the rotation appeared to land;
      // the engine never took it). Count the keep (a closed class + a count). NOTHING about either secret --
      // not its length, not a digest, not a fragment -- is recorded: presence of the substitution is the whole
      // signal, and it is enough to name the bug.
      if (incomingValue === "" && existing) await recordConfigCoercion(this.state.storage, "otlp-destination", "malformed-secret-kept-prior");
      let rec: OtlpPushDestinationRecord;
      try {
        rec = this.buildOtlpPushRecord(effectiveReq, caller);
      } catch (e) {
        await this.auditOtlpPushChange(caller, "otlp-push-destination-set", { op: "set", rejectReason: classifyOtlpPushRejectReason(e) });
        throw e;
      }
      await this.state.storage.put(OTLP_PUSH_CONFIG_KEY, rec);
      if (!existing) {
        await this.state.storage.delete(OTLP_PUSH_TRAIL_KEY);
      }
      await this.auditOtlpPushChange(caller, "otlp-push-destination-set", { op: "set" });
      return this.getOtlpPushView();
    }

    // clearOtlpPushDestination is the OWNER-EXCLUSIVE delete. NOT dual-control gated (closing an egress is
    // the safe direction, mirroring clearSiemPushDestination). Wipes the trail too, so a destination
    // configured again later starts from a clean slate.
    async clearOtlpPushDestination(
      caller: { method: AuthMethod; email: string | null; subject: string | null; groups: string[]; sourceIp?: string | null } | null,
    ): Promise<{ ok: true }> {
      const resolved = await this.roleForCaller(caller);
      if (resolved.role !== "owner") throw new AuthError("forbidden: only an Owner may clear the OTLP metrics push destination");
      const removed = await this.state.storage.delete(OTLP_PUSH_CONFIG_KEY);
      if (removed) {
        await this.state.storage.delete(OTLP_PUSH_TRAIL_KEY);
        await this.auditOtlpPushChange(caller, "otlp-push-destination-cleared", { op: "clear" });
      }
      return { ok: true };
    }

    // recordOtlpPushOutcome is the drain's own outcome recorder: append ONE bounded trail entry. STRAGGLER
    // GUARD (mirroring recordSiemPushOutcome): the whole call is a NO-OP unless the CURRENT config exists AND
    // its gen equals the outcome's gen, so a delivery in flight when the owner clears/reconfigures cannot
    // attribute its outcome to a freshly-configured (different-gen) destination's trail.
    async recordOtlpPushOutcome(req: {
      ok?: unknown;
      httpStatus?: unknown;
      reason?: unknown;
      downpipeCount?: unknown;
      truncated?: unknown;
      droppedCount?: unknown;
      rejectedDataPoints?: unknown;
      gen?: unknown;
      causeDigest?: unknown;
    }): Promise<{ ok: true }> {
      const current = await this.getOtlpPushRecordRaw();
      const gen = typeof req.gen === "string" ? req.gen : undefined;
      if (!current || current.gen !== gen) return { ok: true };
      const entry: OtlpPushDeliveryAttempt = {
        at: nowMillisISO(),
        ok: req.ok === true,
        ...(typeof req.httpStatus === "number" ? { httpStatus: req.httpStatus } : {}),
        ...(typeof req.reason === "string" ? { reason: req.reason } : {}),
        ...(typeof req.downpipeCount === "number" ? { downpipeCount: req.downpipeCount } : {}),
        ...(req.truncated === true ? { truncated: true } : {}),
        // G164: the SIZE of the truncation, clamped to a non-negative int. truncated:true alone could not tell
        // support how many downpipes vanished from the customer's dashboards when the fleet outgrew the cap.
        ...(typeof req.droppedCount === "number" && Number.isFinite(req.droppedCount) && req.droppedCount > 0 ? { droppedCount: Math.floor(req.droppedCount) } : {}),
        ...(typeof req.rejectedDataPoints === "number" && req.rejectedDataPoints > 0 ? { rejectedDataPoints: req.rejectedDataPoints } : {}),
        // G164: the join key, SHAPE-GATED at the redaction chokepoint (bare 12-hex or nothing), so a drifted
        // or hostile recorder can never turn the field into a free-text seam. It is what lets support join a
        // trail row in the pack to the customer's own Workers Logs line for the SAME fault.
        ...(typeof req.causeDigest === "string" && /^[0-9a-f]{12}$/.test(req.causeDigest) ? { causeDigest: req.causeDigest } : {}),
      };
      const prior = await this.getOtlpPushTrail();
      const trail = [...prior, entry].slice(-OTLP_PUSH_TRAIL_CAP);
      await this.state.storage.put(OTLP_PUSH_TRAIL_KEY, trail);
      if (entry.ok) return { ok: true };
      const failureCount = countTrailingOtlpFailures(trail);
      await this.appendAudit({
        actorEmail: null,
        actorMethod: "engine",
        sourceIp: null,
        action: "otlp-push-delivery-failure",
        outcome: "failed",
        target: { kind: "push-destination", op: "delivery-failure", failureCount },
      });
      return { ok: true };
    }

    // otlpMetricsSnapshot is the MINIMAL read of the EXISTING DO run/replication state behind the canonical
    // backup-health metric set (PLAN.md M2 note: "the metric VALUES come from the same DO state
    // the /metrics endpoint uses"). It reuses the EXACT primitives reconcileAlerts/reconcileReplicationAlerts
    // already read (listDownpipes, the hist:/repl: prefix scans, allDestinationIds) and does NOT recompute
    // any staleness/freshness judgement: it reports RAW facts only (the newest run's timestamp/outcome/
    // duration/size, and each configured destination's last-known-good flag read VERBATIM off
    // DestReplState.lastOk), leaving any "is this stale" threshold entirely to the metric CONSUMER (the
    // SRE's own alerting rule), exactly the idiom PLAN.md names (time - last_success > threshold).
    async otlpMetricsSnapshot(): Promise<{ downpipes: OtlpDownpipeMetrics[] }> {
      const states = await this.listDownpipes();
      const histMap = await this.listAllByPrefix<RunHistoryEntry[]>("hist:");
      const replMap = await this.listAllByPrefix<Record<string, DestReplState>>("repl:");
      const downpipes: OtlpDownpipeMetrics[] = [];
      for (const ds of states) {
        const ring = histMap.get(`hist:${ds.config.id}`) ?? [];
        // WINDOWED counts over the retained run-history ring (bounded at RING_CAP entries per downpipe): the
        // engine holds no separate persistent lifetime tally, so these are exact counts of what the ring
        // CURRENTLY retains, not a true cumulative lifetime counter (see cron/otlp-push-shape.ts for why they
        // ship as OTLP gauges rather than monotonic sums).
        let attemptsTotal = 0;
        let successTotal = 0;
        let failureTotal = 0;
        let newestResolved: RunHistoryEntry | undefined;
        let newestOk: RunHistoryEntry | undefined;
        for (const h of ring) {
          attemptsTotal++;
          if (h.status === "ok") successTotal++;
          // abandoned (a crashed run reclaimed by the lease) counts as a failure here, the SAME mapping
          // reconcileAlerts applies for its MinRun view (an abandoned run must not read as a success).
          else if (h.status === "failed" || h.status === "abandoned") failureTotal++;
          if (h.status !== "in-flight") newestResolved = h; // the ring is newest-last; the last write wins
          if (h.status === "ok") newestOk = h;
        }
        const repl = replMap.get(`repl:${ds.config.id}`) ?? {};
        const destinations: OtlpDestinationHealth[] = [];
        for (const destId of allDestinationIds(ds.config)) {
          const st = repl[destId];
          // Absent repl row means no seal/mirror attempt has landed for this destination yet (a brand-new
          // fan-out leg, or a downpipe that has never run): omit rather than assert either polarity.
          if (st) destinations.push({ id: destId, healthy: st.lastOk });
        }
        downpipes.push({
          id: ds.config.id,
          name: ds.config.name,
          enabled: ds.config.enabled === true,
          ...(newestOk !== undefined ? { lastSuccessTimestampSeconds: runTimestampSeconds(newestOk) } : {}),
          ...(newestResolved !== undefined ? { backupSuccess: (newestResolved.status === "ok" ? 1 : 0) as 0 | 1 } : {}),
          attemptsTotal,
          successTotal,
          failureTotal,
          ...(newestResolved?.durationMs !== undefined ? { durationSeconds: newestResolved.durationMs / 1000 } : {}),
          ...(runSizeBytes(newestResolved) !== undefined ? { sizeBytes: runSizeBytes(newestResolved)! } : {}),
          destinations,
        });
      }
      return { downpipes };
    }
  };
}
