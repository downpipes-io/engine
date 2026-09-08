// The OTLP/HTTP metrics push drain: on each cron tick, if an OTLP
// collector destination is configured AND enabled, read the CURRENT canonical backup-health metric snapshot
// straight off the scheduler DO's own run/replication state (scheduler-do-otlp-push.ts's otlpMetricsSnapshot,
// the SAME accessor a Prometheus /metrics endpoint would read -- no separate accumulator, no recomputed
// freshness), shape it as an OTLP/HTTP JSON ResourceMetrics payload (cron/otlp-push-shape.ts), and POST it
// through the bespoke egress-secure sender (notify/otlp-push-sender.ts) with the one configured auth header.
// UNLIKE the SIEM audit-log push (cron/siem-push-pass.ts) there is NO cursor: every tick re-reads the
// current state and pushes a fresh snapshot, so a missed tick is simply a gap in the customer's own time
// series, never a backlog or a redelivery concern. OPT-IN: no destination configured, or the operator has
// it disabled, is a silent no-op (no phone-home unless wired), mirroring the SIEM push drain and
// runBeaconEmitPass's opt-in gate. The outbound fetch lives here (the Worker/pass layer), never the DO
// (design rule F11).

import { loadConfigWrapKey, OTLP_PUSH_SECRET_AAD, resolveConfigSecret } from "../admin/config-secret.ts";
// Imported from the leaf router-helpers.ts, NOT the router.ts hub, mirroring cron/siem-push-pass.ts's own
// import (see that file's comment: importing schedulerStub/doURL from router.ts here would create a cycle
// through admin/router.ts -> admin/router-push.ts -> cron/*-pass.ts; router-helpers.ts is the true leaf).
import { doURL, type schedulerStub } from "../admin/router-helpers.ts";
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { deliverOtlpPush, type OtlpPushSendResult } from "../notify/otlp-push-sender.ts";
import type { OtlpPushDestinationRecord } from "../sched/scheduler-do-base.ts";
import { causeDigest } from "../seal/slice.ts";
import { notePushTrailWriteFailure } from "./cron-fault-ledger.ts";
import { buildOtlpResourceMetrics, buildOtlpResourceMetricsChunks, type OtlpDownpipeMetrics } from "./otlp-push-shape.ts";
// The pass-level failure vocabulary is SHARED with the SIEM drain (one closed set for both push trails, so
// the pack's siemPush/otlpPush sections and the bot reason over the same codes).
import type { PushPassFailCode } from "./siem-push-pass.ts";

// OTLP_CONFIG_UNREADABLE_PREFIX is the ONE message prefix fetchOtlpPushConfig throws when the DO round-trip
// itself failed (as opposed to the secret unwrap failing underneath it). classifyOtlpConfigFault matches on
// this engine-owned literal ONLY, to pick a closed code; the message itself is never recorded anywhere.
const OTLP_CONFIG_UNREADABLE_PREFIX = "OTLP push destination configuration unreadable";

// classifyOtlpConfigFault coarsens a config-step throw into a closed PushPassFailCode (support-pack G247),
// the OTLP twin of classifyPushConfigFault. The message, the DO status and the unwrap error text never
// leave this function.
export function classifyOtlpConfigFault(e: unknown): Extract<PushPassFailCode, "config-unreadable" | "secret-unresolvable"> {
  const m = e instanceof Error ? e.message : "";
  return m.startsWith(OTLP_CONFIG_UNREADABLE_PREFIX) ? "config-unreadable" : "secret-unresolvable";
}

// ResolvedOtlpPushConfig is the OTLP push destination with its auth secret RESOLVED to plaintext (at the
// moment of use only; never persisted or logged). gen is the config's generation id (the straggler guard):
// the drain carries it in the outcome it posts back so the DO can drop an outcome for a since-cleared/
// replaced config, mirroring ResolvedPushConfig.
export interface ResolvedOtlpPushConfig {
  endpoint: string;
  authHeaderName: string;
  authHeaderValue: string;
  enabled: boolean;
  gen: string;
}

// OtlpPushDeliveryResult is the outcome the drain records: ok, an optional HTTP status, an optional coarse
// reason on failure (a DeliveryFailCode string), plus the HONEST accounting of what was actually shaped into
// the body -- downpipeCount is the post-cap number of downpipes SENT (never the pre-cap snapshot length), and
// truncated flags an over-cap snapshot (mon-otlp F3). It NEVER carries a body, a url, or a secret.
export interface OtlpPushDeliveryResult {
  ok: boolean;
  status?: number;
  reason?: string;
  downpipeCount: number;
  truncated: boolean;
  // droppedCount SIZES the truncation (G164): how many downpipes the OTLP_PUSH_DOWNPIPE_CAP left out of this
  // push. truncated:true rode alone before, so support could not answer the only question the customer asks --
  // "how many of our downpipes are missing from the dashboards?" -- once the fleet outgrew the cap. 0 when the
  // whole (post-cap) snapshot fitted.
  droppedCount: number;
  // rejectedDataPoints carries an OTLP partial_success count through to the trail: the push was accepted
  // (ok true) but the collector dropped this many datapoints server-side. A LOUD partial-loss signal, never
  // a silent full success (finding F1). Absent when the collector accepted everything.
  rejectedDataPoints?: number;
}

// fetchOtlpPushConfig reads the RAW OTLP push destination record (GET /otlp-push-config, INTERNAL-ONLY,
// never a public admin route) and resolves the sealed auth secret to plaintext, mirroring fetchPushConfig.
// wrapKey is the resolved CONFIG_WRAP_KEY; a present envelope with no key configured throws loudly
// (resolveConfigSecret), exactly like the destination credential and SIEM push paths.
export async function fetchOtlpPushConfig(scheduler: ReturnType<typeof schedulerStub>, wrapKey: Uint8Array | undefined): Promise<ResolvedOtlpPushConfig | null> {
  const resp = await scheduler.fetch(doURL("/otlp-push-config"), { method: "GET" });
  if (!resp.ok) throw new Error(`${OTLP_CONFIG_UNREADABLE_PREFIX} (DO responded ${resp.status})`);
  const { record } = (await resp.json()) as { record?: OtlpPushDestinationRecord | null };
  if (!record) return null;
  const authHeaderValue = await resolveConfigSecret(wrapKey, record.authHeaderValue, OTLP_PUSH_SECRET_AAD);
  return { endpoint: record.endpoint, authHeaderName: record.authHeaderName, authHeaderValue, enabled: record.enabled, gen: record.gen };
}

// deliverResolvedOtlpPush builds the OTLP ResourceMetrics body from the CURRENT snapshot and sends it,
// mirroring deliverResolvedPush. Exported so the drain and a future admin test-send route can share one path.
// It carries the shaper's ACTUAL downpipeCount + truncated back out (never the pre-cap input length), so the
// caller records what was really sent, not what it was handed (mon-otlp F3).
export async function deliverResolvedOtlpPush(cfg: ResolvedOtlpPushConfig, downpipes: OtlpDownpipeMetrics[], nowMs: number): Promise<OtlpPushDeliveryResult> {
  const shaped = buildOtlpResourceMetrics(downpipes, nowMs);
  const r = await deliverOtlpPush(cfg.endpoint, shaped.body, cfg.authHeaderName, cfg.authHeaderValue);
  return toDeliveryResult(r, shaped.downpipeCount, shaped.truncated, shaped.droppedCount);
}

function toDeliveryResult(r: OtlpPushSendResult, downpipeCount: number, truncated: boolean, droppedCount: number): OtlpPushDeliveryResult {
  return {
    ok: r.ok,
    ...(r.status !== undefined ? { status: r.status } : {}),
    ...(r.code !== undefined ? { reason: r.code } : {}),
    downpipeCount,
    truncated,
    droppedCount,
    ...(r.rejectedDataPoints !== undefined ? { rejectedDataPoints: r.rejectedDataPoints } : {}),
  };
}

// recordOutcome posts ONE delivery attempt outcome back to the DO (the trail authority), stamped with the
// config's gen so the DO can drop it if the destination was cleared/replaced mid-delivery. Best-effort: a
// record hiccup is logged and swallowed rather than turning an already-classified delivery outcome into a
// crashed pass, mirroring cron/siem-push-pass.ts's recordOutcome.
async function recordOutcome(
  scheduler: ReturnType<typeof schedulerStub>,
  attempt: { ok: boolean; httpStatus?: number; reason?: string; downpipeCount: number; truncated?: boolean; droppedCount?: number; rejectedDataPoints?: number; gen: string; causeDigest?: string },
): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/otlp-push-record"), {
      method: "POST",
      body: JSON.stringify(attempt),
      headers: { "content-type": "application/json" },
    });
    // G293: the twin of the SIEM trail write -- the response was never read, so a lost trail row read as a
    // recorded one and the metrics feed's trail went quietly stale while the pass reported success.
    if (!resp.ok) notePushTrailWriteFailure("otlp");
  } catch (e) {
    notePushTrailWriteFailure("otlp");
    log("error", `otlp push outcome record skipped: ${(e as Error).message}`);
  }
}

// recordOtlpPassFault records a PRE-DELIVERY fault on the OTLP push trail (support-pack G247), the twin of
// cron/siem-push-pass.ts's recordPassFault: before it, a malformed wrap key, an unreadable DO config or an
// unreadable metrics snapshot took an early `return false` that wrote NOTHING, so "our Grafana/collector
// stopped receiving metrics" arrived with an empty trail. The DO drops an outcome whose gen does not match
// the live config, so a fault raised before the config resolved re-reads the raw record for its gen alone
// (an absent record means OTLP push is not configured: nothing to record; an unreachable DO means the trail
// itself is unwritable). `reason` is a closed PushPassFailCode, never a message, status line or endpoint.
// `cause` (G164) is the RAW throw behind the closed reason. It is reduced to a 12-hex one-way digest here and
// nowhere else, so the trail row can be joined to the customer's own Workers Logs line for the same fault.
async function recordOtlpPassFault(scheduler: ReturnType<typeof schedulerStub>, reason: PushPassFailCode, gen?: string, cause?: unknown): Promise<void> {
  let g = gen;
  if (g === undefined) {
    try {
      const resp = await scheduler.fetch(doURL("/otlp-push-config"), { method: "GET" });
      if (!resp.ok) return;
      const { record } = (await resp.json()) as { record?: { gen?: unknown } | null };
      if (!record || typeof record.gen !== "string") return;
      g = record.gen;
    } catch {
      return;
    }
  }
  const digest = cause !== undefined ? await causeDigest((cause as Error)?.message ?? "") : undefined;
  await recordOutcome(scheduler, { ok: false, reason, downpipeCount: 0, gen: g, ...(digest !== undefined ? { causeDigest: digest } : {}) });
}

// runOtlpPushPass is the cron drain, wired into drive() alongside runSiemPushPass. Returns whether the pass
// COMPLETED (true) or bailed unexpectedly (false), the same false-green signal every tallyPass'd pass
// reports. A REJECTED delivery to the customer's own collector is still a COMPLETED pass (the outcome is
// recorded on the trail); only an unreadable DO round-trip counts against passErrors -- the fail-open
// contract this feature must never break a backup pass over.
export async function runOtlpPushPass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<boolean> {
  // loadConfigWrapKey is guarded and has its OWN arm so the trail can
  // name the wrap key as the cause (wrap-key-invalid) rather than blaming a DO read that never ran.
  let wrapKey: Uint8Array | undefined;
  try {
    wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
  } catch (e) {
    log("error", `otlp push pass: config wrap key unusable: ${(e as Error).message}`);
    await recordOtlpPassFault(scheduler, "wrap-key-invalid", undefined, e);
    return false;
  }
  let cfg: ResolvedOtlpPushConfig | null;
  try {
    cfg = await fetchOtlpPushConfig(scheduler, wrapKey);
  } catch (e) {
    log("error", `otlp push pass: configuration unreadable: ${(e as Error).message}`);
    await recordOtlpPassFault(scheduler, classifyOtlpConfigFault(e), undefined, e);
    return false;
  }
  // Opt-in: no destination configured, or the operator has it disabled, is a silent no-op.
  if (!cfg?.enabled) return true;
  let downpipes: OtlpDownpipeMetrics[];
  try {
    const snapResp = await scheduler.fetch(doURL("/otlp-metrics-snapshot"), { method: "GET" });
    const doc = (await snapResp.json()) as { downpipes?: OtlpDownpipeMetrics[] };
    downpipes = Array.isArray(doc.downpipes) ? doc.downpipes : [];
  } catch (e) {
    log("error", `otlp push pass: metrics snapshot unreadable: ${(e as Error).message}`);
    await recordOtlpPassFault(scheduler, "snapshot-unreadable", cfg.gen);
    return false;
  }
  // The delivery TAIL (shape -> chunk -> send -> record) is in its own try/catch, like every DO round-trip
  // above it: deliverOtlpPush is non-throwing by contract and the shaper is pure, but a contract-violating
  // throw must still record a failure and surface as the false-green signal, rather than escaping
  // runOtlpPushPass or skipping the tick silently.
  //
  // CHUNKING: a single POST covering a large fleet can exceed a vendor's
  // OTLP/HTTP request-size cap (New Relic's ~1 MB, the tightest of the targets), which would otherwise fail
  // the WHOLE tick silently every 15 minutes. buildOtlpResourceMetricsChunks splits the (post-cap) snapshot
  // into conservative, independently-sized chunks; EACH is sent and recorded as its OWN delivery outcome, so
  // one oversized fleet degrades to "some chunks delivered, some did not" (all individually visible on the
  // trail) rather than an opaque all-or-nothing failure.
  try {
    const chunks = buildOtlpResourceMetricsChunks(downpipes, Date.now());
    for (const chunk of chunks) {
      const sent = await deliverOtlpPush(cfg.endpoint, chunk.body, cfg.authHeaderName, cfg.authHeaderValue);
      const result = toDeliveryResult(sent, chunk.downpipeCount, chunk.truncated, chunk.droppedCount);
      await recordOutcome(scheduler, {
        ok: result.ok,
        ...(result.status !== undefined ? { httpStatus: result.status } : {}),
        ...(result.reason !== undefined ? { reason: result.reason } : {}),
        // Record the ACTUAL number of downpipes shaped into THIS chunk, NEVER the pre-cap snapshot length,
        // and flag an over-cap truncation, so a large fleet's trail never over-reports (mon-otlp F3).
        downpipeCount: result.downpipeCount,
        ...(result.truncated ? { truncated: true } : {}),
        // G164: SIZE the truncation. The boolean says "you are missing downpipes"; this says how many.
        ...(result.droppedCount > 0 ? { droppedCount: result.droppedCount } : {}),
        ...(result.rejectedDataPoints !== undefined ? { rejectedDataPoints: result.rejectedDataPoints } : {}),
        gen: cfg.gen,
      });
    }
    return true;
  } catch (e) {
    log("error", `otlp push pass: shape-or-deliver fault: ${(e as Error).message}`);
    // Record the fault as a failure so the tick is not lost silently; a record hiccup here is itself
    // swallowed by recordOutcome. The shaper threw (no honest shaped count exists), so the pre-cap length is
    // the best coarse "attempted N" for this FAULT row only -- an ok:false entry, never a success misreport.
    await recordOutcome(scheduler, { ok: false, reason: "shape-or-deliver-fault", downpipeCount: downpipes.length, gen: cfg.gen, causeDigest: await causeDigest((e as Error)?.message ?? "") });
    return false;
  }
}
