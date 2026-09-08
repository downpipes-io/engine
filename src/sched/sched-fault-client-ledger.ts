// clientDiagnostics (G172-G181, and G097's console half): the BROWSER's own evidence, which rides IN the
// customer's support pack rather than in any background beacon.
//
// It is its own module because it is the one subject in this family that is not an engine fault at all: every
// field is a fact only the browser held. Moved verbatim out of./sched-fault-ledger.ts, whole:
// the closed vocabularies, the ring shape, the pure applier and the recorder that gates on them are all here,
// so the module boundary is the FAMILY boundary. The redaction rule these records are written under is stated
// once, in ./sched-fault-ledger.ts, and binds this file.

import { type FaultCountAgg, type LedgerStorage, bumpCount, writeLedger } from "./sched-fault-core.ts";

// ---- clientDiagnostics (G172-G181, G097's console half): the browser evidence that rode IN the pack ---
//
// The console is where the customer's failure is SEEN and nowhere it is RECORDED: a blank page on boot, a
// console-Worker 500, a bulk protect that created 300 of 1000 and stopped, an update stuck at "Still
// verifying", a dual-control route 404ing after a partial upgrade. All of it died with the tab.
//
// NO TELEMETRY BEACON: the console keeps its own bounded closed-class ring in the browser
// and POSTS it, at pack-generation time, into THIS record, which the engine then signs into the pack the
// customer generates and shares. Nothing is sent anywhere in the background; the evidence is point-in-time and
// travels only inside the artefact the customer chose to share. THIS is the engine-side sink: the single
// redaction chokepoint for an UNTRUSTED browser-authored body. Every field is re-validated against a closed
// set or clamped to a bounded integer HERE, so a compromised/buggy console structurally cannot write an error
// message, a stack, a screen name, a route path, an item name or a URL into the pack.
export const CLIENT_CRASH_PHASES = ["boot", "render", "route-invariant", "chunk-load"] as const;
const CLIENT_CRASH_PHASE_SET: ReadonlySet<string> = new Set(CLIENT_CRASH_PHASES);

// G172 / G181: the multi-item operations whose casualty list lived in a modal.
export const CLIENT_BULK_OPS = ["bulk-create", "bulk-protect", "bulk-run", "bulk-disable", "fleet-drill", "reattach-all", "attach-confirm-poll"] as const;
const CLIENT_BULK_OP_SET: ReadonlySet<string> = new Set(CLIENT_BULK_OPS);
export const CLIENT_BULK_FAIL_CLASSES = ["rate-limited", "halted-401", "engine-5xx", "network", "refused", "shape-mismatch", "timed-out"] as const;
const CLIENT_BULK_FAIL_SET: ReadonlySet<string> = new Set(CLIENT_BULK_FAIL_CLASSES);

// G176: where the update settle/verify journey ENDED.
export const CLIENT_SETTLE_STATES = ["settled", "stalled", "unknown", "signed-out"] as const;
const CLIENT_SETTLE_STATE_SET: ReadonlySet<string> = new Set(CLIENT_SETTLE_STATES);

// G178: the console<->engine CONTRACT skew a partial upgrade produces.
export const CLIENT_SKEW_KINDS = ["route-missing", "mode-mismatch", "unknown-enum", "missing-field"] as const;
const CLIENT_SKEW_KIND_SET: ReadonlySet<string> = new Set(CLIENT_SKEW_KINDS);
export const CLIENT_ROUTE_FAMILIES = ["restore", "dual-control", "downpipes", "destinations", "keys", "licence", "notify", "rbac", "sources", "other"] as const;
const CLIENT_ROUTE_FAMILY_SET: ReadonlySet<string> = new Set(CLIENT_ROUTE_FAMILIES);

// G097 (console half) + G174: the console-side write/dispatch faults the ENGINE never sees.
export const CLIENT_FAULT_KINDS = [
  "evidence-write-failed", // G097: the POST that records a drill-evidence row failed (404/500/network/quota) and was caught-and-discarded, so the dated trail silently has a hole
  "worker-unhandled-500", // G174: the console WORKER (a separate script) threw and served an "internal error" page
  "worker-asset-miss", // G174: the console shell asked for a chunk-<hash>.js the deploy no longer has (the blank page after a deploy)
  "worker-url-parse-failed", // G174: the console worker could not parse its own request URL
] as const;
const CLIENT_FAULT_KIND_SET: ReadonlySet<string> = new Set(CLIENT_FAULT_KINDS);

export const CLIENT_DIAG_KEY = "diag:clientdiag";
export const CLIENT_DIAG_RING_CAP = 16;
const CLIENT_COUNT_CAP = 100_000;
// The console's own BUILD id: a product-controlled version string (the same redaction class as engine.version,
// which the pack already carries). Clamped, control-stripped, and restricted to the shape a version can take,
// so it can never become a smuggling channel for a message or a path.
const CONSOLE_BUILD_ID_PATTERN = /^[0-9A-Za-z._+-]{1,64}$/;

export interface ClientBulkOutcome {
  at: string;
  op: string; // closed CLIENT_BULK_OPS
  attempted: number;
  succeeded: number;
  failed: number;
  halted: boolean;
  timedOut: boolean;
  pollFailures: number;
  failedByClass: FaultCountAgg; // closed CLIENT_BULK_FAIL_CLASSES -> counts
}
export interface ClientSettleJourney {
  at: string;
  terminalState: string; // closed CLIENT_SETTLE_STATES
  settleAttempts: number;
  statusReadFailures: number;
  pollAttempts: number;
  pollCeilingHit: boolean;
  unexpectedOutcome: boolean;
}
export interface ClientDiagnostics {
  consoleBuildId: string | null; // the skew PAIR's other half (engine.version is already in the pack)
  crashes: FaultCountAgg; // closed phase -> {count,lastAt}
  faults: FaultCountAgg; // closed CLIENT_FAULT_KINDS -> {count,lastAt}
  skew: FaultCountAgg; // "<routeFamily>|<skewKind>" -> {count,lastAt}
  bulkOutcomes: ClientBulkOutcome[]; // newest-last, capped
  settleJourneys: ClientSettleJourney[]; // newest-last, capped
  at: string; // when the console last signed its ring into the engine
}

const EMPTY_CLIENT_DIAG: ClientDiagnostics = { consoleBuildId: null, crashes: {}, faults: {}, skew: {}, bulkOutcomes: [], settleJourneys: [], at: "" };

// clampInt is the bounded-integer coercion every count on the untrusted body goes through.
function clampInt(v: unknown, cap = CLIENT_COUNT_CAP): number {
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.min(cap, Math.floor(v)) : 0;
}

/**
 * applyClientDiagnostics folds ONE untrusted console-authored ring into the durable record. PURE, and the
 * SINGLE REDACTION CHOKEPOINT for this aggregate: every enum is closed-set validated (an out-of-vocabulary
 * value is DROPPED, never stored, so no browser string can become a storage key), every count is clamped to a
 * bounded non-negative integer, the build id must match a version-shaped pattern, and NOTHING else on the body
 * is read. An error message, a stack, a screen name, a route path, a downpipe name, an item id or a URL cannot
 * enter this record even if a future console posts one.
 *
 * @param prior - the stored record, if any.
 * @param body - the console's posted ring (UNTRUSTED).
 * @param nowIso - the DO clock as an ISO string (injected, so the validator is deterministic).
 * @returns the new record.
 */
export function applyClientDiagnostics(prior: ClientDiagnostics | undefined, body: unknown, nowIso: string): ClientDiagnostics {
  const rec: ClientDiagnostics = {
    ...EMPTY_CLIENT_DIAG,
    ...(prior ?? {}),
    crashes: { ...(prior?.crashes ?? {}) },
    faults: { ...(prior?.faults ?? {}) },
    skew: { ...(prior?.skew ?? {}) },
    bulkOutcomes: Array.isArray(prior?.bulkOutcomes) ? [...prior.bulkOutcomes] : [],
    settleJourneys: Array.isArray(prior?.settleJourneys) ? [...prior.settleJourneys] : [],
  };
  if (typeof body !== "object" || body === null || Array.isArray(body)) return rec;
  const b = body as Record<string, unknown>;
  rec.at = nowIso;
  if (typeof b.consoleBuildId === "string" && CONSOLE_BUILD_ID_PATTERN.test(b.consoleBuildId)) rec.consoleBuildId = b.consoleBuildId;
  // Crashes: {phase: count}. An unknown phase is dropped.
  if (typeof b.crashes === "object" && b.crashes !== null && !Array.isArray(b.crashes)) {
    for (const [phase, raw] of Object.entries(b.crashes as Record<string, unknown>)) {
      if (!CLIENT_CRASH_PHASE_SET.has(phase)) continue;
      const n = clampInt(raw);
      if (n > 0) bumpCount(rec.crashes, phase, nowIso, n);
    }
  }
  // Console-side faults: {kind: count}. An unknown kind is dropped.
  if (typeof b.faults === "object" && b.faults !== null && !Array.isArray(b.faults)) {
    for (const [kind, raw] of Object.entries(b.faults as Record<string, unknown>)) {
      if (!CLIENT_FAULT_KIND_SET.has(kind)) continue;
      const n = clampInt(raw);
      if (n > 0) bumpCount(rec.faults, kind, nowIso, n);
    }
  }
  // Contract skew: a list of {routeFamily, skewKind}. Both halves closed-set validated, so the composite key
  // space is bounded by the two sets and no route PATH can ever become a key.
  if (Array.isArray(b.skew)) {
    for (const row of b.skew.slice(0, 64)) {
      if (typeof row !== "object" || row === null) continue;
      const r = row as Record<string, unknown>;
      const fam = typeof r.routeFamily === "string" && CLIENT_ROUTE_FAMILY_SET.has(r.routeFamily) ? r.routeFamily : null;
      const kind = typeof r.skewKind === "string" && CLIENT_SKEW_KIND_SET.has(r.skewKind) ? r.skewKind : null;
      if (fam === null || kind === null) continue;
      bumpCount(rec.skew, `${fam}|${kind}`, nowIso, clampInt(r.count) || 1);
    }
  }
  // Bulk outcomes: counts + closed classes only. Never an item name, a prefix or a per-item reason.
  if (Array.isArray(b.bulkOutcomes)) {
    for (const row of b.bulkOutcomes.slice(0, CLIENT_DIAG_RING_CAP)) {
      if (typeof row !== "object" || row === null) continue;
      const r = row as Record<string, unknown>;
      if (typeof r.op !== "string" || !CLIENT_BULK_OP_SET.has(r.op)) continue;
      const failedByClass: FaultCountAgg = {};
      if (typeof r.failedByClass === "object" && r.failedByClass !== null && !Array.isArray(r.failedByClass)) {
        for (const [cls, raw] of Object.entries(r.failedByClass as Record<string, unknown>)) {
          if (!CLIENT_BULK_FAIL_SET.has(cls)) continue;
          const n = clampInt(raw);
          if (n > 0) bumpCount(failedByClass, cls, nowIso, n);
        }
      }
      rec.bulkOutcomes.push({
        at: nowIso,
        op: r.op,
        attempted: clampInt(r.attempted),
        succeeded: clampInt(r.succeeded),
        failed: clampInt(r.failed),
        halted: r.halted === true,
        timedOut: r.timedOut === true,
        pollFailures: clampInt(r.pollFailures),
        failedByClass,
      });
    }
  }
  // Settle journeys (G176): counts, booleans and one closed terminal state. Never the unexpected outcome's
  // string (it is mapped to a boolean at the console and re-checked as a boolean here).
  if (Array.isArray(b.settleJourneys)) {
    for (const row of b.settleJourneys.slice(0, CLIENT_DIAG_RING_CAP)) {
      if (typeof row !== "object" || row === null) continue;
      const r = row as Record<string, unknown>;
      if (typeof r.terminalState !== "string" || !CLIENT_SETTLE_STATE_SET.has(r.terminalState)) continue;
      rec.settleJourneys.push({
        at: nowIso,
        terminalState: r.terminalState,
        settleAttempts: clampInt(r.settleAttempts),
        statusReadFailures: clampInt(r.statusReadFailures),
        pollAttempts: clampInt(r.pollAttempts),
        pollCeilingHit: r.pollCeilingHit === true,
        unexpectedOutcome: r.unexpectedOutcome === true,
      });
    }
  }
  if (rec.bulkOutcomes.length > CLIENT_DIAG_RING_CAP) rec.bulkOutcomes = rec.bulkOutcomes.slice(rec.bulkOutcomes.length - CLIENT_DIAG_RING_CAP);
  if (rec.settleJourneys.length > CLIENT_DIAG_RING_CAP) rec.settleJourneys = rec.settleJourneys.slice(rec.settleJourneys.length - CLIENT_DIAG_RING_CAP);
  return rec;
}

// recordClientDiagnostics is the DO-side writer for POST /client-diag. Best-effort like every other recorder:
// a browser's diagnostic ring must never be able to fail (or slow) the pack build that carries it.
export async function recordClientDiagnostics(storage: LedgerStorage, body: unknown): Promise<void> {
  const nowIso = new Date().toISOString();
  await writeLedger<ClientDiagnostics>(storage, CLIENT_DIAG_KEY, "client-diag", (prior) => applyClientDiagnostics(prior, body, nowIso));
}
