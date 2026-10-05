// Fixture COHERENCE check for the support corpus.
//
// WHY THIS EXISTS. A corpus scenario plants one fault by editing one part of the healthy world. When the edit
// leaves other rows saying the opposite, the pack contradicts itself, and a reader who cross-checks the whole
// pack trusts the healthy rows and reads the fault wrong. The blind-diagnosis baseline measured this
// on three of nine cases: a revoked credential whose preflight, export and canary stayed healthy; a dropped cron
// trigger whose ticks stayed three minutes old; and a benign update over a healthy world that was itself not
// healthy on the current engine. Those cases graded the fixture, not the pack. This check rejects such a pack
// before any grader reads it.
//
// Each rule reads the SIGNED BUNDLE the harness emitted (the bytes a reader sees), never the scenario source.
// A fault that is truly intermittent may contradict a rule on purpose; it declares a waiver with a reason, and a
// waiver for a rule that does not fire is itself a finding, so a waiver cannot outlive the reason for it.

type Dict = Record<string, unknown>;

/** The closed rule ids. A waiver must name one of these. */
export const COHERENCE_RULES = [
  "version-drift",
  "healthy-preflight",
  "dest-refusal-vs-healthy-dest",
  "dest-refusal-unrecorded",
  "overdue-unexplained",
  "cron-verified-ticks-stale",
  "cron-work-after-last-tick",
  "runlog-counter",
  "tick-dispatch-unexplained",
  "next-run-off-cadence",
  "audit-behind-events",
] as const;
export type CoherenceRule = (typeof COHERENCE_RULES)[number];

export interface CoherenceFinding {
  rule: CoherenceRule;
  detail: string;
}

const HOUR = 3_600_000;
const MIN = 60_000;

// Standing refusals: a destination that answers one of these refuses every write until someone changes the
// credential or the bucket policy, or recreates the bucket. A throttle or a 5xx is transient and is not here.
const STANDING_AUTH_CODES = ["AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "403"];
// NoSuchBucket is standing too, but only the export half of the rule applies to it. The preflight destination
// probe is a HEAD, and a HEAD response has no body, so the store's 404 for a deleted bucket and its 404 for a
// fresh bucket with no RUNLOG yet look the same; the real probe reads both as verified. A pack with a deleted
// bucket and a verified destination item is therefore what a real engine emits (a pack gap, not a fixture fault).
const STANDING_CODES = [...STANDING_AUTH_CODES, "NoSuchBucket"];

function obj(v: unknown): Dict | undefined {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Dict) : undefined;
}
function arr(v: unknown): Dict[] {
  return Array.isArray(v) ? (v.filter((x) => obj(x) !== undefined) as Dict[]) : [];
}
function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
function ms(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string") {
    const t = Date.parse(v);
    return Number.isFinite(t) ? t : undefined;
  }
  return undefined;
}
/** Compare two x.y.z versions; NaN parts compare as 0. */
export function cmpVersion(a: string, b: string): number {
  const pa = a.split(".").map((x) => Number.parseInt(x, 10) || 0);
  const pb = b.split(".").map((x) => Number.parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}
function preflightItem(b: Dict, id: string): Dict | undefined {
  return arr(obj(b.preflight)?.items).find((i) => i.id === id);
}

function versionDrift(b: Dict, out: CoherenceFinding[]): void {
  const v = obj(b.engine)?.version;
  if (typeof v !== "string") return;
  const check = (path: string, got: unknown): void => {
    if (typeof got === "string" && got !== v) out.push({ rule: "version-drift", detail: `${path} reads ${got} under engine ${v}` });
  };
  check("engine.deployBaseline.version", obj(obj(b.engine)?.deployBaseline)?.version);
  check("recovery.deploy.engineVersion", obj(obj(b.recovery)?.deploy)?.engineVersion);
  check("updates.settledHighWaterMark", obj(b.updates)?.settledHighWaterMark);
  const pending = obj(obj(b.updates)?.pending);
  if (pending !== undefined) {
    check("updates.pending.fromVersion", pending.fromVersion);
    const to = pending.toVersion;
    if (typeof to === "string" && cmpVersion(to, v) <= 0) out.push({ rule: "version-drift", detail: `updates.pending offers ${to}, which is not newer than the running ${v}` });
  }
  // The newest engine-version-change event names the version the engine moved TO, which is the one running.
  const changes = arr(b.configEvents).filter((e) => e.action === "engine-version-change");
  const newest = changes.reduce<Dict | undefined>((m, e) => (m === undefined || (num(e.seq) ?? 0) > (num(m.seq) ?? 0) ? e : m), undefined);
  if (newest !== undefined) check(`configEvents[seq=${String(newest.seq)}].toVersion`, newest.toVersion);
}

function healthyPreflight(b: Dict, isFault: boolean, out: CoherenceFinding[]): void {
  if (isFault) return;
  for (const i of arr(obj(b.preflight)?.items)) {
    const st = i.status;
    if (i.required === true && st !== "verified" && st !== "configured") out.push({ rule: "healthy-preflight", detail: `required preflight ${String(i.id)} is ${String(st)} in a world labelled no-fault` });
    else if (st === "failed") out.push({ rule: "healthy-preflight", detail: `preflight ${String(i.id)} failed in a world labelled no-fault` });
  }
}

function destRefusals(b: Dict, out: CoherenceFinding[]): void {
  const runs = obj(b.runs) ?? {};
  const dest = preflightItem(b, "destination");
  const destFaults = obj(b.destFaults) ?? {};
  for (const [dp, rows] of Object.entries(runs)) {
    const latest = arr(rows)[0];
    if (latest?.status !== "failed" || typeof latest.error !== "string") continue;
    const m = /^destination rejected the write \(([^)]*)\)/.exec(latest.error);
    if (m === null) continue;
    const code = m[1] ?? "";
    // Every destination refusal on the run path passes through DestFaultLog and is drained into destFaults.
    if (destFaults[dp] === undefined) out.push({ rule: "dest-refusal-unrecorded", detail: `runs.${dp}[0] failed at the destination (${code}) and destFaults carries no row for ${dp}` });
    if (!STANDING_CODES.includes(code)) continue;
    const failedAt = ms(latest.startedAt) ?? 0;
    if (STANDING_AUTH_CODES.includes(code) && dest?.status === "verified") out.push({ rule: "dest-refusal-vs-healthy-dest", detail: `runs.${dp}[0] was refused (${code}), a standing refusal, while preflight destination reads verified` });
    const eh = obj(obj(b.recovery)?.exportHealth);
    const ehAt = ms(eh?.at);
    const okAfter = ehAt !== undefined && ehAt > failedAt && arr(eh?.perDest).some((p) => p.ok === true);
    if (okAfter) out.push({ rule: "dest-refusal-vs-healthy-dest", detail: `runs.${dp}[0] was refused (${code}) and the control-plane export wrote to the destination after it` });
    const exportedAt = ms(obj(b.controlPlaneExport)?.exportedAt);
    if (exportedAt !== undefined && exportedAt > failedAt) out.push({ rule: "dest-refusal-vs-healthy-dest", detail: `runs.${dp}[0] was refused (${code}) and controlPlaneExport.exportedAt records a successful export after it` });
  }
}

function schedulerCoherence(b: Dict, out: CoherenceFinding[]): void {
  const gen = ms(b.generatedAt);
  if (gen === undefined) return;
  const sched = obj(b.scheduler);
  const ticks = arr(sched?.ticks);
  const newestTick = ticks.reduce<number | undefined>((m, t) => {
    const at = num(t.at);
    return at !== undefined && (m === undefined || at > m) ? at : m;
  }, undefined);
  const cron = preflightItem(b, "cron-tick");
  if (cron?.status === "verified" && newestTick !== undefined && gen - newestTick > HOUR) {
    out.push({ rule: "cron-verified-ticks-stale", detail: `preflight cron-tick reads verified while the newest scheduler tick is ${Math.round((gen - newestTick) / MIN)} minutes old` });
  }
  // A cron that stopped cannot have done cron work since. The control-plane export, the per-tick deploy-identity
  // marker and the scheduled restore drill all run from the cron, so each must be no newer than the last tick.
  if (newestTick !== undefined && gen - newestTick > HOUR) {
    const limit = newestTick + 15 * MIN;
    const cronWork: Array<[string, number | undefined]> = [
      ["recovery.exportHealth.at", ms(obj(obj(b.recovery)?.exportHealth)?.at)],
      ["recovery.deploy.lastSeenAt", ms(obj(obj(b.recovery)?.deploy)?.lastSeenAt)],
      ...arr(b.downpipes).map((d): [string, number | undefined] => [`downpipes[id=${String(d.id)}].lastRestoreTestAt`, num(d.lastRestoreTestAt)]),
      // The replicate pass is cron work too, so no replication heartbeat can post-date the last tick.
      ...arr(b.downpipes).flatMap((d) => arr(obj(d.replication)?.destinations).map((r): [string, number | undefined] => [`downpipes[id=${String(d.id)}].replication[id=${String(r.id)}].at`, num(r.at)])),
    ];
    for (const [path, at] of cronWork) {
      if (at !== undefined && at > limit) out.push({ rule: "cron-work-after-last-tick", detail: `${path} is ${Math.round((at - newestTick) / HOUR)} hours after the last scheduler tick, which cron work cannot be` });
    }
  }
  const fresh = newestTick !== undefined && gen - newestTick <= 15 * MIN;
  const nothingDue = ticks.length > 0 && ticks.every((t) => num(t.due) === 0);
  const indexMatched = obj(sched?.dueIndex)?.matched === true;
  if (!(fresh && nothingDue && indexMatched && cron?.status === "verified")) return;
  for (const d of arr(b.downpipes)) {
    if (d.enabled !== true || d.inFlight === true || d.stalled === true) continue;
    const next = num(d.nextRunAt);
    const cadenceMs = (num(d.cadenceSeconds) ?? 0) * 1000;
    if (next === undefined || gen - next <= Math.max(2 * cadenceMs, HOUR)) continue;
    out.push({
      rule: "overdue-unexplained",
      detail: `downpipes[id=${String(d.id)}].nextRunAt is ${Math.round((gen - next) / HOUR)} hours past, yet the cron is verified, the scheduler ticked within 15 minutes, saw nothing due and its due index matches`,
    });
  }
}

// The counter is the last run index allocated. Below a retained index it reads as a counter reset (a fault the
// pack reports as runlog.reset), so that half applies to every world; a scenario that plants a reset waives it.
// Above the newest index plus the runs in flight, some allocated run is missing from every history ring; a fault
// world may have one (a run that crashed before it recorded), so that half applies to no-fault worlds only.
function runlogCounter(b: Dict, isFault: boolean, out: CoherenceFinding[]): void {
  const rl = obj(obj(b.scheduler)?.runlog);
  const counter = num(rl?.counter);
  if (counter === undefined) return;
  let maxIndex = -1;
  for (const rows of Object.values(obj(b.runs) ?? {})) for (const r of arr(rows)) maxIndex = Math.max(maxIndex, num(r.index) ?? -1);
  const inFlight = arr(b.downpipes).filter((d) => d.inFlight === true).length;
  if (maxIndex >= 0 && (counter < maxIndex || (!isFault && counter > maxIndex + inFlight))) {
    out.push({ rule: "runlog-counter", detail: `scheduler.runlog.counter is ${counter} while the newest retained run index is ${maxIndex} and ${inFlight} run(s) are in flight` });
  }
}

// A tick that dispatched a run leaves a run: one started at or after the tick, or a downpipe still in flight.
function tickDispatch(b: Dict, out: CoherenceFinding[]): void {
  const ticks = arr(obj(b.scheduler)?.ticks).filter((t) => (num(t.dispatched) ?? 0) > 0);
  const newest = ticks.reduce<Dict | undefined>((m, t) => (m === undefined || (num(t.at) ?? 0) > (num(m.at) ?? 0) ? t : m), undefined);
  const at = num(newest?.at);
  if (newest === undefined || at === undefined) return;
  let started = 0;
  for (const rows of Object.values(obj(b.runs) ?? {})) for (const r of arr(rows)) if ((ms(r.startedAt) ?? 0) >= at - 2 * MIN) started++;
  const inFlight = arr(b.downpipes).filter((d) => d.inFlight === true).length;
  if (started + inFlight === 0) out.push({ rule: "tick-dispatch-unexplained", detail: `the scheduler tick at ${new Date(at).toISOString()} dispatched ${String(newest.dispatched)} run(s), and no run started after it and nothing is in flight` });
}

// In a no-fault world a downpipe's next run is its newest run's start plus its cadence (a tick either side).
function nextRunCadence(b: Dict, isFault: boolean, out: CoherenceFinding[]): void {
  if (isFault) return;
  const runs = obj(b.runs) ?? {};
  for (const d of arr(b.downpipes)) {
    const next = num(d.nextRunAt);
    const cadenceMs = (num(d.cadenceSeconds) ?? 0) * 1000;
    const newest = arr(runs[String(d.id)])[0];
    const started = ms(newest?.startedAt);
    if (d.enabled !== true || next === undefined || cadenceMs <= 0 || started === undefined) continue;
    const expected = started + cadenceMs;
    if (Math.abs(next - expected) > 15 * MIN) out.push({ rule: "next-run-off-cadence", detail: `downpipes[id=${String(d.id)}].nextRunAt is ${Math.round((next - expected) / MIN)} minutes from its newest run's start plus its ${cadenceMs / 1000}s cadence` });
  }
}

// An intact audit chain verified through seq N cannot be behind an audit event the pack excerpts at seq > N.
function auditBehindEvents(b: Dict, out: CoherenceFinding[]): void {
  const audit = obj(b.audit);
  const through = num(audit?.checkedThrough);
  if (audit?.intact !== true || through === undefined) return;
  const maxSeq = arr(b.configEvents).reduce((m, e) => Math.max(m, num(e.seq) ?? 0), 0);
  if (maxSeq > through) out.push({ rule: "audit-behind-events", detail: `audit.checkedThrough is ${through} while configEvents carries seq ${maxSeq}` });
}

/** Every coherence finding for one emitted bundle. `isFault` is the scenario's own label. */
export function coherenceFindings(bundle: Dict, isFault: boolean): CoherenceFinding[] {
  const out: CoherenceFinding[] = [];
  versionDrift(bundle, out);
  healthyPreflight(bundle, isFault, out);
  destRefusals(bundle, out);
  schedulerCoherence(bundle, out);
  runlogCounter(bundle, isFault, out);
  tickDispatch(bundle, out);
  nextRunCadence(bundle, isFault, out);
  auditBehindEvents(bundle, out);
  return out;
}

/**
 * Apply a scenario's waivers. Returns the failures to report: every unwaived finding, every waiver that names
 * a rule outside COHERENCE_RULES or carries no reason, and every waiver whose rule did not fire (a stale waiver
 * hides the next real contradiction of the same kind).
 */
export function coherenceFailures(findings: CoherenceFinding[], waivers: Partial<Record<string, string>> | undefined): string[] {
  const w = waivers ?? {};
  const fails: string[] = [];
  const fired = new Set(findings.map((f) => f.rule));
  for (const f of findings) if (w[f.rule] === undefined) fails.push(`${f.rule}: ${f.detail}`);
  for (const [rule, reason] of Object.entries(w)) {
    if (!(COHERENCE_RULES as readonly string[]).includes(rule)) fails.push(`waiver names unknown rule ${rule}`);
    else if (typeof reason !== "string" || reason.trim() === "") fails.push(`waiver for ${rule} gives no reason`);
    else if (!fired.has(rule as CoherenceRule)) fails.push(`stale waiver: ${rule} did not fire`);
  }
  return fails;
}
