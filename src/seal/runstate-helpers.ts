// runstate-helpers.ts holds the module-level helpers and tuning constants the seal DO and the
// worker-side seal entry points share (extracted from runstate.ts for finding engine-src-046-01;
// behaviour-preserving, the symbols are unchanged). The seal DO and sealRunSliced/sealRunBuffered
// in runstate.ts import these; nothing here changes control flow or values.

import { doURL, resolveDiscoveryToken } from "../admin/router-helpers.ts";
import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { loadRecipients, loadSigner } from "../keys-env.ts";
import { REASON_DESTINATION_ACCESS } from "../restore-reasons.ts";
import { accountInDiscoveryScope, type DiscoveryScopeConfig } from "../sched/config-validate.ts";
import type { DownpipeConfig, DownpipeState } from "../sched/scheduler-do.ts";
import { effectiveCfConfigSelector } from "../sources/cf-config-discovery.ts";
import type { Selector } from "../sources/types.ts";
import { API_DISCOVERY_SOURCE_TYPES, buildAdapter } from "./adapters.ts";
import { classifyEnvKnob, type KnobResolution, type SliceBudget } from "./budget.ts";
import { ConfigFaultError } from "./config-fault.ts";
import { FANOUT_SAMPLE_CAP } from "./fanout.ts";
import type { RunlogLock } from "./pipeline.ts";
import { throttleRetryFromEnv } from "./retry.ts";
import { noteStranded } from "./run-observations.ts";
import { postSealFault } from "./seal-fault-post.ts";
import type { SliceDeps } from "./slice.ts";
import { routeSealVerifyAlert, type SealVerification, sealVerifyEmission, verifyAtSeal, verifyAtSealEnabled } from "./verify-at-seal.ts";

export const DOC_KEY = "doc";
export const SHARD_PREFIX = "shard:";

// multipartAbortFlag reads the destination's stranded-parts signal (multipart-abort-stranded-parts): how many
// FAILED multipart uploads' best-effort aborts ALSO failed on this destination this invocation (invisible
// part-storage the bucket lifecycle/abort policy must reap). Only the multipart-capable S3 destination
// implements the accessor; an absent one (R2 native binding / memory double) is zero. It returns a spread that
// folds `multipartAbortFailed:true` into the /complete body ONLY when something was actually stranded -- a
// BOOLEAN, never a count or a key -- so completeRun stamps it on the run row and the fault stops being swallowed.
// Gap G062: it lives HERE (not in runstate.ts) because the seal DO's SLICED and FAN-OUT completion bodies must
// stamp exactly the same flag the inline path does -- the whole point of the parity fix is that one rule, not
// two, decides what a completion carries.
export function multipartAbortFlag(dest: Destination | undefined): { multipartAbortFailed: true } | Record<string, never> {
  if (dest === undefined) return {}; // faulted before the destination was built: nothing was uploaded, so nothing is stranded
  const n = typeof dest.multipartAbortFailures === "function" ? dest.multipartAbortFailures() : 0;
  // G066: the run row's boolean says THAT parts were stranded, never HOW MANY -- so "why does the archive bucket
  // grow far faster than the data?" could not be answered even in principle. Record the COUNT alongside the
  // (unchanged) boolean, in the seal-fault ring's stranding class.
  if (n > 0) noteStranded("multipart-parts", n);
  return n > 0 ? { multipartAbortFailed: true } : {};
}

// downDestinationFlag names the destination PROVEN down by a failed run (DEST-1), so the scheduler records a
// lastOk:false reachability heartbeat and the map's per-destination indicator lights up for a SOLE-destination
// outage too, not just a fan-out replica. Gap G062: the inline path did this and the seal DO (sliced, and every
// fan-out completion) did not, so the biggest customers' runs -- the sliced/fan-out population -- were exactly
// the ones whose destination outage never lit the marker. Only on a DESTINATION-ACCESS classification (a source
// or config fault must never blame the bucket) and only when the run had a resolved destination id. A closed
// coarse class in, the customer's own destination id out; never a URL, endpoint or bucket name.
export function downDestinationFlag(coarse: string, destinationId?: string): { downDestinationIds: string[] } | Record<string, never> {
  return coarse === REASON_DESTINATION_ACCESS && destinationId !== undefined ? { downDestinationIds: [destinationId] } : {};
}

// OPEN_PREFIX namespaces the RunSealDO's append-only OPEN-SHARD batches (Fix 2a): the AES-256-GCM-wrapped
// manifest lines of records sealed-but-not-yet-flushed, carried across slices so a shard spans them and
// reaches shardMax. The batches are EPHEMERAL DO scratch (deleted at finalise / cleanup) and never enter
// the signed archive. OPEN_SEQ_PAD zero-pads the monotonic batch sequence so a prefix list() enumerates
// the live batches in numeric order; 12 digits covers far more slices than any run produces.
export const OPEN_PREFIX = "open:";
const OPEN_SEQ_PAD = 12;
export function openBatchKey(seq: number): string {
  return `${OPEN_PREFIX}${String(seq).padStart(OPEN_SEQ_PAD, "0")}`;
}

// SHARD_LIST_PAGE / SHARD_LIST_MAX_PAGES bound the PAGED enumeration of the seal DO's shard rows
// (R0-1). A Durable Object storage list() returns at most one page (the platform caps it at ~1000
// keys), so finaliseAndComplete must loop with a startAfter cursor until a SHORT page comes back
// rather than read a single un-paged list() that silently drops every shard past the first page (a
// run with >1000 shards would otherwise sign a root over only the listed shards while declaring the
// full record count and the Merkle root over ALL records: a spec-violating, incomplete archive that
// still reports ok). 1000 is the platform's own page size; the max-pages guard is defence in depth
// against a degenerate backing store that never returns a short page (1000 pages * 1000 = a million
// shards, far beyond any real run), mirroring the scheduler DO's listAllByPrefix (ENG-SCALE-08).
export const SHARD_LIST_PAGE = 1000;
export const SHARD_LIST_MAX_PAGES = 1000;
// MAX_SLICE_FAILURES is the hard-fault ceiling: after this many strikes the run is marked failed and a
// /complete-with-error is posted, so the failure is surfaced by the alert and notification paths rather
// than dropped silently. The value of 8 gives about 70 minutes of maximum cumulative back-off at the
// RETRY_CAP_MS ceiling before terminal failure, which operators can use to reason about the recovery
// window. Throttle-class failures (503/429) ride the separate patient ladder below, not this one.
export const MAX_SLICE_FAILURES = 8;
export const RETRY_BASE_MS = 5_000;
export const RETRY_CAP_MS = 5 * 60_000;
export const NEXT_SLICE_DELAY_MS = 50;

// Throttle ladder (T1-C): a destination/source THROTTLE (503 SlowDown / 429) is handled on its OWN
// patient ladder, separate from the MAX_SLICE_FAILURES strike ladder above. It backs off the same 5s ->
// 5min as the strike ladder but tolerates FAR more rounds, and it NEVER cleans up the checkpoint while
// waiting, so the run is effectively PARKED: the same run resumes from its last checkpoint the moment the
// destination recovers (dedup makes the re-seal idempotent) rather than a fresh run re-crawling the
// source from zero every cadence for the length of the outage. DEFAULT_THROTTLE_MAX_YIELDS rounds at the
// 5min cap give a parking window of several hours (7 ramp rounds ~10min + ~53 capped rounds ~4.4h) before
// the run is given up with an honest "destination unavailable" reason (the source data is unchanged, so a
// fresh run next cadence backs it up). Tunable via DEST_THROTTLE_MAX_YIELDS.
export const THROTTLE_BASE_MS = 5_000;
export const THROTTLE_CAP_MS = 5 * 60_000;
export const DEFAULT_THROTTLE_MAX_YIELDS = 60;

// throttleMaxYields reads the optional DEST_THROTTLE_MAX_YIELDS knob (a positive integer), fail-soft to
// the default, so a typo'd knob can never shorten the parking window to zero or stop a backup.
export function throttleMaxYields(env: Env): number {
  const raw = (env as { DEST_THROTTLE_MAX_YIELDS?: unknown }).DEST_THROTTLE_MAX_YIELDS;
  if (typeof raw === "string" && raw.trim() !== "") {
    const n = Number(raw);
    if (Number.isInteger(n) && n > 0) return n;
  }
  return DEFAULT_THROTTLE_MAX_YIELDS;
}

// runSelector computes the record selector for a run. A cf-config downpipe honours its discovery cache
// + mode (auto = capture only the discovered PRESENT surfaces so a run is not one GET per all ~200
// surfaces; manual or a stale/absent cache = the configured include/exclude, which fail-safes to ALL).
// Every other source type uses its configured include/exclude unchanged.
export function runSelector(state: DownpipeState): Selector {
  if (state.config.source.type === "cf-config") {
    return effectiveCfConfigSelector(state.config.source, state.cfConfigDiscovery, Date.now());
  }
  return { include: state.config.source.include, exclude: state.config.source.exclude };
}

// runSealVerification is the SHARED verify-at-seal step every successful finalise path runs right
// before it posts the clean /complete (finding ENG-RST-01). It reads the just-written archive BACK
// from the destination and verifies it (verify-at-seal.ts: keyless Tier-0 always, a small decrypt
// sample when the operational key is held), and on a SUSPECT verdict fires a critical notification.
// It is FULLY FAIL-OPEN: it never throws (verifyAtSeal never throws, and the alert is guarded), never
// mutates the destination, and the returned SealVerification is attached to the /complete body so the
// DO records "verified at seal" (or "suspect") on the run row and surfaces it to posture/status. When
// the feature is off (VERIFY_AT_SEAL falsey) it returns undefined and the dest is never re-read.
// SealVerifyContext groups the run-invariant inputs of the verify-at-seal step (the env, the scheduler
// stub, the destination being read back, and the downpipe identity for the alert) so the call stays
// within the positional-parameter limit; the per-run runId and plaintext size stay positional.
export interface SealVerifyContext {
  env: Env;
  scheduler: DurableObjectStub;
  dest: Destination;
  downpipe: { id: string; name: string };
  // master is this run's PER-RUN key, when the caller still holds it (every seal path that finalises its
  // own run does). It lets the keyed decrypt tier run WITHOUT the in-account operational key, so a
  // break-glass-only downpipe gets real decrypt verification at seal time. It is NOT zeroised here: the
  // caller owns it and already zeroises it in a finally that spans this call, so passing it widens no
  // window. Omit it and the step behaves exactly as before (operational key or Tier-0).
  master?: Uint8Array;
}

export async function runSealVerification(ctx: SealVerifyContext, runId: string, plaintextBytes: number): Promise<SealVerification | undefined> {
  const { env, scheduler, dest, downpipe, master } = ctx;
  if (!verifyAtSealEnabled(env)) {
    // G067: an ABSENT verdict would otherwise be ambiguous between "verification is switched OFF for this
    // deployment" and "this run predates the verdict field". Record the OFF posture once per run, so a
    // suspect-free pack is never mistaken for a verified one. A closed enum; nothing else rides.
    await postSealFault(scheduler, { kind: "verify-suspect", at: Date.now(), downpipeId: downpipe.id, runId, verifyMode: "off" });
    return undefined;
  }
  const v = await verifyAtSeal(env, dest, runId, plaintextBytes, master);
  if (v.status === "suspect") {
    // G067: the suspect verdict itself is already on the run row (status/tier/coarse reason). What a diagnosis
    // could NOT get was: WHICH of 900 shards, HOW MANY records verified clean before the fault (sampled is
    // zeroed on a failure), whether two recurring reader faults are the SAME fault (no digest), and what
    // transiently broke on a recovered verdict. Ordinals, counts, a hex digest and closed enums only -- never a
    // shard id, an object key or a reader exception.
    await postSealFault(scheduler, {
      kind: "verify-suspect",
      at: Date.now(),
      downpipeId: downpipe.id,
      runId,
      verifyMode: verifyModeOf(v.tier),
      ...(v.causeDigest !== undefined ? { causeDigest: v.causeDigest } : {}),
      ...(v.failingOrdinal !== undefined ? { ordinal: v.failingOrdinal } : {}),
      ...(v.verifiedBeforeFail !== undefined ? { verifiedBeforeFail: v.verifiedBeforeFail } : {}),
      ...(v.attempts !== undefined ? { attemptsRun: v.attempts } : {}),
      ...(v.recovered === true ? { recovered: true } : {}),
    });
    // Fail-open: the bytes are already written and the run still completes. Raise the alert (the DO's
    // /complete also persists the suspect verdict, which the posture seal-verification check reads).
    const routed = await routeSealVerifyAlert(env, scheduler, sealVerifyEmission(downpipe.id, downpipe.name, v));
    // G212: the CRITICAL suspect-archive alert's routing is FAIL-OPEN, and it dies before or around the notify
    // history write -- so "we never got the suspect-archive alert" left NO evidence that an attempt was even
    // made. Record the failure, and separate the two cases support cannot otherwise tell apart: the alert never
    // went out at all (routingFailed) vs it WAS delivered and only its history row was lost.
    if (routed.routingFailed === true || routed.historyWriteFailed === true) {
      await postSealFault(scheduler, {
        kind: "alert-routing-failed",
        at: Date.now(),
        downpipeId: downpipe.id,
        runId,
        alertEventClass: "restore-test-fail",
        // historyWriteFailed:true means the alert WAS delivered and only its history row was lost; absent means
        // the routing itself threw, so no alert was ever sent. That distinction is the whole gap.
        ...(routed.historyWriteFailed === true ? { historyWriteFailed: true } : {}),
      });
    }
  }
  return v;
}

// verifyModeOf maps the verdict's TIER to the closed per-run verify mode (G067), so the pack can say which
// defence actually ran on a suspect run rather than leaving it to be inferred.
function verifyModeOf(tier: SealVerification["tier"]): "tier-0" | "sampled" | "full" {
  if (tier === "full") return "full";
  if (tier === "sampled-decrypt") return "sampled";
  return "tier-0";
}

export function json(v: unknown, status = 200): Response {
  return new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
}

// requireEnv is the run path's env-var gate. G142: an absent var is now a TYPED config fault carrying the
// var NAME (an operator label from the engine's own fixed vocabulary -- never its value), so a redeploy that
// dropped SIGNER_PRIVATE or BREAK_GLASS_PUBLIC is named in the pack instead of collapsing into "run failed".
// The message and the throw are unchanged, so every downstream classification behaves exactly as before.
export function requireEnv(v: string | undefined, name: string): string {
  if (!v) throw new ConfigFaultError(name === "SIGNER_PRIVATE" ? "signer-missing" : "env-missing", `missing required configuration: ${name}`, name);
  return v;
}

// runlogLockVia adapts the scheduler DO's /runlog-lock routes to the RunlogLock interface. destKey is the
// DESTINATION the run is sealing to (SCALE-3 per-destination keying): finalisers writing different
// destinations take different lock slots and never serialise on each other, so a concurrent trigger storm
// spread across destinations does not all queue on one lock. An absent/blank destKey targets the default
// destination's slot (the legacy unkeyed behaviour), so existing callers are unchanged.
export function runlogLockVia(scheduler: DurableObjectStub, destKey?: string): RunlogLock {
  const keyed = typeof destKey === "string" && destKey.length > 0 ? destKey : undefined;
  return {
    acquire: async () => {
      const init: RequestInit = keyed
        ? { method: "POST", body: JSON.stringify({ key: keyed }), headers: { "content-type": "application/json" } }
        : { method: "POST" };
      const r = (await (await scheduler.fetch(doURL("/runlog-lock/acquire"), init)).json()) as { acquired: boolean; token?: string };
      return r.acquired && r.token ? r.token : null;
    },
    release: async (token: string) => {
      await scheduler.fetch(doURL("/runlog-lock/release"), { method: "POST", body: JSON.stringify({ token, ...(keyed ? { key: keyed } : {}) }) });
    },
  };
}

// cfConfigToken resolves the engine's read-only discovery token for an API-based source run -- cf-config,
// workers, AND the three media sources (stream/images/artifacts), all of which read the Cloudflare REST API
// with the same "Read all resources" discovery token discovery itself uses (the membership set is shared
// with buildAdapter so the resolver can never drift from the adapters that demand the token). It returns
// undefined for every binding source type (KV/R2/D1/Secrets), so those runs make no extra DO fetch. For an
// API source it delegates to the shared resolveDiscoveryToken (scheduler DO first, then the DISCOVERY_API_TOKEN
// env fallback) so an IaC/env-token deployment -- which has no DO-stored discovery config -- still resolves the
// token and can run, exactly as the six admin readers already do. The token is used only to read during the
// crawl and is never persisted into the run or logged.
export async function cfConfigToken(
  scheduler: DurableObjectStub,
  state: DownpipeState,
  env: Env,
): Promise<string | undefined> {
  if (!API_DISCOVERY_SOURCE_TYPES.has(state.config.source.type)) return undefined;
  const token = await resolveDiscoveryToken(scheduler, env);
  // Cross-account confused-deputy guard (ASVS V4, HI-11) -- the highest-impact re-check: this is the run
  // path's actual data-capture chokepoint every entry point (sealRunSliced/sealRunBuffered/the seal DO
  // resume) funnels through before buildAdapter uses state.config.source.accountId verbatim with this
  // SAME shared token. A create-time check alone is not enough (the Owner can narrow the discovery
  // config's `selected` set AFTER this downpipe was created, with no re-validation of already-saved
  // downpipes), so this THROWS on a miss -- a recorded, alertable failed run, never a silent seal of the
  // wrong account. Fetched separately from the token above: accountsSeen/selected are not part of
  // resolveDiscoveryToken's return, which every OTHER caller of it only ever needed the token from (kept
  // that way so the token resolution stays the ONE shared place, per its own header comment). A null
  // discovery config (env/IaC-only token) is a no-op (accountInDiscoveryScope), matching the fallback above.
  const accountId = state.config.source.accountId;
  if (typeof accountId === "string" && accountId !== "") {
    const cfg = ((await (await scheduler.fetch(doURL("/sources/discovery-config"), { method: "GET" })).json()) as { config?: DiscoveryScopeConfig | null }).config ?? null;
    if (!accountInDiscoveryScope(accountId, cfg)) {
      // G142: TYPED so the pack can say "this run failed because its account is outside the discovery scope"
      // rather than "run failed". NO name rides: the only candidate label here is the customer's account id,
      // which this evidence deliberately never carries (the code alone is the remedy).
      throw new ConfigFaultError("account-scope-excluded", `accountId "${accountId}" is not one of the discovery-selected Cloudflare accounts; ask the owner to re-select it under Sources`);
    }
  }
  return token ?? undefined;
}

// SliceDepsOptions groups the optional runtime routing context (the per-run destination override and
// the cf-config discovery token) so sliceDepsFromEnv keeps to the 4-parameter guardrail.
export interface SliceDepsOptions {
  destOverride?: RuntimeDestConfig | null;
  cfToken?: string;
}

export async function sliceDepsFromEnv(env: Env, config: DownpipeConfig, budget: SliceBudget, opts: SliceDepsOptions = {}): Promise<SliceDeps> {
  const signer = await loadSigner(requireEnv(env.SIGNER_PRIVATE, "SIGNER_PRIVATE"));
  const recipients = loadRecipients(requireEnv(env.BREAK_GLASS_PUBLIC, "BREAK_GLASS_PUBLIC"), env.OPERATIONAL_PUBLIC);
  const dest = await buildDestination(env, budget, opts.destOverride ?? null);
  const source = buildAdapter(env, { config } as DownpipeState, opts.cfToken);
  const segmentTargetBytes = numKnob(env.SCALE_SEGMENT_TARGET_BYTES);
  const shardMaxRecords = numKnob(env.SCALE_SHARD_MAX_RECORDS);
  return {
    source,
    dest,
    signer,
    recipients,
    budget,
    ...(segmentTargetBytes !== undefined ? { segmentTargetBytes } : {}),
    ...(shardMaxRecords !== undefined ? { shardMaxRecords } : {}),
    throttleRetry: throttleRetryFromEnv(env),
  };
}

export function numKnob(v: unknown): number | undefined {
  if (typeof v !== "string" || v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
}

// Fan-out (Fix 2b) knob defaults + bounds. FAIL-SAFE OFF: SCALE_FANOUT_RANGES defaults to 1 (the serial
// path) and is clamped to [1, 256], so a typo or an over-set value can only fall back to serial / a sane
// cap, never break a backup or spawn an unbounded worker fleet.
export const SCALE_FANOUT_RANGES_DEFAULT = 1; // OFF: a serial run unless the operator opts in
export const SCALE_FANOUT_RANGES_MAX = 256;
export const SCALE_FANOUT_MIN_RECORDS_DEFAULT = 1_000_000; // small runs stay serial

// fanoutRangeCount parses SCALE_FANOUT_RANGES fail-soft: 1 (off) on absent/invalid, clamped to the max.
export function fanoutRangeCount(env: { SCALE_FANOUT_RANGES?: unknown }): number {
  const n = numKnob(env.SCALE_FANOUT_RANGES);
  if (n === undefined) return SCALE_FANOUT_RANGES_DEFAULT;
  return Math.min(n, SCALE_FANOUT_RANGES_MAX);
}

// fanoutMinRecords parses SCALE_FANOUT_MIN_RECORDS fail-soft to the default.
export function fanoutMinRecords(env: { SCALE_FANOUT_MIN_RECORDS?: unknown }): number {
  return numKnob(env.SCALE_FANOUT_MIN_RECORDS) ?? SCALE_FANOUT_MIN_RECORDS_DEFAULT;
}

// fanoutSampleCap parses SCALE_FANOUT_SAMPLE_CAP fail-soft to FANOUT_SAMPLE_CAP. It is the DIRECT-PLAN
// threshold: a run whose whole keyspace fits this cheap front sample is planned inline; a larger run is
// handed to the coordinator's sliced balanced count-then-stride scan (fanout.ts FANOUT_SAMPLE_CAP).
export function fanoutSampleCap(env: { SCALE_FANOUT_SAMPLE_CAP?: unknown }): number {
  return numKnob(env.SCALE_FANOUT_SAMPLE_CAP) ?? FANOUT_SAMPLE_CAP;
}

// sealLadderKnobSources reports the SOURCE of the fault-ladder + fan-out knobs (gap G169). Every one of them
// resolves FAIL-SOFT -- a typo'd DEST_THROTTLE_MAX_YIELDS silently keeps the 60-round parking window; a
// mis-parsed SCALE_FANOUT_RANGES silently keeps the run SERIAL (the "I turned fan-out on and nothing fanned
// out" ticket) -- so the pack showed a running default with no hint the operator's value had been REJECTED.
// The classifier mirrors numKnob (positive integers only) and each family's clamp, so the reported resolution
// is the one the engine actually runs with. Never the raw string: an invalid value is reported ONLY as the
// closed enum member "invalid".
export function sealLadderKnobSources(env: Env): Record<string, KnobResolution> {
  const e = env as unknown as { DEST_THROTTLE_MAX_YIELDS?: unknown; SCALE_FANOUT_RANGES?: unknown; SCALE_FANOUT_MIN_RECORDS?: unknown; SCALE_FANOUT_SAMPLE_CAP?: unknown };
  return {
    destThrottleMaxYields: classifyEnvKnob(e.DEST_THROTTLE_MAX_YIELDS, DEFAULT_THROTTLE_MAX_YIELDS, Number.MAX_SAFE_INTEGER),
    fanoutRanges: classifyEnvKnob(e.SCALE_FANOUT_RANGES, SCALE_FANOUT_RANGES_DEFAULT, SCALE_FANOUT_RANGES_MAX),
    fanoutMinRecords: classifyEnvKnob(e.SCALE_FANOUT_MIN_RECORDS, SCALE_FANOUT_MIN_RECORDS_DEFAULT, Number.MAX_SAFE_INTEGER),
    fanoutSampleCap: classifyEnvKnob(e.SCALE_FANOUT_SAMPLE_CAP, FANOUT_SAMPLE_CAP, Number.MAX_SAFE_INTEGER),
  };
}

// truthyKnob mirrors the ADMIN_TOKEN_DISABLED convention ("1"/"true"/"yes"/"on").
export function truthyKnob(v: unknown): boolean {
  return typeof v === "string" && /^(1|true|yes|on)$/i.test(v.trim());
}
