// Orphan reconcile DRY-RUN INVENTORY pass for the cron driver (cron/drive.ts). For every destination
// bucket the fleet seals to, runOrphanReconcile discovers the run-trees physically present but ABSENT
// from that bucket's signed RUNLOG (the orphaned-but-recoverable bytes a contended/throttled/crashed
// finalise leaves behind), classifies each, and EMITS a per-class inventory in the structured log. It
// DELETES NOTHING and SALVAGES NOTHING -- the enforced GC + salvage are a separate, larger future project
// riding on a sharded-RUNLOG topology change.
//
// ADDITIVE + REVERSIBLE: the whole pass is gated behind the ORPHAN_RECONCILE env flag (DEFAULT OFF), so
// deploying this code changes NOTHING -- no extra reads, no log lines -- until an operator opts in. Rollback
// = unset the flag (or stop calling runOrphanReconcile). It mirrors the retention prune pass's per-destination
// infra (loadSigner -> verifier, zeroised on every exit; buildDestination per bucket; fetchDestConfig), and is
// wholly fail-open: a missing key, a DO hiccup, or a per-destination fault degrades to "no inventory this
// tick", never a crashed cron.

import { loadConfigWrapKey } from "../admin/config-secret.ts";
import { doURL } from "../admin/router.ts";
import { b64urlDecode } from "../crypto/bytes.ts";
import { type HybridVerifier, hybridVerify } from "../crypto/sign.ts";
import { buildDestination, fetchDestConfig } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import { attestKeyless } from "../format/keyless.ts";
import type { RootManifest } from "../format/manifest.ts";
import type { ObjectStore } from "../format/reader.ts";
import { parseRunlog } from "../format/writer.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { log } from "../log.ts";
import { primaryDestinationId } from "../sched/destinations.ts";
import type { DownpipeState } from "../sched/scheduler-do.ts";
import {
  countFreshnessResiduals,
  deferredInventory,
  type OrphanProbe,
  type OrphanProbeResult,
  planReconcileInventory,
  type ReconcileInventory,
  type ReconcilePolicy,
  type ReconcileSignal,
  reconcileSignalFor,
  summariseInventory,
} from "../seal/reconcile.ts";
import {
  noteReconcileCircuitBreaker,
  noteReconcileEnabled,
  noteReconcileSkip,
  noteRunlogSigVerdict,
} from "./cron-fault-ledger.ts";

// runlogParses reports whether the RUNLOG body PARSES as a valid NDJSON RUNLOG (support-pack mode
// runlog-sig-stale-window). It is a CLASSIFICATION only, run on the sig-UNVERIFIED abstain path to tell a
// body-vs-sig STALE WINDOW (body well-formed, signature lags) from a hard corrupt body; the pass abstains +
// deletes nothing regardless, so parsing unverified bytes is never a trust decision. Total (never throws).
function runlogParses(bytes: Uint8Array): boolean {
  try {
    parseRunlog(bytes);
    return true;
  } catch {
    return false;
  }
}

// reconcileEnabled is the ADDITIVE/REVERSIBLE gate: the dry-run inventory pass runs only when
// ORPHAN_RECONCILE is set to an affirmative value ("1"/"true"/"on", case-insensitive). Absent or any
// other value => the pass is a no-op, so the deployed code is byte-for-byte invisible until opted in.
function reconcileEnabled(env: Env): boolean {
  const raw = typeof env.ORPHAN_RECONCILE === "string" ? env.ORPHAN_RECONCILE.trim().toLowerCase() : "";
  return raw === "1" || raw === "true" || raw === "on" || raw === "yes";
}

// reconcilePolicyFromEnv reads the optional inventory knobs (grace window, the circuit-breaker
// fraction, the per-pass read-budget) from env, falling back to the module defaults on absent/invalid
// values so a typo never crashes the pass (it just uses the default).
function reconcilePolicyFromEnv(env: Env): ReconcilePolicy {
  const policy: { graceHours?: number; maxOrphanFraction?: number; maxClassifyPerPass?: number } = {};
  const grace = posNum(env.ORPHAN_RECONCILE_GRACE_HOURS);
  if (grace !== null) policy.graceHours = grace;
  const frac = posNum(env.ORPHAN_RECONCILE_MAX_FRACTION);
  if (frac !== null) policy.maxOrphanFraction = frac;
  const maxClassify = posInt(env.ORPHAN_RECONCILE_MAX_CLASSIFY);
  if (maxClassify !== null) policy.maxClassifyPerPass = maxClassify;
  return policy;
}

// posNum / posInt parse an optional positive numeric env knob; null on absent/invalid (use the default).
function posNum(v: string | undefined): number | null {
  if (typeof v !== "string" || v.trim() === "") return null;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : null;
}
function posInt(v: string | undefined): number | null {
  const n = posNum(v);
  return n === null ? null : Math.floor(n);
}

/**
 * Runs the orphan reconcile DRY-RUN INVENTORY for every destination bucket the fleet seals to. It asks
 * the DO for the downpipe list (GET /downpipes), derives the distinct PRIMARY destinations (each
 * self-contained archive with its own RUNLOG), and inventories each bucket once. The signer is loaded
 * ONCE for the whole pass purely to derive the PUBLIC verifier (the inventory is keyless - it never
 * signs), and its ML-DSA secret is zeroised on every exit path (the NC-6 discipline the seal/retention
 * paths follow). Fail-open throughout: a missing SIGNER_PRIVATE or a DO hiccup degrades to a skipped
 * tick; a per-destination fault skips just that bucket.
 */
export async function runOrphanReconcile(env: Env, scheduler: DurableObjectStub): Promise<void> {
  // ADDITIVE/REVERSIBLE gate: do nothing at all unless explicitly opted in.
  // G333: the pass is OPT-IN, so an empty reconcile section in the pack is AMBIGUOUS -- "the operator never
  // turned it on" and "it is on and has been bailing every tick for weeks" look identical. Echo the flag (a
  // boolean; never the env value) so the two are finally distinguishable, on every tick, including the
  // disabled one.
  const enabled = reconcileEnabled(env);
  noteReconcileEnabled(enabled);
  if (!enabled) return;

  // The downpipe list is the only cost when no bucket has runs; we read it to learn the destinations.
  let states: DownpipeState[];
  try {
    const resp = await scheduler.fetch(doURL("/downpipes"), { method: "GET" });
    states = (await resp.json()) as DownpipeState[];
  } catch (e) {
    // G333: every bail below leaves the LAST persisted signal standing, and a months-old signal is
    // indistinguishable from a fresh one. The closed skip reason is what separates them.
    noteReconcileSkip("downpipes-unavailable");
    log("error", `orphan reconcile skipped this tick: downpipe list unavailable (${(e as Error).message})`);
    return;
  }

  // Each destination is a SELF-CONTAINED archive with its OWN RUNLOG, so inventory per distinct PRIMARY
  // destination (the bucket a downpipe's runs actually seal to, resolved exactly as the seal path does).
  // A downpipe with no pinned destination resolves to "" (the default bucket).
  const destKeys = distinctPrimaryDestinations(states);
  if (destKeys.length === 0) return; // no downpipes => no buckets to inventory

  // Load the signer ONCE only to derive the public verifier (the inventory is keyless). A missing
  // SIGNER_PRIVATE degrades the whole pass to a skipped tick (we cannot verify a RUNLOG signature, the
  // one input that tells us what is committed, without it).
  let signer: Awaited<ReturnType<typeof loadSigner>>;
  try {
    if (!env.SIGNER_PRIVATE) throw new Error("missing required configuration: SIGNER_PRIVATE");
    signer = await loadSigner(env.SIGNER_PRIVATE);
  } catch (e) {
    // G333: no SIGNER_PRIVATE means the pass can never verify a RUNLOG, so it bails EVERY tick -- silently, and
    // permanently, while the pack shows a reconcile signal that stopped updating for reasons unknown.
    noteReconcileSkip("signer-missing");
    log("error", `orphan reconcile skipped this tick: ${(e as Error).message}`);
    return;
  }
  try {
    const verifier = verifierFrom(signer);
    const policy = reconcilePolicyFromEnv(env);
    const now = Date.now();
    for (const destKey of destKeys) {
      try {
        await inventoryOneDestination(env, scheduler, verifier, destKey, policy, now);
      } catch (e) {
        // A per-destination fault must not abort the pass or crash the cron; log coarsely and continue.
        // G333: THIS destination's inventory (and therefore its signal) is now stale, while the others may be
        // fresh -- "one destination's inventory is months old" is exactly this branch.
        noteReconcileSkip("inventory-fault");
        log("error", `orphan reconcile inventory skipped for destination ${destKey || "default"}: ${(e as Error).message}`);
      }
    }
  } finally {
    // Zeroise the per-pass signer's ML-DSA secret on every exit path (the NC-6 discipline), even though
    // this pass never signs - it holds the secret in memory only to derive the public verifier.
    signer.mldsaSecret.fill(0);
  }
}

// distinctPrimaryDestinations collects the distinct PRIMARY destination keys the fleet seals to (the
// buckets whose RUNLOGs could hold orphans), resolving each downpipe's primary exactly as the seal path
// does (primaryDestinationId; "" = default). Exported so the validator can assert the bucket set without
// standing up a DO.
export function distinctPrimaryDestinations(states: DownpipeState[]): string[] {
  const keys = new Set<string>();
  for (const s of states) keys.add(primaryDestinationId(s.config) ?? "");
  return [...keys];
}

// inventoryOneDestination inventories ONE bucket: build the destination, read + VERIFY its RUNLOG
// signature (abstain if it does not verify - the fail-closed Phase A anchor), derive the committed set
// and per-downpipe max committed index, enumerate the physical run-trees page-by-page, then run the pure
// planner and EMIT the inventory. It writes/deletes nothing.
async function inventoryOneDestination(
  env: Env,
  scheduler: DurableObjectStub,
  verifier: HybridVerifier,
  destKey: string,
  policy: ReconcilePolicy,
  now: number,
): Promise<void> {
  let dest: Destination;
  try {
    const destCfg = await fetchDestConfig(scheduler, destKey || undefined, loadConfigWrapKey(env.CONFIG_WRAP_KEY));
    if (destKey && !destCfg) {
      noteReconcileSkip("dest-not-configured"); // G333: a downpipe pins a destination whose config record is gone
      log("error", `orphan reconcile skipped for destination ${destKey}: not configured`);
      return;
    }
    dest = await buildDestination(env, undefined, destCfg ?? null);
  } catch (e) {
    noteReconcileSkip("dest-build-failed"); // G333: the destination could not be BUILT (credential, endpoint, wrap key)
    log("error", `orphan reconcile skipped for destination ${destKey || "default"}: ${(e as Error).message}`);
    return;
  }

  // Phase A: anchor on the RUNLOG, then sanity-check the anchor (fail-closed). A bucket with no RUNLOG
  // has finalised nothing, so nothing can be an orphan. We NEVER inventory against a RUNLOG whose
  // signature does not verify - that is the one input that tells us what is committed; trusting a
  // forged/garbled RUNLOG could mis-classify a real run as an orphan. Abstain + emit a deferred report.
  const runlog = await dest.get("_RECOVERY/RUNLOG");
  if (!runlog) {
    // Nothing finalised in this bucket: record the honest "no RUNLOG" health so a dest that has never
    // sealed is distinguishable in the pack from one whose RUNLOG went corrupt.
    await persistReconcileSignal(scheduler, reconcileSignalFor(destKey, now, false, false, null));
    return; // nothing finalised in this bucket
  }
  const sigObj = await dest.get("_RECOVERY/RUNLOG.sig");
  if (!sigObj || !(await verifyRunlogSig(runlog.body, sigObj.body, verifier))) {
    // G333: SPLIT the two. A .sig object that is ABSENT (an operator deleted it, or a bucket lifecycle rule
    // expired it) needs a re-sign; a signature that FAILED verification is a signer rotation or TAMPER, and the
    // operator must not proceed. Both used to record the same runlogSigVerified:false. The pass still abstains
    // and still deletes nothing either way -- only the evidence improves.
    noteRunlogSigVerdict(sigObj !== null);
    // The unverifiable-RUNLOG signal: abstain AND record the RUNLOG health. Distinguish the two shapes the
    // pack diagnoses differently -- a hard corrupt/unparseable body (runlog-corrupt-parse) vs a body-vs-sig
    // STALE WINDOW where the body still parses but the detached signature lags it (runlog-sig-stale-window,
    // transient). runlogParses is a classification only; the pass deletes nothing on this abstain regardless.
    const runlogBodyParses = runlogParses(runlog.body);
    await persistReconcileSignal(scheduler, reconcileSignalFor(destKey, now, true, false, null, { runlogBodyParses }));
    emitInventory(deferredInventory(destKey, "RUNLOG signature unverifiable; abstaining (cannot trust the committed set)"));
    return;
  }

  // The committed set + per-downpipe max committed index, derived from the VERIFIED RUNLOG. This is the
  // topology-aware "committedRunIds" accessor - the SINGLE place that reads the RUNLOG topology. Today it
  // reads the one account-global object; under (a) sharded-RUNLOG it MUST be changed here in lockstep
  // with the topology change (R7), or a wrong-source read mass-mis-classifies live committed runs.
  const entries = parseRunlog(runlog.body);
  const committedRunIds = new Set<string>(entries.map((e) => e.runId));
  const committedMaxIndex = new Map<string, number>();
  for (const e of entries) {
    const prev = committedMaxIndex.get(e.downpipeId);
    if (prev === undefined || e.index > prev) committedMaxIndex.set(e.downpipeId, e.index);
  }

  // Phase B: enumerate the physical run-trees, paging to keep memory bounded on a mature store.
  const physicalRunIds = await enumeratePhysicalRunIds(dest);

  // The keyless probe (Phase D IO): attest under the public verifier, and on a valid signature re-read
  // the (already-verified) root for its index / createdAt / prevRunId. The store wrapper throws on a
  // missing object; the probe maps a genuinely-absent root (404) to a "broken" verdict and a transient
  // failure to a throw (=> the planner classifies "unreadable").
  const probe = orphanProbeVia(dest, verifier);

  const inv = await planReconcileInventory({ destKey, committedRunIds, committedMaxIndex, physicalRunIds, now, policy, probe });
  // freshness-rollback-residual: count COMMITTED entries whose non-null prevRunId dangles (points to a runId
  // absent from this RUNLOG). Computed from the ALREADY-parsed entries -- no extra reads, no seal-path touch.
  const freshnessResiduals = countFreshnessResiduals(entries);
  await persistReconcileSignal(scheduler, reconcileSignalFor(destKey, now, true, true, inv, { freshnessResiduals }));
  emitInventory(inv);
}

// persistReconcileSignal records the bounded, redaction-safe per-destination reconcile signal into the
// scheduler DO (POST /reconcile-inventory) so the support pack can carry the orphan inventory + RUNLOG
// health (support-pack modes reconcile-orphans-invisible / runlog-corrupt-parse). This is a DIAGNOSTIC
// write only: the report-only reconcile pass still deletes nothing and never touches an archive, RUNLOG or
// the seal path. Best-effort: a persist failure degrades to "no reconcile signal this tick", never a
// crashed cron (it rides inside inventoryOneDestination's per-destination try/catch as well).
async function persistReconcileSignal(scheduler: DurableObjectStub, signal: ReconcileSignal): Promise<void> {
  try {
    const resp = await scheduler.fetch(doURL("/reconcile-inventory"), {
      method: "POST",
      body: JSON.stringify(signal),
      headers: { "content-type": "application/json" },
    });
    // G333: the response was never read, so a REFUSED persist passed for a written signal -- and the pack then
    // shows the PREVIOUS signal as if this tick had confirmed it.
    if (!resp.ok) noteReconcileSkip("persist-failed");
  } catch (e) {
    noteReconcileSkip("persist-failed");
    log("error", `orphan reconcile signal persist failed for ${signal.destKey || "default"} (non-critical): ${(e as Error).message}`);
  }
}

// verifyRunlogSig verifies the detached, b64url-encoded RUNLOG signature under the operator-pinned
// public verifier - the same check checkRunlogFreshness/attestKeyless make, lifted here so Phase A can
// abstain BEFORE trusting the committed set. A malformed signature is treated as "did not verify"
// (fail-closed), never thrown.
async function verifyRunlogSig(runlogBytes: Uint8Array, sigBytes: Uint8Array, verifier: HybridVerifier): Promise<boolean> {
  try {
    const sig = b64urlDecode(new TextDecoder().decode(sigBytes).trim());
    return await hybridVerify(verifier, runlogBytes, sig);
  } catch {
    return false;
  }
}

// enumeratePhysicalRunIds returns the distinct runIds with at least one object under run/<runId>/. It
// uses listPage when the destination supports it (bounded memory on a mature store, the dest/types.ts
// contract), falling back to list() otherwise. Discovery keys off ANY run/<runId>/ object (not only the
// root), so a run killed before writing its root is still discovered.
export async function enumeratePhysicalRunIds(dest: Destination): Promise<string[]> {
  const ids = new Set<string>();
  if (dest.listPage) {
    let cursor: string | undefined;
    do {
      const page = await dest.listPage("run/", cursor);
      for (const key of page.keys) addRunId(ids, key);
      cursor = page.cursor;
    } while (cursor);
  } else {
    for (const key of await dest.list("run/")) addRunId(ids, key);
  }
  return [...ids];
}

// addRunId extracts the <runId> from a run/<runId>/... key (split on the SECOND '/') and records it.
// Only a key with a trailing tree object (run/<id>/something) yields an id; a malformed key is ignored.
function addRunId(ids: Set<string>, key: string): void {
  const parts = key.split("/");
  if (parts.length >= 3 && parts[0] === "run" && parts[1]) ids.add(parts[1]);
}

// orphanProbeVia builds the production OrphanProbe over one destination. It discriminates a TRANSIENT
// read failure (throw => the planner classifies "unreadable", retry next tick) from a genuinely-ABSENT
// root (404 => a partial/root-less tree, classified "broken") by reading the root via dest.get (which
// returns null on 404 and throws on transport errors) before the keyless attestation.
export function orphanProbeVia(dest: Destination, verifier: HybridVerifier): OrphanProbe {
  // attestKeyless reads via a get-only ObjectStore that THROWS on a missing object.
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  return async (runId: string): Promise<OrphanProbeResult> => {
    const rootKey = `run/${runId}/root.manifest.json`;
    let rootGet: Awaited<ReturnType<Destination["get"]>>;
    try {
      rootGet = await dest.get(rootKey);
    } catch (e) {
      // A transport/transient failure: surface it so the planner classifies "unreadable" (abstain).
      throw e instanceof Error ? e : new Error(String(e));
    }
    if (rootGet === null) {
      // The root is genuinely absent (a run killed before/while writing its root): a broken tree.
      return { attestation: { signatureValid: false, complete: false, downpipeId: null }, root: null };
    }
    // The root object exists; let attestKeyless decide signatureValid + completeness (keyless, total).
    const attestation = await attestKeyless(store, runId, verifier, { allowStale: true });
    let root: RootManifest | null = null;
    if (attestation.signatureValid) {
      // attestKeyless already verified the signature over these exact bytes, so parsing them is safe;
      // we only need the fields the inventory classifies on (index / createdAt / prevRunId / downpipeId).
      root = JSON.parse(new TextDecoder().decode(rootGet.body)) as RootManifest;
    }
    return { attestation, root };
  };
}

// emitInventory writes the dry-run inventory to the structured log (the report-only analogue of the
// retention dry-run line). An abstained pass (deferred set) - especially the circuit-breaker case - is
// logged at error level (high severity: it usually means a topology/version skew that needs an
// operator); a normal inventory is logged at info with the three-way summary + the per-class breakdown.
// It NEVER writes an audit event (the retention dry-run path does not audit either; only an enforced
// apply would, and there is no apply here). No secret/plaintext: ids/indices/counts only.
function emitInventory(inv: ReconcileInventory): void {
  const where = inv.destKey || "default";
  if (inv.deferred !== undefined) {
    // Both abstains are error-level (the circuit-breaker case is high severity: it usually means a
    // topology/version skew an operator must look at).
    // G333: the circuit-breaker abstain was LOG-ONLY free text (which can describe the customer's topology, so
    // it can never ride in a pack). Record the BOOLEAN -- the fact the breaker tripped is the diagnosis; the
    // sentence is not.
    if (inv.circuitBreakerTripped) noteReconcileCircuitBreaker();
    log("error", `orphan reconcile ABSTAINED for destination ${where}${inv.circuitBreakerTripped ? " [CIRCUIT-BREAKER]" : ""}: ${inv.deferred}`);
    return;
  }
  const s = summariseInventory(inv);
  const b = inv.byClass;
  log(
    "info",
    `orphan reconcile (dry-run inventory) ${where}: committed ${s.committed}, orphaned-recoverable ${s.orphanedRecoverable}, never-referenced ${s.neverReferenced}, undetermined ${s.undetermined} ` +
      `[physical ${inv.physicalRunCount}, orphans ${inv.orphansFound}; salvageable ${b.salvageable}, stale ${b.stale}, broken ${b.broken}, within-grace ${b["within-grace"]}, unreadable ${b.unreadable}, pending ${inv.pendingClassify}] (deletes nothing)`,
  );
}
