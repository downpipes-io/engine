// runBeaconEmitPass -- the OPT-IN, content-free, fail-open vendor beacon (no-custody).
//
// OFF BY DEFAULT: the engine remains no-phone-home unless an operator sets BOTH BEACON_URL (the control
// plane base) and BEACON_INGEST_KEY (the shared ingest bearer). Absent either => this returns immediately
// and nothing leaves the account. This preserves the no-phone-home posture as the default; the beacon is
// an explicit opt-in for the operator who wants the assurance view + the deploy-ledger corroboration.
//
// CONTENT-FREE / NO-CUSTODY (non-negotiable): the payload is the closed downpipe-beacon-v1 aggregate -- an
// opaque account tag, the engine version + immutable Cloudflare deploy id, and COUNTS ONLY (downpipe count,
// a coarse healthy/stalled split, one account-wide max recent-run index). NOTHING per-downpipe, no names,
// no values, no secrets; the control-plane receiver additionally 422-rejects any per-downpipe field, so the
// envelope is enforced on both ends. The deploy ledger keys on the cfVersionId change between two beacons.
//
// FAIL-OPEN: a beacon is advisory and can never touch a backup or a restore, so any fault (DO read, the
// outbound POST, a malformed base URL) degrades to "no beacon this tick" and is swallowed -- never a thrown
// cron, never a delayed backup.

import { doURL, type schedulerStub } from "../admin/router.ts";
import type { Env } from "../env.d.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { log } from "../log.ts";
import { beaconConfigured } from "./beacon-config.ts";
import { type BeaconFailClass, classifyBeaconFail, noteBeaconEnv, noteBeaconFail, noteBeaconStateWriteFailure } from "./cron-fault-ledger.ts";

export async function runBeaconEmitPass(env: Env, scheduler: ReturnType<typeof schedulerStub>): Promise<void> {
  // G278: record WHICH of the three env vars are present, as booleans. The gate below is all-or-nothing, so a
  // HALF-configured beacon (one var typo'd) is indistinguishable from a deliberately-off one -- which is the
  // "we opted in but the vendor assurance view never lit up" ticket, and it is unanswerable today. The VALUES
  // (the URL, the ingest key, the account tag) never enter the ledger: presence booleans only. Recorded
  // BEFORE the gate, so a half-configured beacon is still diagnosable when the gate turns it off.
  noteBeaconEnv({ url: env.BEACON_URL, ingestKey: env.BEACON_INGEST_KEY, accountId: env.CF_ACCOUNT_ID });
  // Opt-in gate: no phone-home unless the operator has configured BOTH the endpoint and the bearer AND the
  // account tag is known (the beacon's key). Any missing => silently off. The predicate lives in
  // beacon-config.ts because the posture screen has to answer the same question and must never disagree.
  if (!beaconConfigured(env)) {
    return;
  }
  // Read AFTER the gate, which narrows all three to string.
  const base = env.BEACON_URL;
  const ingestKey = env.BEACON_INGEST_KEY;
  const accountTag = env.CF_ACCOUNT_ID;
  try {
    const agg = (await (await scheduler.fetch(doURL("/beacon-aggregate"), { method: "GET" })).json()) as {
      downpipeCount?: number;
      healthy?: number;
      stalled?: number;
      runlogMaxIndex?: number;
    };
    const vm = env.CF_VERSION_METADATA;
    const cfVersionId = vm && typeof vm.id === "string" && vm.id !== "" ? vm.id : undefined;
    const beacon = {
      kind: "downpipe-beacon-v1",
      accountTag,
      engineVersion: ENGINE_VERSION,
      ...(cfVersionId ? { cfVersionId } : {}),
      downpipeCount: agg.downpipeCount ?? 0,
      healthy: agg.healthy ?? 0,
      stalled: agg.stalled ?? 0,
      runlogMaxIndex: agg.runlogMaxIndex ?? 0,
      emittedAt: new Date().toISOString(),
    };
    const url = new URL("/beacon", base).href;
    const resp = await fetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${ingestKey}`, "content-type": "application/json" },
      body: JSON.stringify(beacon),
    });
    // Record the attempt OUTCOME for the support pack (beacon-post-lost): a lost/failing beacon is otherwise
    // invisible. Best-effort + fail-open, a record hiccup must never delay or fail the backup path.
    // G324: the CLASS rides with the attempt now, so the DO's beacon record (which the pack carries) can say
    // WHY, not just that it failed. Computed once and used for both the cron ledger and the DO record.
    const failClass = resp.ok ? undefined : classifyBeaconFail(undefined, resp.status);
    await recordBeaconState(scheduler, resp.ok, resp.status, failClass);
    // A non-2xx is advisory only (e.g. the operator disabled ingestion, or a 422 if the receiver tightened
    // the shape): log and move on, never retry-loop or throw.
    if (!resp.ok) {
      noteBeaconFail(failClass!);
      log("error", `vendor beacon POST returned ${resp.status}; skipped this tick`);
    }
  } catch (e) {
    // The outbound POST (or the aggregate read) threw: record a failed attempt so the pack shows the beacon
    // is NOT reaching the vendor, then swallow. Still fail-open.
    //
    // G278: the throw path persisted ok:false with NO status and NO class, so a malformed BEACON_URL (a
    // permanent operator error, one line to fix) read exactly like a network blip (self-healing). Classify it
    // HERE, where the exception is in hand; the classifier returns a closed enum and the message, the URL and
    // the ingest key are discarded.
    // G324: the SAME closed class now also rides into the DO's beacon record, so the pack can tell a
    // malformed BEACON_URL (permanent, one line to fix) from a network blip (self-healing) without a
    // Workers Logs export the vendor structurally cannot request.
    const failClass = classifyBeaconFail(e);
    noteBeaconFail(failClass);
    await recordBeaconState(scheduler, false, undefined, failClass);
    log("error", `vendor beacon skipped this tick: ${(e as Error).message}`);
  }
}

// recordBeaconState posts the last-attempt outcome to the scheduler DO. Best-effort/fail-open: any error is
// swallowed so a persist hiccup never touches the backup path (the beacon is advisory).
async function recordBeaconState(scheduler: ReturnType<typeof schedulerStub>, ok: boolean, status: number | undefined, errorClass?: BeaconFailClass): Promise<void> {
  try {
    await scheduler.fetch(doURL("/beacon-state"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      // errorClass is a CLOSED BeaconFailClass, never the URL, the ingest key or the throw message; the DO
      // re-validates it against the same closed set at its own boundary (G324).
      body: JSON.stringify({ ok, ...(typeof status === "number" ? { status } : {}), ...(errorClass !== undefined ? { errorClass } : {}) }),
    });
  } catch {
    // A lost write here would let beacon.lastOk / lastAt go silently STALE, presenting a weeks-old beacon
    // verdict as current. Count the loss (a count, nothing else) so a stale beacon field is attributable
    // rather than misleading. Still fail-open: never let beacon bookkeeping affect a backup.
    noteBeaconStateWriteFailure();
    noteBeaconStateWriteFailure();
  }
}
