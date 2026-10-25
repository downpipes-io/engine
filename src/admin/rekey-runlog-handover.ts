// The RUNLOG hand-over a signer re-key runs (seal/runlog-handover.ts holds the per-destination logic, and
// sched/rekey-handover.ts the record the scheduler DO keeps).
//
// The order, for POST /keys/install with a confirmed re-key:
//   1. beginRekeyRunlogHandover: hold the OLD PUBLIC key and new run allocations in the DO, then verify every
//      destination's RUNLOG under the old key. If any fails, the DO record is dropped and the re-key stops
//      before a secret is written, naming each failing destination.
//   2. The route installs the secrets.
//   3. completeRekeyRunlogHandover: re-sign, under the new key, each RUNLOG that still verifies under the held
//      old public key. A destination it cannot hand over stays pending under the held key. With none pending
//      the held key is discarded, and an audit row records it.
// When the route cannot tell whether the new signer was installed, it settles every destination as pending:
// the held key then lets the attended route finish the hand-over under whichever signer is live.

import { DEPLOY_DEST_ID } from "../dest/dest-resolution.ts";
import { buildDestination, envDestinationDeclared, resolveDestination } from "../dest/factory.ts";
import type { Destination } from "../dest/types.ts";
import type { Env } from "../env.d.ts";
import type { Signer } from "../format/writer.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { encodeVerifier } from "../sched/rekey-handover.ts";
import { type HandoverOutcome, handOverRunlog, type PrecheckAnomaly, type PrecheckRefusal, precheckRunlog } from "../seal/runlog-handover.ts";
import type { HybridVerifier } from "../crypto/sign.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { doURL } from "./router-helpers.ts";
import { reportRunlogAnomaly } from "./integrity-fault-report.ts";
import { noteSiteFault } from "./site-faults.ts";

// A destination the hand-over covers: its id ("" = the env-backed destination of an estate with no console
// destination), the operator's label, and the built destination (null when it could not be built).
export interface HandoverTarget {
  id: string;
  label: string;
  dest: Destination | null;
}

export interface PrecheckFailure {
  id: string;
  label: string;
  reason: PrecheckRefusal;
}

// listHandoverTargets names every destination a run can seal to: each console destination, and the
// env-backed one when the deployment declares it. A destination that cannot be built is still listed, with
// dest null, so the pre-check refuses on it rather than skipping it.
export async function listHandoverTargets(env: Env, scheduler: DurableObjectStub): Promise<HandoverTarget[]> {
  const j = (await (await scheduler.fetch(doURL("/destinations"), { method: "GET" })).json()) as { destinations?: Array<{ id?: unknown; label?: unknown }> };
  const rows = (Array.isArray(j.destinations) ? j.destinations : []).filter((d): d is { id: string; label?: unknown } => typeof d.id === "string");
  const ids: Array<{ id: string; label: string }> = rows.map((d) => ({ id: d.id, label: typeof d.label === "string" ? d.label : d.id }));
  if (envDestinationDeclared(env)) {
    if (ids.length === 0) ids.push({ id: "", label: "deploy-time destination" });
    else if (!ids.some((d) => d.id === DEPLOY_DEST_ID)) ids.push({ id: DEPLOY_DEST_ID, label: "deploy-time destination" });
  }
  const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
  const out: HandoverTarget[] = [];
  for (const d of ids) {
    try {
      const res = await resolveDestination(env, scheduler, d.id || undefined, wrapKey);
      out.push({ ...d, dest: res.ok ? await buildDestination(env, undefined, res.config, d.id || undefined) : null });
    } catch (e) {
      noteSiteFault("rekey.handover-target-open", e);
      out.push({ ...d, dest: null });
    }
  }
  return out;
}

// precheckTargets verifies every target's RUNLOG under the old key and returns each failure. A chain-anomaly
// refusal's forensic row is pushed to anomalies, when given, for the support pack.
export async function precheckTargets(targets: readonly HandoverTarget[], oldVerifier: HybridVerifier, anomalies?: PrecheckAnomaly[]): Promise<PrecheckFailure[]> {
  const failed: PrecheckFailure[] = [];
  for (const t of targets) {
    const r = t.dest ? await precheckRunlog(t.dest, oldVerifier) : ({ ok: false, reason: "unreadable" } as const);
    if (!r.ok) {
      failed.push({ id: t.id, label: t.label, reason: r.reason });
      if ("anomaly" in r && r.anomaly !== undefined) anomalies?.push(r.anomaly);
    }
  }
  return failed;
}

// handOverTargets runs the hand-over on each target and returns each outcome. A target that cannot be built
// stays pending.
export async function handOverTargets(targets: readonly HandoverTarget[], oldVerifier: HybridVerifier, newSigner: Signer): Promise<Array<{ id: string; label: string; outcome: HandoverOutcome }>> {
  const out: Array<{ id: string; label: string; outcome: HandoverOutcome }> = [];
  for (const t of targets) {
    let outcome: HandoverOutcome = "pending";
    if (t.dest) {
      try {
        outcome = await handOverRunlog(t.dest, oldVerifier, newSigner);
      } catch (e) {
        noteSiteFault("rekey.handover-resign", e);
        outcome = "pending";
      }
    }
    out.push({ id: t.id, label: t.label, outcome });
  }
  return out;
}

export type BeginResult = { ok: true; targets: HandoverTarget[]; oldVerifier: HybridVerifier | null } | { ok: false; status: number; message: string; failed: PrecheckFailure[] };

// beginRekeyRunlogHandover is step 1. It reads the outgoing signer's public halves from this request's env
// (the old Worker's secret), runs the pre-check, then opens the DO record with every target pending. When the current signer does not
// load, nothing can verify a RUNLOG under it: the re-key (which is then the repair) proceeds with no hand-over,
// and each destination RUNLOG waits for the attended re-sign. Nothing is signed unverified.
export async function beginRekeyRunlogHandover(env: Env, scheduler: DurableObjectStub): Promise<BeginResult> {
  let oldVerifier: HybridVerifier;
  try {
    const old = await loadSigner(env.SIGNER_PRIVATE ?? "");
    oldVerifier = verifierFrom(old);
    old.mldsaSecret.fill(0); // only the public halves are kept
  } catch {
    // site-fault-waiver: src/admin/rekey-runlog-handover.ts:beginRekeyRunlogHandover:catch:1 -- a signer that does not load is the state this re-key repairs, and the install response reports it as runlogHandover.skipped
    return { ok: true, targets: [], oldVerifier: null };
  }
  // Everything that can fault runs BEFORE the record is opened, so a fault or a timeout here leaves no record.
  const targets = await listHandoverTargets(env, scheduler);
  const anomalies: PrecheckAnomaly[] = [];
  const failed = await precheckTargets(targets, oldVerifier, anomalies);
  // A chain anomaly is recorded where the seal path records one (integrityFaults, per downpipe), so a pack taken
  // after this refusal names it. The refusal below does not depend on the post.
  for (const a of anomalies) await reportRunlogAnomaly(scheduler, a.downpipeId, a.row);
  if (failed.length > 0) {
    const names = failed.map((f) => `${f.label}${f.id && f.id !== f.label ? ` (${f.id})` : ""}: ${f.reason}`).join("; ");
    return { ok: false, status: 409, message: `the re-key stopped before any key was changed: the RUNLOG of ${failed.length === 1 ? "this destination does" : "these destinations do"} not verify under the current signer, so it cannot be handed over: ${names}`, failed };
  }
  // The record opens with every target pending. If this request stops before settle, those destinations
  // stay pending and the attended route can finish them; settle trims the list. With no target there is
  // nothing to hand over and no record is opened.
  if (targets.length > 0) {
    const opened = await scheduler.fetch(doURL("/rekey-handover/begin"), { method: "POST", body: JSON.stringify({ oldVerifier: encodeVerifier(oldVerifier), pending: targets.map((t) => t.id) }), headers: { "content-type": "application/json" } });
    if (!opened.ok) {
      const why = opened.status === 409 ? "an earlier re-key has destinations still waiting to be handed over; finish those first" : "the re-key hand-over could not be recorded";
      return { ok: false, status: 409, message: why, failed: [] };
    }
  }
  return { ok: true, targets, oldVerifier };
}

export interface HandoverSummary {
  outcomes: Array<{ id: string; outcome: HandoverOutcome }>;
  pending: string[];
  heldKeyDiscarded: boolean;
  skipped?: "outgoing-signer-unreadable";
}

// completeRekeyRunlogHandover is step 3, after the secrets are installed. newSignerPrivate null means the
// route cannot tell whether the new signer was installed: every target is then settled as pending.
export async function completeRekeyRunlogHandover(scheduler: DurableObjectStub, begun: { targets: HandoverTarget[]; oldVerifier: HybridVerifier | null }, newSignerPrivate: string | null): Promise<HandoverSummary> {
  if (begun.oldVerifier === null) return { outcomes: [], pending: [], heldKeyDiscarded: false, skipped: "outgoing-signer-unreadable" };
  const oldVerifier = begun.oldVerifier;
  let outcomes: Array<{ id: string; label: string; outcome: HandoverOutcome }>;
  if (newSignerPrivate === null) {
    outcomes = begun.targets.map((t) => ({ id: t.id, label: t.label, outcome: "pending" as const }));
  } else {
    const signer = await loadSigner(newSignerPrivate);
    try {
      outcomes = await handOverTargets(begun.targets, oldVerifier, signer);
    } finally {
      signer.mldsaSecret.fill(0);
    }
  }
  const pending = outcomes.filter((o) => o.outcome === "pending").map((o) => o.id);
  const settled = (await (await scheduler.fetch(doURL("/rekey-handover/settle"), { method: "POST", body: JSON.stringify({ pending }), headers: { "content-type": "application/json" } })).json()) as { discarded?: unknown };
  return { outcomes: outcomes.map((o) => ({ id: o.id, outcome: o.outcome })), pending, heldKeyDiscarded: settled.discarded === true };
}

// abortRekeyRunlogHandover drops the record when the re-key wrote no secret (it failed before the first PUT).
export async function abortRekeyRunlogHandover(scheduler: DurableObjectStub): Promise<void> {
  await scheduler.fetch(doURL("/rekey-handover/abort"), { method: "POST" });
}
