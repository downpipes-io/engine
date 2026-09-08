// router-audit.ts -- the actor-attribution + first-class audit-appender primitives shared by the admin
// routes: the caller-header builder that forwards the resolved caller to the DO, and the audit appenders
// (incl. the self-redeploy-retry variants) plus the best-effort restore-proven stamp.
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import type { AuditAction, AuditDraft, AuditEvent, AuditOutcome, AuditTarget } from "./audit.ts";
import type { DroppedWriteKind } from "./diag-records.ts";
import { flushDroppedWrites, noteDroppedWrite, recordDiagWrite } from "./diag-writer.ts";
import { CALLER_HEADER, type Caller, encodeCaller } from "./identity.ts";
import { doURL, schedulerStub } from "./router-helpers.ts";


// callerHeaders builds the internal header that forwards the resolved caller to the DO on a
// mutating call, so the DO can re-check authority (defence in depth) and attribute the actor.
// SECURITY: the router ALWAYS sets this from the verified verdict; it never copies an inbound
// client header onto the DO fetch (it forwards only the body), so an attacker-supplied
// x-downpipe-caller on the inbound request is overwritten, never honoured. See identity.ts.
export function callerHeaders(caller: Caller): Record<string, string> {
  return { [CALLER_HEADER]: encodeCaller(caller), "content-type": "application/json" };
}


// recordAudit appends one first-class audit event by forwarding a redaction-safe draft to the DO
// (the chain authority), threading the verified actor, the auth method, and the source IP. The
// target is the closed AuditTarget union, so a caller cannot smuggle a value into the log. It
// returns the appended AuditEvent (the intent route echoes it). Building the draft here, in the
// router, keeps the audit recording next to the action it describes, while the actual append (seq
// allocation, chaining, persistence) stays in the DO's single read-modify-write.
export async function recordAudit(
  scheduler: DurableObjectStub,
  caller: Caller,
  sourceIp: string | null,
  action: AuditAction,
  outcome: AuditOutcome,
  target: AuditTarget,
): Promise<AuditEvent> {
  const draft: AuditDraft = {
    // actorSubject is the STABLE principal that performed the action (null for the bare-token break-glass);
    // actorEmail is the display identity. Both are recorded so the trail attributes the immutable identity
    // AND shows a human-legible email; subject is an opaque id, redaction-safe.
    actorSubject: caller.subject,
    actorEmail: caller.email,
    actorMethod: caller.method,
    sourceIp,
    action,
    outcome,
    target,
  };
  const resp = await scheduler.fetch(doURL("/audit"), { method: "POST", body: JSON.stringify(draft), headers: { "content-type": "application/json" } });
  // G100: the append's RESPONSE was never checked. A DO that ANSWERS a non-2xx (a route chain skewed by a
  // partial deploy, storage pressure) therefore dropped an audit event in silence -- and configEvents, the
  // pack's "what CHANGED" excerpt, then reads as though the mutation never happened. Absence of evidence
  // reading as absence of change is the worst failure mode this pack has, so the LOSS is now counted. The
  // parse below is unchanged, so a non-2xx still surfaces to the caller exactly as before.
  if (!resp.ok) {
    noteDroppedWrite("audit-write");
    await flushDroppedWrites(scheduler);
  }
  return (await resp.json()) as AuditEvent;
}


// SELF_DEPLOY_RETRY_MAX_ATTEMPTS / SELF_DEPLOY_RETRY_BASE_MS are the shared retry budget for the
// best-effort appends that run AFTER a source attach/detach has redeployed the engine and momentarily
// reset this Durable Object. The backoff escalates as SELF_DEPLOY_RETRY_BASE_MS * (attempt + 1) to give
// the DO time to recover under its new code.
const SELF_DEPLOY_RETRY_MAX_ATTEMPTS = 5;
const SELF_DEPLOY_RETRY_BASE_MS = 300;


// isSelfDeployReset decides which THROWN message is the version rollout this family exists to ride out.
// Cloudflare can raise either the named form ("Durable Object reset because its code was updated") or an
// opaque "internal error; reference = ..." for the identical reset, depending on the stub, so both forms are
// matched here rather than only the named one.
//
// It is deliberately ANCHORED to the whole message rather than matched anywhere inside one, so a real fault
// that merely mentions an internal error in a longer sentence is still treated as a fault. Over-matching is
// bounded in any case: a message that is retried and never recovers costs the ladder's budget and is then
// counted and logged exactly as before, which is why the exhaustion path exists.
const DO_SELF_DEPLOY_RESET = /reset because its code was updated|Durable Object reset/i;
const DO_OPAQUE_ROLLOUT_FAULT = /^\s*internal error\s*(?:;\s*reference\s*=\s*\S+)?\s*\.?\s*$/i;
function isSelfDeployReset(msg: string): boolean {
  return DO_SELF_DEPLOY_RESET.test(msg) || DO_OPAQUE_ROLLOUT_FAULT.test(msg);
}


// retryAfterSelfDeploy runs a best-effort append `op` that may transiently fail because the action just
// redeployed the engine and reset the audit DO ("Durable Object reset because its code was updated", or the
// opaque "internal error; reference = ..." the same rollout raises: see isSelfDeployReset). It
// retries ONLY that reset, with a short escalating backoff, getting a fresh stub inside `op` each time; a
// non-reset error is a real fault and ends the loop immediately. `op` returns true when the append landed
// and false on a non-reset fault; `op`'s return value passes straight through (a false from a non-reset
// fault does NOT trigger the exhaustion log). `faultMsg` labels the non-reset fault log. `exhaustedMsg` is
// logged ONLY when every reset retry is used up. Returns true iff the append landed.
// G100: `kind` is the closed dropped-write kind to COUNT when the write is finally lost (a non-reset fault,
// an exhausted retry ladder, or an op that returned false). These writes run right after a self-redeploy --
// which is exactly the highest-impact failure mode window ("did a deploy drop my source bindings?") -- so a silently lost
// audit append here means the deploy KEYSTONE never reaches the pack, and the post-deploy pack is then
// indistinguishable from one where no redeploy happened at all. The loss is recorded, never the message.
async function retryAfterSelfDeploy(op: () => Promise<boolean>, faultMsg: string, exhaustedMsg: string, kind: DroppedWriteKind, env: Env): Promise<boolean> {
  for (let attempt = 0; attempt < SELF_DEPLOY_RETRY_MAX_ATTEMPTS; attempt++) {
    try {
      const landed = await op();
      if (landed) return true;
      // The op ANSWERED and refused (a non-2xx): a real loss, not a retryable DO reset.
      noteDroppedWrite(kind);
      await flushDroppedWrites(schedulerStub(env));
      return false;
    } catch (e) {
      const msg = (e as Error)?.message ?? "";
      // Only the self-redeploy reset is expected and retryable; anything else is a real fault.
      if (!isSelfDeployReset(msg)) {
        log("warn", `${faultMsg} (non-reset): ${msg.slice(0, 140)}`);
        noteDroppedWrite(kind);
        await flushDroppedWrites(schedulerStub(env));
        return false;
      }
      await new Promise((r) => setTimeout(r, SELF_DEPLOY_RETRY_BASE_MS * (attempt + 1)));
    }
  }
  log("warn", exhaustedMsg);
  noteDroppedWrite(kind);
  await flushDroppedWrites(schedulerStub(env));
  return false;
}


// recordAuditAfterSelfDeploy records the audit for an action that JUST redeployed the engine: a source
// attach/detach rewrites the Worker's own settings, and an engine-version promote/rollback/ramp (asvs-HI-19)
// replaces the Worker's code outright -- either way it creates a new Worker version and momentarily RESETS
// this Durable Object, so the first append fails with "Durable Object reset because its code was updated".
// The change itself has already succeeded (the caller only reaches here once it has), so a delayed (or
// lost) audit must NEVER turn it into a user-facing failure (the same best-effort rule as
// stampRestoreProven). We retry with a short escalating backoff to let the DO recover with its new code,
// getting a FRESH stub each time, then give up quietly. Returns true iff it landed.
export async function recordAuditAfterSelfDeploy(
  env: Env,
  caller: Caller,
  sourceIp: string | null,
  action: AuditAction,
  target: AuditTarget,
): Promise<boolean> {
  return retryAfterSelfDeploy(
    async () => {
      await recordAudit(schedulerStub(env), caller, sourceIp, action, "success", target);
      return true;
    },
    "post-self-deploy audit append failed",
    "post-self-deploy audit append deferred: the engine's self-redeploy kept the audit DO reset across retries; the underlying change already landed",
    "audit-write",
    env,
  );
}


// recordAuditCheckedAfterSelfDeploy is the CHECKED audit append for an action that has just mutated the
// engine's OWN worker secrets, which is a self-redeploy by another name.
//
// WHY IT EXISTS. A POST /admin/keys/install that writes all four secrets can still lose its keys-installed
// audit row: each Cloudflare secret PUT rolls a NEW WORKER VERSION, and updating a worker's script RESETS
// its Durable Objects, so the append that follows the PUTs can race the rollout and throw "Durable Object
// reset because its code was updated" on a stub the isolate is already holding.
//
// The remedy already exists two functions above, written for the source-attach appends that redeploy the
// engine in exactly the same way. This binds it to the other half the key ceremony needs: recordAudit does
// NOT throw when the DO answers a non-2xx (it counts the loss and returns the error body parsed as an
// event), so a landed append is told from a lost one by its numeric seq, and only the DO RESET is retried.
// A fresh stub is taken on every attempt, which is the point: the stub the caller holds is the one the
// rollout invalidated. Best-effort, like every sibling here: the secrets are already written, so a deferred
// audit row must never turn a landed ceremony into a failure for the operator. Returns true iff it landed.
export async function recordAuditCheckedAfterSelfDeploy(
  env: Env,
  caller: Caller,
  sourceIp: string | null,
  action: AuditAction,
  outcome: AuditOutcome,
  target: AuditTarget,
  kind: DroppedWriteKind,
): Promise<boolean> {
  return retryAfterSelfDeploy(
    async () => {
      const appended = await recordAudit(schedulerStub(env), caller, sourceIp, action, outcome, target);
      // No numeric seq means the DO ANSWERED without appending. That is a real loss, not a reset, so the
      // ladder counts it and stops rather than hammering a DO that is up and refusing.
      return typeof appended?.seq === "number";
    },
    `${action} audit append failed after a secret write`,
    `${action} audit append deferred: the worker versions rolled by the secret writes kept the audit DO reset across retries; the secrets themselves are installed`,
    kind,
    env,
  );
}


// observeAttachAfterSelfDeploy records the credential-lifecycle "spent ephemeral attach token" row after
// a source attach. Like the audit append, the attach JUST redeployed the engine and momentarily reset the
// DO, so it retries with a short escalating backoff over a FRESH stub, then gives up quietly (fail-open:
// a dropped cleanup row is never worse than the manual baseline). The token VALUE is never passed, only
// its PUBLIC id (when account-owned), its expires_on, a permission summary, and the attached source names.
export async function observeAttachAfterSelfDeploy(
  env: Env,
  facts: { tokenId?: string; expiresOn?: string; permissionSummary: string; sourcesAttached: string[] },
): Promise<boolean> {
  const body = JSON.stringify(facts);
  return retryAfterSelfDeploy(
    async () => {
      const r = await schedulerStub(env).fetch(doURL("/expiry/observe-attach"), { method: "POST", body });
      return r.ok; // a non-OK that is not a DO reset is a real fault we do not retry
    },
    "attach observe failed",
    "attach observe deferred: the engine's self-redeploy kept the DO reset across retries; the attach still succeeded and was post-verified",
    "audit-write",
    env,
  );
}


// recordVerifiedEngineAccountAfterSelfDeploy persists the engine's own Cloudflare account id
// (LICENCE-BINDING-ON-CLAIM follow-up,), proven by the attach or update-apply that just
// succeeded: both read /accounts/{a}/workers/scripts/{name} for the engine's own script name before
// writing to it, so a success already means Cloudflare confirmed this account owns that script. Uses
// the SAME self-redeploy retry as its siblings above: an attach rewrites the Worker's own settings and
// a promote replaces its code outright, either of which resets this Durable Object right when this
// write would otherwise land. Fully best-effort, like observeAttachAfterSelfDeploy: a dropped write
// only means GET /admin/status keeps reporting cfAccountId absent (or from a still-unset CF_ACCOUNT_ID)
// until the NEXT attach or apply succeeds; it must never turn an already-landed attach/apply into a
// failure, so the caller does not need to check the returned boolean.
export async function recordVerifiedEngineAccountAfterSelfDeploy(env: Env, accountId: string, via: "attach" | "update-apply"): Promise<boolean> {
  const body = JSON.stringify({ accountId, via });
  return retryAfterSelfDeploy(
    async () => {
      const r = await schedulerStub(env).fetch(doURL("/sources/engine-account-verified"), { method: "POST", body });
      return r.ok;
    },
    "engine-account-verified write failed",
    "engine-account-verified write deferred: the engine's self-redeploy kept the DO reset across retries; the underlying change already landed",
    "audit-write",
    env,
  );
}


// recordBookkeepingAfterSelfDeploy writes an update-lifecycle bookkeeping record (POST /update-pending or
// POST /update-settled) with the SAME self-redeploy retry as recordAuditAfterSelfDeploy: promoting, rolling
// back or ramping the engine version IS the self-redeploy that resets this Durable Object, so the write can
// transiently fail even though the version change already landed (asvs-HI-19). Unlike its best-effort
// siblings above, this one is NOT fire-and-forget: a lost bookkeeping write leaves the update lifecycle
// stale (e.g. a pending verification that never records its outcome), so the caller MUST check the
// returned boolean and, on false, tell the operator honestly instead of assuming the write landed. Returns
// true iff the write landed.
export async function recordBookkeepingAfterSelfDeploy(env: Env, path: string, body: unknown): Promise<boolean> {
  return retryAfterSelfDeploy(
    async () => {
      const r = await schedulerStub(env).fetch(doURL(path), { method: "POST", body: JSON.stringify(body) });
      return r.ok;
    },
    "update bookkeeping write failed",
    "update bookkeeping write deferred: the engine's self-redeploy kept the audit DO reset across retries; the version change still went live",
    // The update-lifecycle kinds already exist for exactly this loss: a settled record that never persisted
    // leaves the console unable to offer a rollback ("no recorded prior version" right after an update).
    path.includes("settled") ? "update-settled" : "update-pending",
    env,
  );
}


// stampRestoreProven records the per-downpipe "offline restorability last proven" record after a BLIND
// restore test or KEYLESS attestation PASSED. It forwards the verified caller so the DO re-checks
// restore.verify (defence in depth) and attributes the prover, and it is fully best-effort: a hiccup
// recording the stamp must NEVER turn a genuine recoverability proof into a failure, so any error is
// swallowed with a coarse log and the proof result still returns. It carries only redaction-safe
// provenance (the downpipe id, the method, the proven runId), never a key or value.
export async function stampRestoreProven(
  scheduler: DurableObjectStub,
  caller: Caller,
  downpipeId: string,
  method: "blind-test" | "keyless-attest",
  runId: string,
): Promise<void> {
  // G100: CHECKED best-effort. The stamp stays fail-open (a proof must never be turned into a failure by a
  // bookkeeping hiccup), but a LOST stamp is no longer silent: it made a downpipe that HAS been proven
  // restorable read as never-proven in the pack (status.restorabilityProven and downpipes[].restoreProven
  // both under-report), which is precisely the claim a customer's auditor asks about.
  await recordDiagWrite(scheduler, "restore-receipt", () =>
    scheduler.fetch(doURL("/restore-proven"), {
      method: "POST",
      body: JSON.stringify({ downpipeId, method, runId }),
      headers: callerHeaders(caller),
    }),
  );
}

// stampRestoreTested records the "Last restore test" RECENCY for a downpipe after a MANUAL drill, blind
// verify or keyless attestation actually ran (the run was opened), so the field updates without waiting for
// the weekly scheduled test (owner: a passing manual drill/verify left "Last restore test: Never tested").
// It posts to the SAME DO route the cron uses (/restore-test-complete -> completeRestoreTest), carrying the
// outcome and, when measured, the recovery cost (durationMs / bytesVerified feed the RTO estimate; the
// scheduled path passes the same). Best-effort and behind a guard, like stampRestoreProven: a stamp hiccup
// must never turn a real result into a failure, and the result still returns. Only redaction-safe counts +
// the downpipe id cross the wire, never a key or value.
export async function stampRestoreTested(
  scheduler: DurableObjectStub,
  caller: Caller,
  downpipeId: string,
  ok: boolean,
  // Each metric accepts undefined explicitly (exactOptionalPropertyTypes) so a caller can forward a
  // DrillResult's optional fields directly; an undefined value is dropped by JSON.stringify, so it reaches
  // completeRestoreTest as honestly absent (no fabricated 0) and contributes no RTO sample.
  metrics: { recordsVerified?: number | undefined; durationMs?: number | undefined; bytesVerified?: number | undefined } = {},
): Promise<void> {
  // G100: CHECKED best-effort, same discipline as stampRestoreProven. A lost recency stamp leaves "Last
  // restore test: Never tested" on a downpipe whose drill actually PASSED -- the console reads it, the
  // posture checks read it, and the pack reports it -- so the loss must be visible rather than inferred.
  await recordDiagWrite(scheduler, "restore-receipt", () =>
    scheduler.fetch(doURL("/restore-test-complete"), {
      method: "POST",
      body: JSON.stringify({ id: downpipeId, ok, ...metrics }),
      headers: callerHeaders(caller),
    }),
  );
}

// stampAttendedVerification records the NARROW attended-verification compliance stamp for ONE run after the
// router sampled-and-verified it from an operator-supplied master (key-posture attend). It forwards the
// verified caller so the DO re-checks drill.run (defence in depth) and attributes the prover, and it is fully
// best-effort like stampRestoreProven/stampRestoreTested: a hiccup recording the stamp must NEVER turn a
// genuine verification result into a failure, so any error is swallowed with a coarse log and the result
// still returns. Only redaction-safe facts cross the wire (the downpipe + run ids, the outcome, the sample
// rate, whether the session was proven, and a CLOSED short reason code on a failure), never the master, the
// seed or any value. The DO (recordAttendedVerification) stamps restoreProven ONLY on a full proven pass.
export async function stampAttendedVerification(
  scheduler: DurableObjectStub,
  caller: Caller,
  facts: { downpipeId: string; runId: string; ok: boolean; sampleRate: number; provenSession: boolean; reason?: string; at?: number },
): Promise<void> {
  try {
    await scheduler.fetch(doURL("/attest-record"), {
      method: "POST",
      body: JSON.stringify(facts),
      headers: callerHeaders(caller),
    });
  } catch (e) {
    log("error", `attest-record stamp skipped (non-critical, verify still returned): ${(e as Error).message}`);
  }
}
