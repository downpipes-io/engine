// router-attest.ts -- the attended-verification session routes (key-posture attend). Attended verification
// lets an offline-key-only customer prove their backups restorable by supplying, through their browser, only
// the per-run MASTER keys (never the break-glass private). This spoke does the CRYPTO + I/O the scheduler DO
// cannot: it issues the live-possession challenge (bound to the break-glass PUBLIC the engine holds in every
// posture), verifies the operator's proof, reads the run capsules from the destination, and samples-and-
// verifies each run from a browser-supplied master to a discard sink -- then forwards only redaction-safe
// results to the DO, which owns the durable session state (scheduler-do-attest.ts) and the narrow compliance
// stamp. The MASTERS are used ONLY within a verify request and are NEVER stored: the session record holds a
// sampling seed + a challenge proof hash, never a key (AttestSession's closed shape enforces this).
//
// Every route gates drill.run + is rate-limited + audited. POST /attest/session/create additionally requires
// STEP-UP (it is in STEPUP_SUBS, gated once in handleAdmin before this spoke) because starting a session is
// what enables per-run masters. Every non-create route is OWNER-BOUND: the DO refuses a caller whose subject
// differs from the session's creator (403), and a null-subject bare-token caller can never own a session.
import type { Env } from "../env.d.ts";
import { type RouterCtx, doURL } from "./router-helpers.ts";
import { jsonResponse, jsonError, gate, callerHeaders, rateLimited, recordAudit, stampAttendedVerification } from "./router-core.ts";
import { withRunDestFallback } from "./router-sources.ts";
import { loadConfigWrapKey } from "./config-secret.ts";
import { issueAttestChallenge, verifyAttestProof } from "../attest/challenge.ts";
import { verifyRunWithMaster, sampleCount } from "../attest/verify.ts";
import { readRunCapsule, type ObjectStore, type RunCapsule } from "../format/reader.ts";
import { buildDestination, type RuntimeDestConfig } from "../dest/factory.ts";
import { loadSigner, verifierFrom } from "../keys-env.ts";
import { classifyRestoreFailure, coarseRestoreTestReasonCode } from "../restore-reasons.ts";
import { b64urlEncode, b64urlDecode } from "../crypto/bytes.ts";
import type { AttestSession, DownpipeState, RunHistoryEntry } from "../sched/types.ts";
import type { Caller } from "./identity.ts";

// ATTEST_VERIFY_BATCH_MAX caps how many runs one POST /attest/session/verify request may carry, so a single
// call cannot fan out an unbounded number of destination reads + decrypt passes.
const ATTEST_VERIFY_BATCH_MAX = 25;
// ATTEST_SEED_BYTES is the per-session sampling-seed length (a reproducible random selector, never a key).
const ATTEST_SEED_BYTES = 32;

// fetchMinRunlogIndex reads the scheduler DO's account-global runlogCounter (GET /scheduler-signals) as the
// out-of-band anti-rollback pin (HI-05), exactly as the blind restore test does: it is allocated
// independently of the destination bucket a verify reads, so a bucket-write adversary who replays an older,
// whole, validly-signed RUNLOG snapshot cannot roll this number back too. Best-effort + fail-open: a
// fetch/parse hiccup or a non-finite value leaves the pin undefined (freshness stays advisory), never a
// reason the verification itself fails.
async function fetchMinRunlogIndex(scheduler: DurableObjectStub): Promise<number | undefined> {
  try {
    const r = await scheduler.fetch(doURL("/scheduler-signals"), { method: "GET" });
    const j = (await r.json()) as { runlog?: unknown };
    const rl = j.runlog && typeof j.runlog === "object" ? (j.runlog as Record<string, unknown>) : null;
    const counter = rl ? Number(rl.counter) : NaN;
    return Number.isFinite(counter) && counter >= 0 ? counter : undefined;
  } catch {
    return undefined;
  }
}

// reqSigner throws a coarse, value-free reason when SIGNER_PRIVATE is unset (the verifier cannot be built).
function reqSigner(v: string | undefined): string {
  if (!v) throw new Error("missing required configuration: SIGNER_PRIVATE");
  return v;
}

// readCapsuleFromDest builds a read-only ObjectStore over a destination and returns the run's master-capsule
// wraps + key commitment (readRunCapsule signature-verifies the manifest first, so a tampered/forged manifest
// is refused before its capsule is served). It mirrors verify.ts's store/verifier construction so the capsule
// read and the master verify resolve the same signed run; the capsule is already sitting in the customer's own
// bucket, so serving it to the authenticated owner discloses nothing new (it is undecryptable without the
// break-glass private, which stays in the browser).
async function readCapsuleFromDest(env: Env, runId: string, destOverride: RuntimeDestConfig | null): Promise<RunCapsule> {
  const signer = await loadSigner(reqSigner(env.SIGNER_PRIVATE));
  const verifier = verifierFrom(signer);
  const dest = await buildDestination(env, undefined, destOverride ?? null);
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  return readRunCapsule(store, runId, verifier);
}

// readSessionOrResponse fetches the session from the DO (which enforces drill.run + ownership) and returns it,
// or the DO's Response to propagate verbatim (a 403 ownership refusal, a 400, a 500) or a 404 when the session
// id is unknown. The DO returns the FULL session (including the proof hash the prove route needs); callers
// that reply to the console strip the proof hash first.
async function readSessionOrResponse(scheduler: DurableObjectStub, caller: Caller, sessionId: string): Promise<AttestSession | Response> {
  const gr = await scheduler.fetch(doURL(`/attest-session/get?id=${encodeURIComponent(sessionId)}`), { method: "GET", headers: callerHeaders(caller) });
  if (!gr.ok) return gr; // propagate the DO's 403 (ownership) / 400 / 500 verbatim
  const { session } = (await gr.json()) as { session: AttestSession | null };
  if (!session) return jsonError("attest session not found", 404);
  return session;
}

// handleAttest dispatches the attended-verification session group. Returns the route's Response, or null when
// no case here matched (the hub falls to the next spoke).
export async function handleAttest(ctx: RouterCtx): Promise<Response | null> {
  const { req, env, url, scheduler, caller, sub, sourceIp } = ctx;
  switch (`${req.method} ${sub}`) {
    // ---- start a session: pin the latest completed run per downpipe + issue the live-possession challenge --
    case "POST /attest/session/create": {
      const body = (await req.json().catch(() => ({}))) as { scope?: unknown; sampleRate?: unknown };
      // ABSENT means the full 100% pass. A PRESENT sampleRate is refused unless it is a whole percentage from
      // 1 to 100, rather than clamped and truncated into one:
      // 0 became 1, a billion became 100, 50.9 became 50 and a string became 100, and the session then reported
      // back the rate the ENGINE chose as though the operator had asked for it. This rate is stamped onto the
      // attested-verification record (recordAttendedVerification) and decides whether restoreProven is set at
      // all, so an operator who asked for one thing and got another is left with an assurance record that
      // misdescribes the check they ran.
      const sampleRateBad = body.sampleRate !== undefined && body.sampleRate !== null && (typeof body.sampleRate !== "number" || !Number.isInteger(body.sampleRate) || body.sampleRate < 1 || body.sampleRate > 100);
      const sampleRate = typeof body.sampleRate === "number" && Number.isInteger(body.sampleRate) && body.sampleRate >= 1 && body.sampleRate <= 100 ? body.sampleRate : 100;
      const denied = gate(caller, "drill.run");
      if (denied) {
        await recordAudit(scheduler, caller, sourceIp, "attest-session-started", "denied", { kind: "attest-session", sessionId: "", runs: 0, sampleRate });
        return denied;
      }
      // Refused AFTER the capability gate, so an unauthorised caller still gets the 403 they would have got
      // before: a body check that ran first would answer a caller who holds nothing a different status from
      // the one the gate gives, which is a shape the gate-observed-as-refused suite reads as a leak.
      if (sampleRateBad) return jsonError("sampleRate must be a whole percentage from 1 to 100 (omit it to verify every record)", 400);
      // Attended verification is masters-enabling; only an ATTRIBUTABLE identity can own a session (the
      // break-glass token has no stable subject to enforce ownership against on the later routes, and would
      // wedge the one-active slot for 8h). Refuse the bare-token / null-subject caller with a clear reason.
      if (caller.subject === null) {
        await recordAudit(scheduler, caller, sourceIp, "attest-session-started", "denied", { kind: "attest-session", sessionId: "", runs: 0, sampleRate });
        return jsonError("attended verification requires an attributable identity (passkey or SSO); the break-glass token cannot own a session", 403);
      }
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      // The challenge is bound to the break-glass PUBLIC the engine holds in every posture; without it there
      // is nothing to prove live possession against, so refuse with an honest, actionable reason.
      if (typeof env.BREAK_GLASS_PUBLIC !== "string" || env.BREAK_GLASS_PUBLIC.trim() === "") {
        return jsonError("attended verification needs the break-glass public key configured (BREAK_GLASS_PUBLIC); complete the key ceremony first", 400);
      }
      // Resolve the selection: an explicit scope (downpipe ids that exist) else all ENABLED downpipes, then
      // pin the LATEST COMPLETED (status "ok") run per selected downpipe from its history ring (newest-first),
      // skipping any downpipe with no completed run. One /downpipes read + one /history (all rings) read.
      const dps = (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as DownpipeState[];
      const hist = (await (await scheduler.fetch(doURL("/history"), { method: "GET" })).json()) as { byDownpipe?: Record<string, RunHistoryEntry[]> };
      const byDownpipe = hist.byDownpipe ?? {};
      const scope = Array.isArray(body.scope) ? body.scope.filter((x): x is string => typeof x === "string") : null;
      const selected = dps.filter((d) => (scope ? scope.includes(d.config.id) : d.config.enabled));
      const pinned: Array<{ downpipeId: string; runId: string; name: string; recordCount: number }> = [];
      for (const d of selected) {
        const ring = byDownpipe[d.config.id] ?? [];
        const latestOk = ring.find((e) => e.status === "ok");
        if (!latestOk) continue; // no completed run to verify; skip
        pinned.push({ downpipeId: d.config.id, runId: latestOk.runId, name: d.config.name, recordCount: typeof latestOk.recordCount === "number" ? latestOk.recordCount : 0 });
      }
      if (pinned.length === 0) return jsonError("no selected downpipe has a completed run to verify", 400);
      // A per-session sampling seed (a reproducible selector, NOT a key) + the live-possession challenge.
      const seed = crypto.getRandomValues(new Uint8Array(ATTEST_SEED_BYTES));
      const seedB64 = b64urlEncode(seed);
      const challenge = await issueAttestChallenge(env.BREAK_GLASS_PUBLIC);
      // Ask the DO to store the session atomically (one active session per account; it stamps the owner +
      // timestamps + a fresh id, and re-checks the attributable-subject rule). On conflict it returns the
      // existing active session's id so the console can resume it; the freshly-issued challenge is discarded.
      const createResp = await scheduler.fetch(doURL("/attest-session/create"), {
        method: "POST",
        body: JSON.stringify({ sampleRate, seedB64, proofHash: challenge.proofHash, runs: pinned.map((p) => ({ downpipeId: p.downpipeId, runId: p.runId, name: p.name, recordCount: p.recordCount })) }),
        headers: callerHeaders(caller),
      });
      if (!createResp.ok) return createResp; // propagate the DO's refusal (403 not-attributable, etc.)
      const created = (await createResp.json()) as { created: boolean; session?: { id: string }; alreadyActive?: boolean; existingId?: string; status?: string };
      if (created.alreadyActive === true) {
        return new Response(JSON.stringify({ error: "an attended-verification session is already active for this account", sessionId: created.existingId ?? "", alreadyActive: true, status: created.status }), { status: 409, headers: { "content-type": "application/json" } });
      }
      const sessionId = created.session?.id ?? "";
      const records = pinned.reduce((sum, p) => sum + sampleCount(p.recordCount, sampleRate), 0);
      await recordAudit(scheduler, caller, sourceIp, "attest-session-started", "success", { kind: "attest-session", sessionId, runs: pinned.length, sampleRate });
      return jsonResponse({
        sessionId,
        challenge: { ciphertextB64: challenge.ciphertextB64, nonceB64: challenge.nonceB64 },
        runs: pinned,
        sampleRate,
        estimate: { runs: pinned.length, records },
      });
    }

    // ---- prove live possession of the break-glass private (the challenge round-trip) ----------------------
    case "POST /attest/session/prove": {
      const denied = gate(caller, "drill.run");
      if (denied) return denied;
      const body = (await req.json().catch(() => ({}))) as { sessionId?: unknown; proofB64?: unknown };
      const sessionId = typeof body.sessionId === "string" ? body.sessionId : "";
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const s = await readSessionOrResponse(scheduler, caller, sessionId);
      if (s instanceof Response) return s;
      if (s.proven) return jsonResponse({ ok: true }); // idempotent: already proven
      if (typeof s.proofHash !== "string" || s.proofHash === "") return jsonError("this session has no pending challenge to prove", 400);
      const proofB64 = typeof body.proofB64 === "string" ? body.proofB64 : "";
      const passed = await verifyAttestProof(s.proofHash, proofB64);
      if (!passed) {
        await recordAudit(scheduler, caller, sourceIp, "attest-session-proven", "denied", { kind: "attest-session", sessionId, runs: s.runs.length, sampleRate: s.sampleRate });
        return jsonError("the live-possession proof did not verify", 400);
      }
      const mp = await scheduler.fetch(doURL("/attest-session/prove"), { method: "POST", body: JSON.stringify({ id: sessionId }), headers: callerHeaders(caller) });
      if (!mp.ok) return mp;
      await recordAudit(scheduler, caller, sourceIp, "attest-session-proven", "success", { kind: "attest-session", sessionId, runs: s.runs.length, sampleRate: s.sampleRate });
      return jsonResponse({ ok: true });
    }

    // ---- serve the run capsules the browser needs to recover each pinned run's master locally --------------
    case "POST /attest/session/capsules": {
      const denied = gate(caller, "drill.run");
      if (denied) return denied;
      const body = (await req.json().catch(() => ({}))) as { sessionId?: unknown; runIds?: unknown };
      const sessionId = typeof body.sessionId === "string" ? body.sessionId : "";
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const s = await readSessionOrResponse(scheduler, caller, sessionId);
      if (s instanceof Response) return s;
      if (!s.proven) return jsonError("prove live possession before requesting capsules", 403);
      const requested = Array.isArray(body.runIds) ? body.runIds.filter((x): x is string => typeof x === "string") : [];
      if (requested.length === 0) return jsonError("runIds must be a non-empty array of pinned run ids", 400);
      const pinnedRuns = new Set(s.runs.map((r) => r.runId));
      // NEVER serve a capsule for a runId not pinned in THIS session: refuse the whole request (fail closed).
      for (const runId of requested) {
        if (!pinnedRuns.has(runId)) return jsonError(`runId ${runId} is not pinned in this session`, 400);
      }
      const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
      const capsules: Array<{ runId: string; masterCapsule: RunCapsule["masterCapsule"]; keyCommitment: string; recordCount: number }> = [];
      const failures: Array<{ runId: string; reason: string }> = [];
      for (const runId of requested) {
        // Per-downpipe destination resolution + 3-2-1 replica fallback, exactly as the restore path does.
        const res = await withRunDestFallback(
          scheduler,
          runId,
          undefined,
          async (cfg): Promise<{ ok: boolean; capsule?: RunCapsule; reason?: string }> => {
            try {
              return { ok: true, capsule: await readCapsuleFromDest(env, runId, cfg) };
            } catch (e) {
              return { ok: false, reason: classifyRestoreFailure(e) };
            }
          },
          wrapKey,
        );
        if (res.ok && res.capsule) {
          capsules.push({ runId, masterCapsule: res.capsule.masterCapsule, keyCommitment: res.capsule.keyCommitment, recordCount: res.capsule.declaredRecordCount });
        } else {
          failures.push({ runId, reason: res.reason ?? "capsule read failed" });
        }
      }
      return jsonResponse({ capsules, ...(failures.length > 0 ? { failures } : {}) });
    }

    // ---- verify a batch of runs from browser-supplied masters (sample-decrypt to a discard sink) ----------
    case "POST /attest/session/verify": {
      const denied = gate(caller, "drill.run");
      if (denied) return denied;
      const body = (await req.json().catch(() => ({}))) as { sessionId?: unknown; batch?: unknown };
      const sessionId = typeof body.sessionId === "string" ? body.sessionId : "";
      const batch = Array.isArray(body.batch) ? body.batch : [];
      if (batch.length === 0) return jsonError("batch must be a non-empty array of { runId, masterB64 }", 400);
      if (batch.length > ATTEST_VERIFY_BATCH_MAX) return jsonError(`batch too large (max ${ATTEST_VERIFY_BATCH_MAX} runs per request)`, 400);
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const s = await readSessionOrResponse(scheduler, caller, sessionId);
      if (s instanceof Response) return s;
      if (!s.proven) return jsonError("prove live possession before verifying runs", 403);
      const pinned = new Map(s.runs.map((r) => [r.runId, r] as const));
      // STRICT: every batch runId must be pinned in this session. A non-pinned run is never verified or
      // stamped (the masters can only ever be spent on a run this session committed to).
      for (const item of batch) {
        const rid = (item as { runId?: unknown }).runId;
        if (typeof rid !== "string" || !pinned.has(rid)) return jsonError("a runId in the batch is not pinned in this session", 400);
      }
      const minRunlogIndex = await fetchMinRunlogIndex(scheduler);
      const seed = b64urlDecode(s.seedB64);
      const wrapKey = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
      const now = Date.now();
      const results: Array<{ runId: string; ok: boolean; recordsVerified: number; recordsTotal: number; failures: number; isLatest: boolean; reason?: string }> = [];
      const updates: Array<{ runId: string; state: "verified" | "failed"; recordsVerified: number; recordsTotal: number; at: number }> = [];
      for (const item of batch) {
        const { runId, masterB64 } = item as { runId: string; masterB64?: unknown };
        const pin = pinned.get(runId)!;
        let master: Uint8Array;
        try {
          master = b64urlDecode(typeof masterB64 === "string" ? masterB64 : "");
        } catch {
          // A malformed master encoding is a per-run failure, never a thrown 500; record it and move on.
          results.push({ runId, ok: false, recordsVerified: 0, recordsTotal: 0, failures: 0, isLatest: false, reason: "master is not valid base64url" });
          updates.push({ runId, state: "failed", recordsVerified: 0, recordsTotal: 0, at: now });
          await stampAttendedVerification(scheduler, caller, { downpipeId: pin.downpipeId, runId, ok: false, sampleRate: s.sampleRate, provenSession: s.proven, reason: "other", at: now });
          continue;
        }
        // Per-downpipe dest resolution + replica fallback; the master opens ONLY this run (a per-run key bound
        // to its own runId by the key commitment). The master is used here and never stored.
        // The attended posture's claim is that the operator's key is gone when the session ends. This master
        // was decapsulated in the operator's browser and decoded in this frame, so this is the frame that OWNS
        // it and the only one that can end it. The Run cannot: openRunWithMaster is handed this buffer rather
        // than acquiring its own, so Run.dispose() deliberately leaves a supplied master alone.
        let result: Awaited<ReturnType<typeof verifyRunWithMaster>>;
        try {
          result = await withRunDestFallback(scheduler, runId, undefined, (cfg) => verifyRunWithMaster(env, runId, master, s.sampleRate, seed, cfg, minRunlogIndex), wrapKey);
        } finally {
          master.fill(0);
        }
        await stampAttendedVerification(scheduler, caller, {
          downpipeId: pin.downpipeId,
          runId,
          ok: result.ok,
          sampleRate: s.sampleRate,
          provenSession: s.proven,
          ...(result.ok ? {} : { reason: coarseRestoreTestReasonCode(result.reason) }),
          at: now,
        });
        results.push({ runId, ok: result.ok, recordsVerified: result.recordsVerified, recordsTotal: result.recordsTotal, failures: result.failures, isLatest: result.isLatest, ...(result.reason !== undefined ? { reason: result.reason } : {}) });
        updates.push({ runId, state: result.ok ? "verified" : "failed", recordsVerified: result.recordsVerified, recordsTotal: result.recordsTotal, at: now });
      }
      // Persist the per-run outcomes onto the session (the DO completes it once no run is still pending) and
      // read back the progress tally.
      const rvResp = await scheduler.fetch(doURL("/attest-session/record-verify"), { method: "POST", body: JSON.stringify({ id: sessionId, results: updates }), headers: callerHeaders(caller) });
      if (!rvResp.ok) return rvResp;
      const rv = (await rvResp.json()) as { progress: { verified: number; failed: number; pending: number; total: number } };
      await recordAudit(scheduler, caller, sourceIp, "attest-run-verified", "success", { kind: "attest-session", sessionId, runs: batch.length, sampleRate: s.sampleRate });
      return jsonResponse({ results, progress: rv.progress });
    }

    // ---- read the session status (proof hash stripped) ----------------------------------------------------
    case "GET /attest/session/status": {
      const denied = gate(caller, "drill.run");
      if (denied) return denied;
      const sessionId = url.searchParams.get("id") ?? "";
      const s = await readSessionOrResponse(scheduler, caller, sessionId);
      if (s instanceof Response) return s;
      const safe: AttestSession = { ...s };
      delete safe.proofHash; // never expose the challenge proof hash to the console
      return jsonResponse({ session: safe });
    }

    // ---- abort the session (frees the one-active slot) ----------------------------------------------------
    case "POST /attest/session/abort": {
      const denied = gate(caller, "drill.run");
      if (denied) return denied;
      const body = (await req.json().catch(() => ({}))) as { sessionId?: unknown };
      const sessionId = typeof body.sessionId === "string" ? body.sessionId : "";
      const limited = await rateLimited(scheduler, caller);
      if (limited) return limited;
      const ab = await scheduler.fetch(doURL("/attest-session/abort"), { method: "POST", body: JSON.stringify({ id: sessionId }), headers: callerHeaders(caller) });
      if (!ab.ok) return ab; // propagate the DO's 403 (ownership) / 400 (not found) verbatim
      const out = (await ab.json()) as { ok: boolean; status: string };
      await recordAudit(scheduler, caller, sourceIp, "attest-session-aborted", "success", { kind: "attest-session", sessionId });
      return jsonResponse({ ok: true, status: out.status });
    }

    default:
      return null;
  }
}
