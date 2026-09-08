// The attended-verification SESSION store (key-posture attend): the durable state machine for an operator-run
// attended verification, layered as a leaf method group like every sibling scheduler-DO mixin. Attended
// verification lets an offline-key-only customer prove their backups restorable by supplying, through their
// browser, only the per-run MASTER keys (never the break-glass private). This mixin owns ONLY the session
// state under `attest-session:<id>`; the CRYPTO (issuing the live-possession challenge, verifying the proof,
// reading capsules, sampling runs from a master) all runs in the ROUTER (it needs env + destination I/O the
// DO does not do), which forwards the redaction-safe results here to persist. The session record carries NO
// key material by construction (see AttestSession in types.ts): seedB64 is a sampling seed, proofHash is a
// hash deleted once proven, and the submitted masters are used only in the router's verify request and never
// reach this store. `this` is SchedulerDOSurface (like every sibling mixin), so these methods call
// this.requireCapability / this.persistDownpipeState / this.state exactly as before; the routing sub-dispatch
// (scheduler-do-routing-signals.ts routeRestoreTests) reaches them through the composed class.

import type { Capability, Role } from "../admin/identity.ts";
import type { AttestSession, AttestSessionRunState } from "./types.ts";
import { AuthError, type SchedulerDOCtor } from "./scheduler-do-base.ts";
import { newULID } from "./scheduler-helpers.ts";

// ATTEST_SESSION_PREFIX is the storage-key namespace; ATTEST_SESSION_TTL_MS is the default 8h session
// lifetime (a create refuses while an active non-expired session exists; a session past its expiry reads as
// "expired" and no longer blocks a fresh create).
const ATTEST_SESSION_PREFIX = "attest-session:";
const ATTEST_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

// AttestCaller is the forwarded, verified caller these methods gate on: the stable subject (the ownership
// axis), the display email (recorded on a full proof), the role + optional resolved capability set (the
// drill.run re-check). Null for an absent/undecodable caller header, which fails every check closed.
type AttestCaller = { role: Role; email: string | null; subject: string | null; capabilities?: ReadonlySet<Capability> } | null;

// effectiveStatus resolves the status a reader should see: an ACTIVE session past its expiry reads as
// "expired" (treated as aborted for the one-active-session rule), so a stale session never wedges the slot
// or reads as still running. A complete/aborted/already-expired status is returned unchanged.
function effectiveStatus(s: AttestSession, now: number): AttestSession["status"] {
  if (s.status === "active" && now > s.expiresAt) return "expired";
  return s.status;
}

// stripProofHash returns the session WITHOUT the challenge proof hash, the shape a create/status reply hands
// back. The proof hash is server-side-only (it is deleted the moment the session is proven); it is never a
// secret (it is sha384(expectedProof)), but the console never needs it, so least-disclosure omits it.
function stripProofHash(s: AttestSession): AttestSession {
  const copy: AttestSession = { ...s };
  delete copy.proofHash;
  return copy;
}

export function AttestMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // readAttestSession loads one session by id (null for an absent id or a missing record).
    async readAttestSession(id: string): Promise<AttestSession | null> {
      if (!id) return null;
      return (await this.state.storage.get<AttestSession>(`${ATTEST_SESSION_PREFIX}${id}`)) ?? null;
    }

    // findActiveAttestSession returns the single ACTIVE non-expired session, or null. It is the one-active-
    // session guard the create enforces: an expired session (past expiresAt) or a complete/aborted one does
    // not count, so a fresh create is admitted once the prior session has ended or lapsed.
    async findActiveAttestSession(now: number): Promise<AttestSession | null> {
      const map = await this.state.storage.list<AttestSession>({ prefix: ATTEST_SESSION_PREFIX });
      for (const s of map.values()) {
        if (s.status === "active" && now <= s.expiresAt) return s;
      }
      return null;
    }

    // requireAttestOwner enforces caller.subject === session.createdBy on every non-create route. A NULL
    // subject (the bare-token break-glass, or an undecodable caller) can NEVER own a session: ownership
    // requires a non-null subject that matches the recorded creator, so a session created by an attributable
    // identity is drivable ONLY by that exact identity. Throws AuthError -> the DO fetch maps it to 403.
    requireAttestOwner(s: AttestSession, caller: AttestCaller): void {
      const subject = caller?.subject ?? null;
      if (subject === null || subject !== s.createdBy) {
        throw new AuthError("forbidden: not the attest session owner");
      }
    }

    // attestSessionCreate stores a new session IFF no active non-expired session exists (one active session
    // per account). The router has already issued the challenge + pinned the runs + generated the seed; this
    // method re-checks drill.run (defence in depth), REFUSES a null-subject caller (the break-glass token
    // cannot OWN a session: it could never be attributed on the later owner-bound routes, and would wedge the
    // one-active slot for 8h), stamps the owner + timestamps, and persists. It returns the created session
    // (proof hash stripped) or, on conflict, the existing active session's id so the console can resume it.
    async attestSessionCreate(
      req: { sampleRate?: number; seedB64?: string; proofHash?: string; runs?: Array<{ downpipeId?: string; runId?: string; name?: string; recordCount?: number }> },
      caller: AttestCaller,
    ): Promise<{ created: boolean; session?: AttestSession; alreadyActive?: boolean; existingId?: string; status?: AttestSession["status"] }> {
      this.requireCapability(caller, "drill.run");
      const subject = caller?.subject ?? null;
      if (subject === null) {
        throw new AuthError("forbidden: attended verification requires an attributable identity (the break-glass token cannot own a session)");
      }
      const now = Date.now();
      const active = await this.findActiveAttestSession(now);
      if (active) {
        return { created: false, alreadyActive: true, existingId: active.id, status: effectiveStatus(active, now) };
      }
      const seedB64 = typeof req.seedB64 === "string" ? req.seedB64 : "";
      const proofHash = typeof req.proofHash === "string" ? req.proofHash : "";
      if (seedB64 === "" || proofHash === "") throw new Error("attest session requires a sampling seed and a challenge proof hash");
      const sampleRate = typeof req.sampleRate === "number" && Number.isFinite(req.sampleRate) ? Math.max(1, Math.min(100, Math.trunc(req.sampleRate))) : 100;
      const runs: AttestSessionRunState[] = (Array.isArray(req.runs) ? req.runs : [])
        .filter((r): r is { downpipeId: string; runId: string; name?: string; recordCount?: number } => typeof r?.downpipeId === "string" && r.downpipeId.length > 0 && typeof r?.runId === "string" && r.runId.length > 0)
        .map((r) => ({
          downpipeId: r.downpipeId,
          runId: r.runId,
          ...(typeof r.name === "string" ? { name: r.name } : {}),
          ...(typeof r.recordCount === "number" && Number.isFinite(r.recordCount) ? { recordCount: r.recordCount } : {}),
          state: "pending" as const,
        }));
      if (runs.length === 0) throw new Error("attest session requires at least one pinned run");
      const session: AttestSession = {
        id: newULID(now),
        createdBy: subject,
        createdByEmail: caller?.email ? caller.email : null,
        createdAt: now,
        expiresAt: now + ATTEST_SESSION_TTL_MS,
        sampleRate,
        seedB64,
        proofHash,
        proven: false,
        status: "active",
        runs,
      };
      await this.state.storage.put(`${ATTEST_SESSION_PREFIX}${session.id}`, session);
      return { created: true, session: stripProofHash(session) };
    }

    // attestSessionGet returns the FULL session (INCLUDING the proof hash) to the router, which needs it to
    // verify the submitted proof on the prove route; the router strips it before any console reply. Enforces
    // drill.run + ownership. Returns { session: null } for a missing record (the router maps that to 404) and
    // reports the effective status (an expired active session reads as "expired").
    async attestSessionGet(id: string, caller: AttestCaller): Promise<{ session: AttestSession | null }> {
      this.requireCapability(caller, "drill.run");
      const s = await this.readAttestSession(id);
      if (!s) return { session: null };
      this.requireAttestOwner(s, caller);
      return { session: { ...s, status: effectiveStatus(s, Date.now()) } };
    }

    // attestSessionMarkProven flips proven:true and DELETES the proof hash once the router has verified the
    // operator's live-possession proof. Enforces drill.run + ownership; refuses a session that is not active
    // (complete/aborted/expired). Idempotent on an already-proven session.
    async attestSessionMarkProven(id: string, caller: AttestCaller): Promise<{ ok: boolean }> {
      this.requireCapability(caller, "drill.run");
      const s = await this.readAttestSession(id);
      if (!s) throw new Error("attest session not found");
      this.requireAttestOwner(s, caller);
      if (s.proven) return { ok: true };
      if (s.status !== "active" || Date.now() > s.expiresAt) throw new Error("attest session is not active");
      s.proven = true;
      delete s.proofHash;
      await this.state.storage.put(`${ATTEST_SESSION_PREFIX}${id}`, s);
      return { ok: true };
    }

    // attestSessionRecordVerify applies the router's per-run verify OUTCOMES onto the session (state +
    // counts), completing the session once no run is still pending. Enforces drill.run + ownership + proven
    // (verify may run only on a proven session). It updates ONLY runs that are pinned in the session (a
    // result for an unknown runId is ignored, never invented), so the router cannot smuggle a run in. Returns
    // the progress tally + the (possibly updated) status.
    async attestSessionRecordVerify(
      req: { id?: string; results?: Array<{ runId?: string; state?: string; recordsVerified?: number; recordsTotal?: number; at?: number }> },
      caller: AttestCaller,
    ): Promise<{ progress: { verified: number; failed: number; pending: number; total: number }; status: AttestSession["status"] }> {
      this.requireCapability(caller, "drill.run");
      const id = typeof req.id === "string" ? req.id : "";
      const s = await this.readAttestSession(id);
      if (!s) throw new Error("attest session not found");
      this.requireAttestOwner(s, caller);
      if (!s.proven) throw new AuthError("forbidden: attest session is not proven");
      const now = Date.now();
      for (const r of Array.isArray(req.results) ? req.results : []) {
        if (typeof r?.runId !== "string") continue;
        const run = s.runs.find((x) => x.runId === r.runId);
        if (!run) continue; // never invent a run not pinned in this session
        if (r.state === "verified" || r.state === "failed" || r.state === "skipped") run.state = r.state;
        if (typeof r.recordsVerified === "number" && Number.isFinite(r.recordsVerified)) run.recordsVerified = r.recordsVerified;
        if (typeof r.recordsTotal === "number" && Number.isFinite(r.recordsTotal)) run.recordsTotal = r.recordsTotal;
        run.at = typeof r.at === "number" && Number.isFinite(r.at) ? r.at : now;
      }
      const pending = s.runs.filter((x) => x.state === "pending").length;
      if (pending === 0 && s.status === "active") s.status = "complete";
      await this.state.storage.put(`${ATTEST_SESSION_PREFIX}${id}`, s);
      const verified = s.runs.filter((x) => x.state === "verified").length;
      const failed = s.runs.filter((x) => x.state === "failed").length;
      return { progress: { verified, failed, pending, total: s.runs.length }, status: s.status };
    }

    // attestSessionAbort marks an active session aborted (a no-op on an already-ended session). Enforces
    // drill.run + ownership. Aborting frees the one-active-session slot so the operator can start a fresh one.
    async attestSessionAbort(id: string, caller: AttestCaller): Promise<{ ok: boolean; status: AttestSession["status"] }> {
      this.requireCapability(caller, "drill.run");
      const s = await this.readAttestSession(id);
      if (!s) throw new Error("attest session not found");
      this.requireAttestOwner(s, caller);
      if (s.status === "active") {
        s.status = "aborted";
        await this.state.storage.put(`${ATTEST_SESSION_PREFIX}${id}`, s);
      }
      return { ok: true, status: s.status };
    }
  };
}
