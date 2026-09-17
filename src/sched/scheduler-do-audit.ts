// The audit-log subsystem: the tamper-evident, hash-chained, append-only record this DO holds, as
// AuditMixin, layered over a base whose `this` is SchedulerDOSurface, so
// every other subsystem records via `this.appendAudit` / `this.appendAuditFromRouter`. The AUDIT_*/auditHead/
// auditRollover keys, the genesis prev-hash, the chain hashing, the rollover cap and the verify/export shapes
// are this DO's single source of truth for the tamper-evident record.

import { AUDIT_CAP, AUDIT_NEAR_CAP_FRACTION, AUDIT_PREFIX, type AuditActorMethod, type AuditDraft, type AuditEvent, auditKey, buildEvent, diffStatus, type ExportFormat, earliestSeqOf, filterEventsAscending, GENESIS_PREV_HASH, headOf, pageEvents, STATUS_SNAPSHOT_KEY, type StatusObservation, type StatusSnapshot, toCSV, verifyChain } from "../admin/audit.ts";
import { mirrorAuditEvent } from "../admin/audit-mirror.ts";
import { ADMIN_COUNTERS_KEY, type AdminCounters, applyAdminCounters } from "../admin/diag-records.ts";
import { isHumanActorMethod } from "../admin/identity-roles.ts";
import { recordAuditGapPage, recordAuditMirrorFailure, recordCeremonyFault, recordChainVerdict, recordStorageAnomaly } from "./sched-fault-ledger.ts";
import { AUDIT_HEAD_KEY, AUDIT_ROLLOVER_KEY, AUDIT_VERIFY_META_KEY, type AuditHead, type AuditRolloverState, type AuditVerifyMeta, type SchedulerDOCtor, STATUS_BASELINE_KEY, type StatusBaselineState } from "./scheduler-do-base.ts";
import { nowMillisISO, parseAuditFilter } from "./scheduler-helpers.ts";

// AUTHN_FAILURE_AUDIT_WINDOW_MS bounds how often ONE row-identity may put an `authn-failure` row on the
// tamper-evident chain. One minute, the same figure as AUTH_SIGNAL_THROTTLE_MS (scheduler-do-idp.ts) and
// support-ingest's AUTH_FAILURE_THROTTLE_MS, and for the same reason: long enough that a storm costs one row,
// short enough that "is it still happening" stays answerable from the row timestamps.
const AUTHN_FAILURE_AUDIT_WINDOW_MS = 60_000;

// AUTHN_FAILURE_AUDIT_PENDING_FLUSH bounds how many ATTEMPTS the window will hold in memory for one
// row-identity before it writes early. 25, the same figure and the same argument as AUTH_SIGNAL_PENDING_FLUSH:
// the tally is an instance field, a Durable Object is evicted when idle and restarted on every deploy, and
// eviction destroys instance fields while durable storage survives. At 25 the chain carries a row per 26
// attempts rather than a row per window, so at most 25 attempts can ever be lost to an eviction, and a
// 600-failure sweep survives a restart as at least 575.
const AUTHN_FAILURE_AUDIT_PENDING_FLUSH = 25;

// AUTHN_FAILURE_AUDIT_KEY_CAP bounds how many distinct row-identities the isolate-local window may hold. See
// appendAuthnFailureAudit for why the key space is already tenant-bounded and why it still needs a ceiling.
const AUTHN_FAILURE_AUDIT_KEY_CAP = 64;

export function AuditMixin<TBase extends SchedulerDOCtor>(Base: TBase) {
  return class extends Base {
    // ---- Audit log: the tamper-evident, hash-chained, append-only record -------------
    // The chain lives under the `audit:` prefix keyed by a zero-padded monotonic sequence so a
    // storage list returns entries in order. The seq is derived from the highest existing entry
    // in the list, so no separate counter key is needed and the append is a SINGLE put: no
    // crash between two writes can diverge the seq from the stored entries.
    // SHA-384 over the canonical JSON of every field except hash, chaining each entry to the prior
    // one's hash (audit.ts owns the exact mechanism so the append and the verify never diverge).
    // REDACTION BY CONSTRUCTION: appendAudit takes only an AuditDraft, whose target is the closed
    // AuditTarget union, so no key/value/secret/private-fingerprint can ever be written.

    // loadAuditHead returns the persisted head pointer, RECONSTRUCTING it from the stored entries the
    // first time it is missing (a deployment upgraded mid-life: it has entries but no pointer yet). The
    // reconstruction is the only remaining full list over the chain, and it runs at most ONCE per
    // isolate-lifetime (the very first appendAudit after the upgrade), after which the pointer is
    // authoritative and every subsequent append is O(1). An empty chain reconstructs to the empty
    // sentinel (headSeq 0, count 0, GENESIS_PREV_HASH). It persists the reconstructed pointer so a later
    // read in the same isolate need not redo the scan.
    async loadAuditHead(): Promise<AuditHead> {
      const stored = (await this.state.storage.get<AuditHead>(AUDIT_HEAD_KEY)) ?? null;
      if (stored !== null) return stored;
      // No pointer yet: reconstruct from the entries (one-time, post-upgrade). listAllByPrefix
      // pages past the platform's one-page list limit (~DO_LIST_PAGE), so a chain longer than a page
      // still reconstructs to the TRUE head, not whatever a single truncated list() call happened to
      // return -- the same truncation shape guarded against elsewhere in the export path, but here a truncated read would
      // PERSIST a wrong head pointer (a future append would chain off a stale hash at a lower seq, risking
      // a seq collision with entries the truncated reconstruction never saw), so completeness matters even
      // more. Sort by the numeric seq too (defence: the padded keys already sort ascending, but a future
      // storage change must not silently reorder the head this pointer commits to).
      const existing = await this.listAllByPrefix<AuditEvent>(AUDIT_PREFIX);
      const values = [...existing.values()].sort((a, b) => a.seq - b.seq);
      const head: AuditHead =
        values.length === 0
          ? { headSeq: 0, headHash: GENESIS_PREV_HASH, count: 0 }
          : { headSeq: values[values.length - 1]!.seq, headHash: values[values.length - 1]!.hash, count: values.length };
      await this.state.storage.put(AUDIT_HEAD_KEY, head);
      // A REBUILT head pointer is expected exactly once (the first append after the upgrade that
      // introduced the pointer). A pointer that keeps needing reconstruction means the key is being LOST, and
      // a lost head is how an audit chain silently re-anchors: the next append chains off a head derived from
      // whatever entries survive, so a deletion in the middle of the chain heals itself out of existence. The
      // rebuild is right; being silent about a repeat is not. Counted only when entries EXIST (a rebuild on an
      // empty chain is the ordinary first-ever append).
      if (values.length > 0) await recordStorageAnomaly(this.state.storage, "audit-head-rebuilt");
      return head;
    }

    // appendAudit is the ONE write path for every audit entry, internal and router-driven alike. It
    // reads the persisted HEAD POINTER, a single DO key holding the head seq, head hash and
    // retained count, to chain the next entry off the head hash and key it head.seq+1, then persists
    // the entry AND the updated pointer in the same single-threaded DO storage turn. This makes the
    // append O(1): it reads the pointer rather than listing the whole chain (up to AUDIT_CAP=10000 entries
    // WITH values) on every audit write, avoiding an O(n) read on a hot auth/config path. The chain INTEGRITY
    // holds regardless: the new entry's prevHash is exactly the prior head's hash (so verifyChain's link check
    // is unaffected) and the seq is strictly monotonic from the pointer (so the contiguity/seq-gap check
    // is unaffected); only the head is LOCATED by a pointer read rather than a scan. The seq is taken
    // from the pointer's head seq, never reused, so a rollover that drops old entries cannot collide with
    // a live seq. The DO serialises its own storage so there is no concurrent-append race. ts is the DO's
    // clock (nowMillisISO), matching the run-history format.
    // noteAuditSourceIpGap folds ONE missing-source-IP observation into the DO's bounded admin-counter
    // aggregate. It writes through applyAdminCounters, the same pure redaction chokepoint the posted
    // tallies go through, so the key space stays bounded by ADMIN_COUNTER_NAMES and the value is an integer.
    // Best-effort: a counter write must never fail an audit append (the chain outranks its own diagnostics).
    async noteAuditSourceIpGap(): Promise<void> {
      try {
        const prior = await this.state.storage.get<AdminCounters>(ADMIN_COUNTERS_KEY);
        await this.state.storage.put(
          ADMIN_COUNTERS_KEY,
          applyAdminCounters(prior, { "audit-human-event-missing-source-ip": 1 }, new Date().toISOString()),
        );
      } catch {
        // The audit entry is already committed; a lost counter bump degrades this evidence, never the chain.
      }
    }

    async appendAudit(draft: AuditDraft): Promise<AuditEvent> {
      const head = await this.loadAuditHead();
      // Chain off the head hash. buildEvent links the new entry's prevHash to prev.hash (or GENESIS when
      // prev is null), so an empty chain (count 0) passes null and produces the genesis entry, and a
      // non-empty chain passes a minimal carrier of the head hash, buildEvent reads only .hash from it,
      // so this produces the identical entry the prior full-entry path did (the chain is byte-for-byte
      // unchanged), without a second read of the head entry.
      const prev: AuditEvent | null = head.count > 0 ? ({ hash: head.headHash } as AuditEvent) : null;
      const seq = head.headSeq + 1;
      const event = await buildEvent(draft, seq, nowMillisISO(), prev);
      await this.state.storage.put(auditKey(seq), event);
      // A HUMAN actor whose source IP was not captured, AT THE MOMENT THE ROW IS WRITTEN. The console
      // renders such rows honestly ("not recorded") and the pack's audit excerpt strips sourceIp from EVERY event
      // by design, so "why do some of our audit rows have no source IP?" is unanswerable from the pack alone: a
      // capture path that is failing (a proxy stripping the header, a route that never threaded it) and one that
      // is healthy produce exactly the same silence there. This counter answers it WITHOUT ever putting
      // an IP in the pack, which is why the evidence is a counter and not a field.
      //
      // WHAT IT ACTUALLY ESTABLISHES, AND NOTHING MORE. It counts ONLY rows THIS engine appends
      // from here on: the bump happens at append time and nothing counts, or could count, the rows already on the
      // chain. So a non-zero count means a capture failure that is HAPPENING, and its lastAt says when it last
      // did; the historical population (rows written before the capture path existed) is not counted, cannot be,
      // and is read off the audit rows themselves, which is where it lives. A {count, lastAt} pair can separate a
      // bounded historical population from an ongoing failure only if nothing ever adds a historical row to the
      // count, which is exactly what gating the bump at append time guarantees.
      //
      // Only human-borne methods are counted. An engine-observed event and the shared-token break-glass have no
      // interactive session to take an IP from, so counting them would raise a fault on a legitimate state,
      // and the counter would climb on a perfectly healthy engine until nobody looked at it any more.
      //
      // A METHOD TEST ALONE IS NOT ENOUGH: it fires on the commonest event in the estate.
      // scheduler-do-routing-identity.ts appends, on EVERY FAILED PASSKEY LOGIN, a draft with
      // actorMethod "passkey", actorSubject null, actorEmail null and sourceIp HARD-CODED null (the login-finish
      // route strips sourceIp off the inbound body, so the DO has no IP to thread and never will). "passkey"
      // there names the MECHANISM, not a person: an unauthenticated ceremony that FAILED has no verified
      // identity and no session to take an IP from, exactly like the engine and token cases above. Gating on
      // method alone would bump this counter on every cancelled WebAuthn prompt, wrong device, stale challenge
      // and credential-stuffing probe, with lastAt = now, on an engine whose capture path is working perfectly --
      // producing a healthy row {count:3, lastAt:<recent>} that is BYTE-IDENTICAL to the ongoing-capture-failure
      // row this counter exists to tell apart. Neither half of that discriminator would then mean anything: a
      // recent lastAt would not imply anything is wrong, and the count would not stay static on a healthy engine.
      //
      // The bump is gated on an ATTRIBUTED actor: an event whose actor the engine actually identified (a
      // subject or an email). That is the population the question is about -- "why do some of our audit rows
      // have no source IP?" is asked about rows that name a PERSON -- and it is the population whose IP the
      // engine had an opportunity to capture. An unattributed human-mechanism event (a failed authn ceremony)
      // is a legitimate state and is counted nowhere.
      const attributed = draft.actorSubject != null || draft.actorEmail != null;
      if (attributed && isHumanActorMethod(draft.actorMethod) && (draft.sourceIp === null || draft.sourceIp === undefined)) {
        await this.noteAuditSourceIpGap();
      }
      // Mirror the committed event as a structured log line for Logpush/SIEM delivery
      // (audit-mirror.ts). The event is redaction-safe by construction and the mirror
      // never throws, so this cannot affect the commit or the chain.
      // It REPORTS whether the line was emitted, and a failure is COUNTED. The mirror is the PUSH
      // leg of the SIEM audit channel; when it dies the customer's SIEM silently stops receiving events, and
      // without this count the pack could not confirm it either way. A count, nothing else -- no event content
      // leaves here.
      if (!mirrorAuditEvent(event)) await recordAuditMirrorFailure(this.state.storage);
      // The new retained count is the prior count plus this append; the rollover below caps it. The
      // pointer's head (seq + hash) is this just-written entry regardless of any rollover, because a
      // rollover drops the OLDEST entries, never the newest.
      let count = head.count + 1;
      // Enforce the retention cap at the one write path. Once the retained count
      // exceeds AUDIT_CAP, roll over the oldest entries so DO storage stays bounded. The seq stays
      // monotonic (we never reuse a seq), and the retained chain stays verifiable from its new earliest
      // entry (verifyAudit passes expectGenesis:false once a rollover is on record). EXPORT-BEFORE-
      // ROLLOVER is the operator path to keep the pruned history; the rollover is COUNTED and surfaced,
      // never a silent drop. After a rollover the retained count is exactly AUDIT_CAP.
      if (count > AUDIT_CAP) {
        await this.rollOverAudit(count - AUDIT_CAP);
        count = AUDIT_CAP;
      }
      // Persist the updated head pointer in the same DO storage turn as the entry put + any rollover, so
      // the pointer never drifts from the stored chain (the DO is single-threaded; there is no torn read).
      await this.state.storage.put(AUDIT_HEAD_KEY, { headSeq: seq, headHash: event.hash, count } satisfies AuditHead);
      return event;
    }

    // rollOverAudit prunes the `dropCount` OLDEST audit entries when the retained count exceeds
    // AUDIT_CAP, and records the new earliest retained seq + the cumulative rolled-over count. It reads
    // ONLY a bounded oldest window (dropCount keys, plus one more to read the new earliest after the
    // delete) via limited prefix lists, never the whole chain, so the rollover stays O(dropCount)
    // (dropCount is 1 in steady state: the cap is crossed by one entry per append). The keys are
    // zero-padded so an ascending prefix list is oldest-first. This carries only seqs/counts, never
    // entry content, so it is redaction-safe. It runs inside the same DO single-threaded storage turn as
    // the append, so the prune, the rollover record and the head-pointer count update are one atomic step.
    async rollOverAudit(dropCount: number): Promise<void> {
      if (dropCount <= 0) return;
      // The oldest dropCount keys: a bounded ascending list from the start of the prefix. (dropCount is
      // 1 in steady state; the limit keeps even a backlog drain bounded.)
      const oldest = await this.state.storage.list<AuditEvent>({ prefix: AUDIT_PREFIX, limit: dropCount });
      const toDrop = [...oldest.keys()];
      for (const k of toDrop) await this.state.storage.delete(k);
      // The earliest retained entry is now the first surviving audit key; read just that one (limit 1).
      const remaining = await this.state.storage.list<AuditEvent>({ prefix: AUDIT_PREFIX, limit: 1 });
      const firstKey = [...remaining.keys()][0];
      const earliest = firstKey !== undefined ? remaining.get(firstKey) : undefined;
      const prior = (await this.state.storage.get<AuditRolloverState>(AUDIT_ROLLOVER_KEY)) ?? null;
      const next: AuditRolloverState = {
        earliestRetainedSeq: earliest ? earliest.seq : (prior?.earliestRetainedSeq ?? 1),
        rolledOverCount: (prior?.rolledOverCount ?? 0) + toDrop.length,
      };
      await this.state.storage.put(AUDIT_ROLLOVER_KEY, next);
    }

    // auditCountAndNearCap reports the live audit count and whether it is at or above the near-cap
    // threshold, so the console can prompt an export before the rollover begins (the retention status
    // surface). It reads the RETAINED count from the head pointer rather than listing the whole
    // chain, so the status poll is O(1) like the append; the pointer's count is kept in lockstep with
    // the entry puts and the rollover, so it is the same number a full list would yield. It carries only
    // the integer count and the boolean, never an entry. count is the number of RETAINED entries
    // (post-rollover), which is the size that bounds DO storage and the number the near-cap warning is about.
    // AND IT CARRIES THE ROLLED-OVER COUNT, because the retained count SATURATES and the boolean derived
    // from it therefore cannot answer the question the warning exists to answer. `auditCount` is pinned at
    // exactly AUDIT_CAP from the first rollover onwards, so {count: 10000, nearCap: true} is the reading
    // BOTH at the moment nothing has been lost and after ten thousand entries have been destroyed. The
    // rollover record already holds the cumulative figure; reading it here is one bounded storage get and it
    // is the only thing that separates "export now and you keep everything" from "an export now keeps what
    // is left". Zero when no rollover has ever occurred, which is the ordinary estate.
    // CORRUPT MUST NOT BE BETTER TREATED THAN MISSING. loadAuditHead RECONSTRUCTS an absent
    // pointer by scanning the chain, so a DELETED head answers the true count; a PRESENT head is returned
    // verbatim, so a head whose count has been zeroed would answer `auditCount: 0` over a full chain. An
    // account that has lost the record would read healthier than one that has lost only the number inside it.
    //
    // The rule this applies is: a field that cannot answer is treated as absent, not believed. This applies it
    // to `count`, which is the field an operator actually reads. TWO tests, and the second is the one the
    // zeroed record needs: a count must be a non-negative integer, AND it must not contradict the record it
    // sits in. A head naming a newest entry at seq N > 0 while claiming zero entries is self-contradictory,
    // and no healthy write can produce it (appendAudit writes headSeq and count in the same object, in the
    // same storage turn).
    //
    // A count that cannot be trusted is NOT presented as a count. The true retained count is derived the same
    // way the absent path derives it, and `auditCountRecovered` rides with it so the ANSWER DIFFERS from the
    // answer a healthy record produces. Reporting the right number silently would leave the two states
    // indistinguishable, which is the defect this avoids.
    // auditHeadTrust is the ONE place that decides whether a PRESENT head pointer may be believed, so the
    // status probe and the disaster-recovery export cannot disagree about it: an export that keeps writing
    // whatever the record says, independent of the probe, would put a zeroed head seq into the artefact a
    // reconcile RESTORES FROM.
    //
    // Two tests. A field must be well-formed, and the record must not contradict itself: a head naming a
    // newest entry above seq 0 while claiming zero entries cannot be true, and no healthy write can produce
    // it, because appendAudit writes headSeq and count into one object in one storage turn.
    //
    // When it cannot be believed, the head is DERIVED from the chain, exactly as loadAuditHead derives an
    // ABSENT one. The full-chain read runs only on that path, so every healthy account is untouched.
    async auditHeadTrust(): Promise<{ head: AuditHead; usable: boolean }> {
      const head = await this.loadAuditHead();
      const countOk = Number.isInteger(head.count) && head.count >= 0 && !(head.count === 0 && Number.isInteger(head.headSeq) && head.headSeq > 0);
      const seqOk = Number.isInteger(head.headSeq) && head.headSeq >= 0 && typeof head.headHash === "string" && head.headHash.length > 0;
      if (countOk && seqOk) return { head, usable: true };
      const values = [...(await this.listAllByPrefix<AuditEvent>(AUDIT_PREFIX)).values()].sort((a, b) => a.seq - b.seq);
      const last = values.length > 0 ? values[values.length - 1]! : null;
      await recordStorageAnomaly(this.state.storage, "audit-head-count-lost");
      return {
        head: last === null ? { headSeq: 0, headHash: GENESIS_PREV_HASH, count: 0 } : { headSeq: last.seq, headHash: last.hash, count: values.length },
        usable: false,
      };
    }

    async auditCountAndNearCap(): Promise<{ auditCount: number; auditNearCap: boolean; auditRolledOverCount: number; auditCountRecovered?: true }> {
      const { head, usable } = await this.auditHeadTrust();
      const auditCount = head.count;
      const rollover = (await this.state.storage.get<AuditRolloverState>(AUDIT_ROLLOVER_KEY)) ?? null;
      const auditRolledOverCount = rollover !== null && Number.isFinite(rollover.rolledOverCount) && rollover.rolledOverCount > 0 ? Math.floor(rollover.rolledOverCount) : 0;
      return {
        auditCount,
        auditNearCap: auditCount >= Math.floor(AUDIT_CAP * AUDIT_NEAR_CAP_FRACTION),
        auditRolledOverCount,
        ...(usable ? {} : { auditCountRecovered: true as const }),
      };
    }

    // appendAuditFromRouter is the POST /audit handler: the router forwards a draft for a first-class
    // event it performed (or denied). The draft is already redaction-safe (the closed AuditTarget),
    // so the DO simply appends it. This route is INTERNAL: a DO fetch never leaves the account and
    // the router builds the request from scratch, so an inbound client cannot reach it (the same
    // invariant as the caller header, see identity.ts). The DO never exposes a client-editable audit
    // write; every entry is a by-product the engine records, which is the point of an append-only log.
    async appendAuditFromRouter(draft: AuditDraft): Promise<AuditEvent> {
      return this.appendAudit(draft);
    }

    // appendAuthnFailureAudit is the ONE write path for every `authn-failure` row (V16.3.1): the failed passkey
    // login, the refused SAML ACS, the refused OIDC / OAuth2 callback and the refused step-up re-authentication.
    // Four writers, one chokepoint, so the throttle below cannot be present on one path and absent on the next.
    //
    // WHY THE THROTTLE IS NOT TIDINESS, AND WHY THE ROWS WOULD BE A REGRESSION WITHOUT IT. AUDIT_CAP is 10,000
    // and rollOverAudit drops the OLDEST entries. authRateLimited admits AUTH_RATE_LIMIT_MAX_PER_WINDOW (30)
    // unauthenticated ceremony requests per minute per IP, and the SAML ACS and the OIDC callback both sit
    // behind exactly that limiter. One IP writing one row per failure therefore produces 1,800 rows an hour and
    // evicts the ENTIRE retained chain -- every role change, key ceremony and restore approval in it -- in about
    // five and a half hours; ten IPs do it in half an hour. Shipping an unthrottled row per failure on an
    // unauthenticated route hands an attacker a history-destruction primitive dressed as an audit improvement,
    // which is a worse defect than the invisible sweep it set out to fix. The engine already knew this on a
    // narrower path: support-ingest.ts says an unthrottled recorder there turns "the very act of observing an
    // attack into a write amplifier for it". Throttled, the worst case is 1,440 rows a day per row-identity and
    // the suppressed attempts survive in `attempts`.
    //
    // WHAT THE WINDOW IS KEYED ON, AND WHY IT IS EVERY FIELD THE ROW ASSERTS. The key carries the ceremony, the
    // actor method, the connection kind and id, and the actor subject and email. An audit row must not assert
    // something the code has not established: if `attempts` could span two connections or two people, then
    // {attempts: 7, connId: "okta-prod"} would read as seven failures against okta-prod when the code only
    // established at least one. Keying on every field the row names makes the count true by construction.
    //
    // WHAT IT COSTS. The window is isolate-local, exactly like recordAuthSignalThrottled and
    // support-ingest's shouldRecordAuthFailure, and there is no cross-isolate state to keep. An eviction inside
    // an open window loses at most AUTHN_FAILURE_AUDIT_PENDING_FLUSH deferred attempts. It can only
    // UNDER-report and never over-report, and the FIRST failure of every window is written immediately, so a
    // sweep is never invisible: only the precision of its tail is traded. Do not read `attempts` as a ledger.
    async appendAuthnFailureAudit(input: {
      ceremony: "passkey-login" | "sso-callback" | "step-up";
      actorMethod: AuditActorMethod;
      // Attributed ONLY on step-up, the one authn failure in the engine with a verified actor: the caller's
      // session established who they are independently of the assertion that just failed. Every other member
      // is an unauthenticated ceremony, and scheduler-do-recovery.ts already settled that an unauthenticated
      // caller must not choose the name the tamper-evident chain records as the actor.
      actorSubject?: string | null;
      actorEmail?: string | null;
      sourceIp: string | null;
      connKind?: "oidc" | "oauth2" | "saml";
      connId?: string;
    }): Promise<void> {
      const subject = input.actorSubject ?? null;
      const email = input.actorEmail ?? null;
      const key = `${input.ceremony}|${input.actorMethod}|${input.connKind ?? ""}|${input.connId ?? ""}|${subject ?? ""}|${email ?? ""}`;
      const now = Date.now();
      const last = this.authnFailureAuditWindow.get(key);
      const pending = this.authnFailureAuditPending.get(key) ?? 0;
      if (last !== undefined && now - last < AUTHN_FAILURE_AUDIT_WINDOW_MS && pending < AUTHN_FAILURE_AUDIT_PENDING_FLUSH) {
        // Inside the open window: defer the ROW, keep the ATTEMPT. The flush ceiling bounds what an isolate
        // eviction can cost, at one extra row per that many attempts.
        this.authnFailureAuditPending.set(key, pending + 1);
        return;
      }
      // The key space is bounded by the tenant's own configuration, not by the caller: a connId is recorded
      // only once it has RESOLVED from storage (so it is one of the connections an Owner created), and a
      // step-up subject belongs to an already-authenticated session (so it is a roster member). It still needs
      // a ceiling, because the map lives for the isolate's lifetime and would otherwise accumulate one entry
      // per member who has ever failed a step-up. Reclaim first: an entry whose window has expired with nothing
      // pending carries no information at all, so dropping it loses nothing. Only if the map is STILL full does
      // the row go unwritten, and then the drop is itself counted rather than silent.
      if (last === undefined && this.authnFailureAuditWindow.size >= AUTHN_FAILURE_AUDIT_KEY_CAP) {
        for (const [k, at] of [...this.authnFailureAuditWindow]) {
          if (now - at >= AUTHN_FAILURE_AUDIT_WINDOW_MS && (this.authnFailureAuditPending.get(k) ?? 0) === 0) {
            this.authnFailureAuditWindow.delete(k);
            this.authnFailureAuditPending.delete(k);
          }
        }
        if (this.authnFailureAuditWindow.size >= AUTHN_FAILURE_AUDIT_KEY_CAP) {
          await recordCeremonyFault(this.state.storage, "authn-failure-audit-key-cap");
          return;
        }
      }
      this.authnFailureAuditWindow.set(key, now);
      this.authnFailureAuditPending.delete(key);
      try {
        await this.appendAudit({
          actorSubject: subject,
          actorEmail: email,
          actorMethod: input.actorMethod,
          sourceIp: input.sourceIp,
          action: "authn-failure",
          outcome: "failed",
          target: {
            kind: "authn-attempt",
            ceremony: input.ceremony,
            ...(input.connKind !== undefined ? { connKind: input.connKind } : {}),
            ...(input.connId !== undefined ? { connId: input.connId } : {}),
            attempts: pending + 1,
          },
        });
      } catch {
        // BEST-EFFORT, ALWAYS: a failed audit write must never turn a rejected sign-in into a 500 on an
        // unauthenticated route. But the DROP is itself evidence -- this row is the only tamper-evident record
        // that a sweep happened, and it is deliberately excluded from the pack's audit excerpt, so a swallowed
        // failure leaves the pack showing a quiet weekend. Count the drop, and hand the attempts this row was
        // carrying back to the tally so the NEXT row that lands still accounts for them.
        this.authnFailureAuditPending.set(key, pending + 1);
        await recordCeremonyFault(this.state.storage, "authn-failure-audit-append-failed");
      }
    }

    // The per-isolate authn-failure audit window: row-identity -> the ms at which a row for it was last
    // written. Instance-scoped (never shared across DO instances) and never persisted, the same shape as
    // authSignalThrottle in scheduler-do-idp.ts.
    authnFailureAuditWindow = new Map<string, number>();

    // The per-isolate DEFERRED ATTEMPT TALLY: how many failures of each row-identity have happened inside the
    // open window and are not yet on the chain. It can hold nothing but a count.
    authnFailureAuditPending = new Map<string, number>();

    // listAuditEntries reads the WHOLE chain in ascending-seq order, via listAllByPrefix. A
    // single storage.list({prefix: AUDIT_PREFIX}) returns at most one platform list page (~DO_LIST_PAGE,
    // 1000 keys), so a bare list call would silently TRUNCATE once the retained chain outgrows a page: readAudit
    // (GET /audit) would show a stale head, verifyAudit (GET /audit/verify) would under-check the chain, and
    // exportAudit's with-limit branch -- the support pack's per-action keystone probe (action=X&limit=1)
    // among others -- could miss a match past the first page. This is the same truncation shape the
    // whole-log (no-limit) export path guards against, reached here through this shared method instead.
    // listAllByPrefix pages a startAfter cursor past DO_LIST_PAGE until the prefix is exhausted
    // (bounded by DO_LIST_MAX_PAGES, itself counted via recordSchedHealth on exhaustion), so every caller
    // of this method reads the COMPLETE retained chain (bounded by AUDIT_CAP, never by the platform's
    // page size), never truncated at ~DO_LIST_PAGE.
    async listAuditEntries(): Promise<AuditEvent[]> {
      const map = await this.listAllByPrefix<AuditEvent>(AUDIT_PREFIX);
      // Defend the ordering invariant explicitly: the paged list is ascending by key (the padded
      // seq), but sort by the numeric seq too so a future storage change cannot silently reorder the
      // chain the verify depends on.
      return [...map.values()].sort((a, b) => a.seq - b.seq);
    }

    // readAudit serves GET /audit: a newest-first page (filtered) plus the chain head, so the console
    // renders the page and a verifier can pin the head. The filter and the pager live in audit.ts so
    // the DO route and the validator shape the page identically.
    async readAudit(params: URLSearchParams): Promise<{ events: AuditEvent[]; headSeq: number; headHash: string }> {
      const all = await this.listAuditEntries();
      const filter = parseAuditFilter(params);
      const events = pageEvents(all, filter);
      const head = headOf(all);
      return { events, headSeq: head.headSeq, headHash: head.headHash };
    }

    // verifyAudit serves GET /audit/verify: recompute the chain and report intact or the first brokenAt
    // seq. A break is a RESULT (still 200), the on-screen proof of tamper-evidence. When a retention
    // rollover has occurred the chain legitimately begins above seq 1, so verify is told NOT to expect
    // genesis (it takes the baseline from the first retained entry instead of failing because genesis
    // was pruned), and it reports the earliest retained seq + the rolled-over count so the console can
    // show "chain begins at entry N, M earlier entries rolled over" rather than a spurious break.
    //
    // IT ALSO CARRIES THE HEAD-ANCHOR VERDICT BESIDE THE RECOMPUTE. The recompute walks the RETAINED
    // entries, so a DELETED TAIL leaves the survivors perfectly linked and `intact` reads TRUE: this is the
    // one break class the engine can detect while its own headline verdict says the chain is fine. A verdict
    // of intact:true standing alone next to a truncation is a claim this call has just disproved, so
    // headTruncated rides WITH it, on the same object, and every reader of this route (the pack's audit
    // section, the console's chain banner) is qualified by it.
    async verifyAudit(): Promise<{ intact: boolean; checkedThrough: number; earliestSeq: number; rolledOver: boolean; rolledOverCount: number; brokenAt?: number; headTruncated?: boolean; headTruncatedAt?: number; headAnchorUnreadable?: true; auditCountRecovered?: true; auditCount: number; auditNearCap: boolean; verify: AuditVerifyMeta }> {
      const startedAt = Date.now();
      const all = await this.listAuditEntries();
      const rollover = (await this.state.storage.get<AuditRolloverState>(AUDIT_ROLLOVER_KEY)) ?? null;
      // HARDENING. The rollover record could be lost (a storage blip,
      // an out-of-band edit) while the pruned entries stay gone: reading it alone would then make verify EXPECT
      // genesis, find the chain begins above seq 1, and report a SPURIOUS break. So we ALSO derive the rollover
      // from the ACTUAL earliest retained seq: a chain that legitimately begins above seq 1 IS a rollover,
      // record or not. expectGenesis follows the real first retained seq, never the (loseable) record.
      const firstSeq = all.length > 0 ? all[0]!.seq : 0;
      const derivedRolledOver = firstSeq > 1;
      // recordedRolledOverCount is the RECORD's count only when the record actually carries one: a positive,
      // finite integer. This is the same test auditCountAndNearCap applies to the very same field of the very
      // same record, and the two must agree: reading the raw field through a `??` would not fall through on 0,
      // so a rollover whose record has been zeroed would answer rolledOver:true with rolledOverCount:0 -- a
      // rollover of nothing -- while the SAME storage state with the record ABSENT correctly answers the true
      // count from the derived fallback below. Without sanitising, the console would render the calm
      // "Chain intact" surface for the zero, identical on a log beginning at entry 1 and on one whose
      // beginning has been destroyed.
      const recordedRolledOverCount = rollover !== null && Number.isFinite(rollover.rolledOverCount) && rollover.rolledOverCount > 0 ? Math.floor(rollover.rolledOverCount) : undefined;
      // ONE definition of "the record says a rollover happened", used by the flag, the anomaly and the count
      // alike, so three readings of one field cannot become three different tests.
      const rolledOver = recordedRolledOverCount !== undefined || derivedRolledOver;
      // The chain demonstrably rolled over (it begins above seq 1) but the rollover RECORD is missing or
      // empty. The derived fallback below keeps verify from reporting a spurious TAMPER, and it also hides the
      // fact that a storage record was LOST. Count the loss: a verify that only reads intact because a
      // fallback covered for a missing record is a materially different statement from a clean chain.
      // It books the loss for a record that is missing OR carries no usable count, so this line and the count
      // below share ONE definition of "the record cannot answer" -- otherwise a zeroed record could be treated
      // as lost here while the count below still preferred that record's zero, recording the loss and then
      // reporting the lost value anyway.
      if (derivedRolledOver && recordedRolledOverCount === undefined) await recordStorageAnomaly(this.state.storage, "rollover-record-lost");
      // The recompute below hashes the WHOLE retained chain and is CPU-heavy near
      // the cap. If the isolate's CPU budget kills it mid-recompute, the put at the end never runs and the
      // PRIOR meta survives, so the pack reads a stale verify as if it were current. Stamp complete:false
      // BEFORE the heavy work, so a killed verify leaves its own tombstone; the complete:true put below
      // overwrites it on every verify that finishes. A prior meta still reading complete:false when we start
      // is proof the last attempt was killed, which is exactly the "verify never finishes on this account"
      // ticket, and it is counted here.
      const priorMeta = (await this.state.storage.get<AuditVerifyMeta>(AUDIT_VERIFY_META_KEY)) ?? null;
      if (priorMeta !== null && priorMeta.complete === false) await recordStorageAnomaly(this.state.storage, "verify-incomplete");
      await this.state.storage.put(AUDIT_VERIFY_META_KEY, { at: nowMillisISO(), entriesChecked: all.length, durationMs: 0, complete: false } satisfies AuditVerifyMeta);
      const verdict = await verifyChain(all, { expectGenesis: firstSeq === 1 });
      // THE TAIL DELETION THE RECOMPUTE CANNOT SEE. verifyChain walks the RETAINED entries and checks
      // that each links to the one before it, so removing the NEWEST entries -- the ones that record what the
      // attacker just did -- leaves the survivors perfectly linked and the chain reads INTACT. The witness is
      // already in storage and needs no key: AUDIT_HEAD_KEY, which appendAudit writes on every commit. Retention
      // rolls the OLDEST entries off (rollOverAudit) and never lowers headSeq, so a retained head BELOW the
      // anchor -- or at it under a different hash -- is a removed or rewritten tail. Read WITHOUT loadAuditHead,
      // which would reconstruct the anchor from the surviving entries and destroy the evidence.
      const anchorHead = (await this.state.storage.get<AuditHead>(AUDIT_HEAD_KEY)) ?? null;
      const retainedHead = all.length > 0 ? all[all.length - 1]! : null;
      // A PRESENT ANCHOR WHOSE headSeq IS NOT A POSITIVE INTEGER IS A CORRUPT ANCHOR, NOT AN ABSENT ONE, and
      // the `> 0` guard below could not tell the two apart. An absent anchor genuinely says nothing (a chain
      // predating the anchor, or a DO whose storage was wiped whole), and treating it as intact is right. A
      // zeroed or wrong-typed one is EVIDENCE THAT HAS BEEN DESTROYED, and treating it as absent would take the
      // witness with it: the whole truncation check would be skipped and the verify would answer `intact: true`
      // with no qualification, byte-identical to the answer over an anchor that is perfectly sound. That is the
      // one answer a damaged record must never produce, so it is reported rather than skipped past.
      const anchorUnreadable = anchorHead !== null && !(Number.isInteger(anchorHead.headSeq) && anchorHead.headSeq > 0 && typeof anchorHead.headHash === "string" && anchorHead.headHash.length > 0);
      if (anchorUnreadable) await recordStorageAnomaly(this.state.storage, "audit-head-anchor-unreadable");
      const truncated =
        anchorHead !== null &&
        !anchorUnreadable &&
        anchorHead.headSeq > 0 &&
        (retainedHead === null || retainedHead.seq < anchorHead.headSeq || (retainedHead.seq === anchorHead.headSeq && retainedHead.hash !== anchorHead.headHash));
      const anchorVerdict = truncated && anchorHead !== null ? { intact: false, brokenAt: anchorHead.headSeq, causeClass: "head-truncated" } : { intact: true };
      // LATCH the verdict. The pack RECOMPUTES this at bundle-build time, so a break that later rolls
      // off the retention window reads INTACT for ever afterwards and the pack carries no evidence it was ever
      // seen -- "audit verify showed a break last Tuesday but shows intact now" is unanswerable in both
      // directions. The latch survives the rollover, records the CLOSED cause class (which separates an edited
      // snapshot from a forged digest from a deleted entry: three different investigations), and stamps
      // healedAt rather than forgetting. Best-effort; it never alters the verdict returned here.
      await recordChainVerdict(this.state.storage, "audit", verdict, undefined, undefined, anchorVerdict);
      // VERIFY-COST metadata. The recompute hashes the whole retained chain,
      // which is CPU-heavy near the cap; record how long it took + how many entries, so the pack can see a
      // costly verify. Persisted so a LATER CPU-killed verify (which never reaches this put) leaves a stale
      // meta that, next to the near-cap flag, tells the story. complete is true because this call finished.
      const meta: AuditVerifyMeta = { at: nowMillisISO(), entriesChecked: all.length, durationMs: Date.now() - startedAt, complete: true };
      await this.state.storage.put(AUDIT_VERIFY_META_KEY, meta);
      const { auditCount, auditNearCap, auditCountRecovered } = await this.auditCountAndNearCap();
      return {
        intact: verdict.intact,
        checkedThrough: verdict.checkedThrough,
        earliestSeq: verdict.earliestSeq,
        rolledOver,
        // Prefer the recorded cumulative count; fall back to the derived count (seqs 1..firstSeq-1 pruned).
        // `??` falls through on null/undefined and NOT on 0, so recordedRolledOverCount must be undefined
        // (never 0) for exactly the records that cannot answer, so the fallback applies to all of them.
        rolledOverCount: recordedRolledOverCount ?? (derivedRolledOver ? Math.max(0, firstSeq - 1) : 0),
        ...(verdict.brokenAt !== undefined ? { brokenAt: verdict.brokenAt } : {}),
        // The anchor's verdict, carried with the recompute's. `intact` above can only speak for the
        // entries that are STILL THERE; this says whether the ones that are gone were supposed to be. A boolean
        // and the anchored head seq, both engine-minted: no entry content, no hash, no actor.
        ...(truncated && anchorHead !== null ? { headTruncated: true, headTruncatedAt: anchorHead.headSeq } : {}),
        // THE TWO WAYS THIS VERDICT CAN BE LESS THAN IT LOOKS, both carried ON the verdict rather than left in
        // a counter, because a qualification an operator has to go and find is a qualification they will not
        // find. `headAnchorUnreadable` says the tail-deletion witness could not run at all, so `intact` speaks
        // only for the entries still present and cannot speak for any that were removed from the end.
        // `auditCountRecovered` says the head pointer's own count was not believable and the number beside it
        // was counted from the chain instead.
        ...(anchorUnreadable ? { headAnchorUnreadable: true } : {}),
        ...(auditCountRecovered === true ? { auditCountRecovered: true } : {}),
        auditCount,
        auditNearCap,
        verify: meta,
      };
    }

    // exportAudit serves GET /audit/export: the full (filtered or whole) log as a downloadable
    // document, JSON by default or CSV with ?format=csv, WITH the chain head hash so an external
    // verifier can confirm completeness and detect truncation-after-export. Generated in-account; the
    // customer's own data, no custody concern. The Content-Disposition makes it a download.
    async exportAudit(params: URLSearchParams): Promise<Response> {
      const { before: _before, limit: _limit, ...filter } = parseAuditFilter(params);
      void _before;
      const format: ExportFormat = params.get("format") === "csv" ? "csv" : "json";

      // FEED FAST PATH. The audit-feed collector pull is exactly afterSeq + limit, ascending
      // JSON, with no richer filter. The `audit:` keys are zero-padded seq, so the next forward page is a
      // BOUNDED storage.list from the cursor key -- genuinely O(limit), not the O(retained-log) full-chain
      // load the slow path does. The chain head and the earliest retained seq are one bounded read each. Any
      // richer query (an actor/action/date filter, a CSV download, the whole-log export) falls through to the
      // full scan below, which is inherently the whole matching set. earliestSeq is surfaced so a collector can
      // detect a rollover GAP (its checkpoint below the oldest retained entry -> pruned events it will never
      // receive).
      const isForwardFeedPage =
        format === "json" &&
        _limit !== undefined &&
        filter.afterSeq !== undefined &&
        filter.actor === undefined &&
        filter.action === undefined &&
        filter.downpipe === undefined &&
        filter.outcome === undefined &&
        filter.from === undefined &&
        filter.to === undefined;
      if (isForwardFeedPage) {
        const afterSeq = filter.afterSeq!;
        const pageMap = await this.state.storage.list<AuditEvent>({ prefix: AUDIT_PREFIX, start: auditKey(afterSeq + 1), limit: _limit });
        // list returns ascending key order (= ascending seq under fixed-width padding); sort by numeric seq
        // too so a future storage change cannot silently reorder the forward page.
        const events = [...pageMap.values()].sort((a, b) => a.seq - b.seq);
        const headMap = await this.state.storage.list<AuditEvent>({ prefix: AUDIT_PREFIX, reverse: true, limit: 1 });
        const headEntry = [...headMap.values()][0];
        const head = headEntry ? { headSeq: headEntry.seq, headHash: headEntry.hash } : { headSeq: -1, headHash: GENESIS_PREV_HASH };
        const earliestMap = await this.state.storage.list<AuditEvent>({ prefix: AUDIT_PREFIX, limit: 1 });
        const earliestSeq = [...earliestMap.values()][0]?.seq ?? 0;
        // THE COLLECTOR IS BEING SERVED A GAP. Its cursor sits below the oldest retained entry, so the
        // events between afterSeq and earliestSeq were rolled over and this collector will NEVER receive them
        // -- "our SIEM has a hole in the audit feed". Without this record that fact would exist ONLY in this
        // HTTP response to the customer's own collector, and the pack could not confirm the hole. Count
        // it with the engine-minted sequence boundary (a monotonic integer, not customer data); no event
        // content rides. Best-effort: the page served is byte-identical whether or not the ledger write lands.
        if (afterSeq + 1 < earliestSeq) await recordAuditGapPage(this.state.storage, earliestSeq);
        const body = JSON.stringify({ events, headSeq: head.headSeq, headHash: head.headHash, earliestSeq, exportedAt: nowMillisISO() });
        return new Response(body, {
          headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="downpipe-audit.json"' },
        });
      }

      // SLOW PATH: the whole matching set. It serves TWO shapes, told apart by whether the caller supplied
      // a limit:
      //
      //  - NO limit -> the COMPLIANCE EXPORT (the console's Export button, or an offboarding/incident pull):
      //    the whole (optionally filtered) log as a downloadable evidence document, which MUST be COMPLETE.
      //    It reads the ENTIRE retained chain via listAllByPrefix, which loops a startAfter cursor past the
      //    platform's one-page (~DO_LIST_PAGE) list limit so every entry up to AUDIT_CAP (10000) is
      //    enumerated, then shapes the document with filterEventsAscending, which applies the filter with NO
      //    page cap -- shaping it instead with pageEvents, whose Math.min(limit, AUDIT_PAGE_MAX=500) would
      //    SILENTLY drop every event older than the newest 500 while the download still presented itself as
      //    the full log. Completeness is the invariant; the chain head hash still travels so an external
      //    verifier can re-verify the exported chain and detect any truncation-after-export, and the
      //    retained-log bound (AUDIT_CAP) is itself surfaced, never silent (earliestSeq here + the verify
      //    route's rolledOverCount signal a retention rollover, and the export-before-rollover path keeps the
      //    pruned history), so the export drops NOTHING without a signal.
      //
      //  - WITH a limit -> a BOUNDED filtered query that did not qualify for the forward-feed fast path above
      //    (the support pack's per-action keystone probe action=X&limit=1, or a filtered forward page
      //    afterSeq=X&action=Y&limit=N). Shaped as newest-first pageEvents, reversed to ascending, then the
      //    afterSeq forward slice, so no internal caller's RESPONSE SHAPE changes; the caller's own limit +
      //    cursor still bound it. listAuditEntries() reads via listAllByPrefix too, so the chain pageEvents
      //    walks is COMPLETE rather than whatever a single list() call happens to return -- a keystone probe
      //    cannot miss the true newest match of an action past the first platform list page. This keeps the
      //    interactive/probe cap unaffected (still AUDIT_PAGE_MAX newest matches) while the READ underneath it
      //    never truncates.
      let matching: AuditEvent[];
      let head: { headSeq: number; headHash: string };
      let earliestSeq: number;
      if (_limit === undefined) {
        const map = await this.listAllByPrefix<AuditEvent>(AUDIT_PREFIX);
        // The `audit:` keys are zero-padded seq (ascending), but sort by numeric seq too so a future storage
        // change cannot silently reorder the exported chain the head hash commits to.
        const all = [...map.values()].sort((a, b) => a.seq - b.seq);
        matching = filterEventsAscending(all, filter);
        head = headOf(all);
        earliestSeq = earliestSeqOf(all);
      } else {
        const all = await this.listAuditEntries();
        const matchingAll = pageEvents(all, { ...filter, limit: Number.MAX_SAFE_INTEGER }).reverse();
        matching = filter.afterSeq !== undefined ? matchingAll.slice(0, _limit) : matchingAll;
        head = headOf(all);
        earliestSeq = earliestSeqOf(all);
      }
      if (format === "csv") {
        const body = toCSV(matching, head);
        return new Response(body, {
          headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": 'attachment; filename="downpipe-audit.csv"' },
        });
      }
      const body = JSON.stringify({ events: matching, headSeq: head.headSeq, headHash: head.headHash, earliestSeq, exportedAt: nowMillisISO() });
      return new Response(body, {
        headers: { "content-type": "application/json", "content-disposition": 'attachment; filename="downpipe-audit.json"' },
      });
    }

    // observeStatus serves POST /audit-status: the router calls it during GET /admin/status with the
    // presence booleans + engineVersion it already computed. The DO diffs them against the last-seen
    // snapshot and appends an engine-observed event per change (a tracked secret presence flipping
    // true, or the engine version changing), then stores the new snapshot. The FIRST observation only
    // establishes the baseline (records nothing), so onboarding from scratch does not emit a burst of
    // "appeared" events for the wiring the operator is mid-way through. These events carry
    // actorMethod "engine"/actorEmail null, closing part of the gap by recording the RESULT
    // of an out-of-band step without the console ever submitting a value.
    async observeStatus(obs: StatusObservation): Promise<{ appended: number; auditCount: number; auditNearCap: boolean; auditRolledOverCount: number }> {
      const prior = (await this.state.storage.get<StatusSnapshot>(STATUS_SNAPSHOT_KEY)) ?? null;
      const { drafts, next } = diffStatus(prior, obs);
      for (const d of drafts) await this.appendAudit(d);
      await this.state.storage.put(STATUS_SNAPSHOT_KEY, next);
      // BASELINE MARKER. The
      // FIRST observation (a fresh DO) -- or one after a snapshot RESET (a wiped / first-poll control plane,
      // where `prior` is null again) -- establishes the baseline, and diffStatus deliberately records NO audit
      // "change" burst (onboarding noise). But a reset is itself worth attributing: a same-version redeploy
      // that reset the DO and silently dropped live source bindings is otherwise indistinguishable from steady
      // state, and the deploy-id-change arm cannot fire on the very first poll (it needs a prior AND a current
      // id). So stamp a durable deploy-identity marker ONCE at baseline (the observed version + Cloudflare
      // deploy id + time) that the support pack surfaces -- it lands once but IS present, coordinating with the
      // vendor-side deploy-ledger (beacon) keystone. This appends NO audit event (the chain length is
      // unchanged), so it never perturbs the tamper chain; it is a separate DO record, like the other observe
      // signals. Best-effort within the observe path: it never throws (a status read must always succeed).
      if (prior === null) {
        try {
          await this.state.storage.put(STATUS_BASELINE_KEY, { version: obs.engineVersion, ...(obs.cfVersionId !== undefined ? { cfVersionId: obs.cfVersionId } : {}), at: Date.now() } satisfies StatusBaselineState);
        } catch {
          /* observability only: never let the baseline marker destabilise the status observation */
        }
      }
      // Surface the live audit count + near-cap flag alongside the diff result. GET /admin/status calls
      // this route, so this is the redaction-safe boundary at which the cap warning becomes available to
      // the console (count is an integer, auditNearCap a boolean; no entry, no value). Computed AFTER the
      // appends above so the count reflects any engine-observed events this poll just recorded.
      // THIS IS THE ONLY PLACE THE ROUTER CAN LEARN THE AUDIT CAPACITY. GET /admin/status posts this
      // observation and reads nothing back, so without this return buildStatus has no auditCount to give the
      // console, auditNearCap is never present in the status body, and the console's capacity card reads
      // "this engine build does not report audit-log capacity" regardless of build. The export-before-rollover
      // warning would never fire anywhere.
      const { auditCount, auditNearCap, auditRolledOverCount } = await this.auditCountAndNearCap();
      return { appended: drafts.length, auditCount, auditNearCap, auditRolledOverCount };
    }

    // getStatusBaseline returns the deploy-identity marker recorded at the last status-snapshot baseline,
    // or null when no observation has ever run. Read by the support pack so a snapshot RESET (a wiped/first-poll control plane)
    // is attributable -- comparing `at` across two packs reveals a reset, and cfVersionId names the deploy.
    // Redaction-safe (a version string + a Cloudflare deploy id + a timestamp).
    async getStatusBaseline(): Promise<StatusBaselineState | null> {
      return ((await this.state.storage.get(STATUS_BASELINE_KEY)) as StatusBaselineState | undefined) ?? null;
    }
  };
}
