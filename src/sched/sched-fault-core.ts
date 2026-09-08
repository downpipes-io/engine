// The scheduler DO fault ledger's SHARED CORE: the substrate every ledger in this family writes through, and
// the six founding ledgers whose vocabularies and recorders were already written as one block.
//
// The substrate is the bounded {count,lastAt} aggregate and its cap, the one storage key per ledger, the
// minimal LedgerStorage surface, the two write primitives every recorder funnels through (bumpCount and
// writeLedger), the dropped-write bookkeeping that makes a LOST diagnostic write countable, and the two clamps
// (safeLabel, stripLedgerControls) every operator-visible string passes through.
//
// It is a LEAF of its own family: it imports nothing from ./sched-fault-ledger.ts and nothing from the
// per-subject ledgers beside it, so all of them can depend on it without a cycle.
//
// SPLIT AXIS. Moved verbatim out of sched-fault-ledger.ts. What must never separate is a closed
// vocabulary and the recorder that GATES on it: a member added to one half and not the other is a silent
// redaction hole rather than a compile error. That pairing is per FAMILY, so the FAMILY is the unit that moves,
// and every family here arrived whole. The redaction rule these records are written under is stated once, in
// sched-fault-ledger.ts, and binds this file.
//
// What each ledger exists for:
//   ceremonyFaults  (G013/G014/G039) the DO-SIDE structural auth-ceremony failure classes. The Worker EDGE
//                   already counts the ceremony's coarse WIRE reason into the closed AUTH_SIGNAL_NAMES
//                   aggregate (admin/auth-signals.ts + passkeySignalName), but a whole family of causes is
//                   invisible from the edge because the DO never surfaces them as a distinct reason: a
//                   STORED COSE key that no longer decodes is reported to the user as their own
//                   `bad_request`; an internal fault is coerced to `bad_request` too; a login challenge
//                   EVICTED under a begin flood is indistinguishable from an expired one; and the recovery
//                   limiter cannot say WHICH bucket denied (per-email, per-IP, or the limiter itself failing
//                   closed). Those are the classes here. Where an EXISTING auth-signal name already says the
//                   thing (recovery-ratelimited, recovery-code-invalid, stepup-failed) the DO keeps calling
//                   recordAuthSignal: this ledger never duplicates that vocabulary, it completes it.
//   recentErrors    (G013) a bounded ring keyed by the OPAQUE errorId the DO already mints and the console
//                   already shows the customer ("sign-in failed (err:ab12cd)" / "internal error, errorId
//                   7f3a..."). Support holding only the pack had no store to dereference that id against, so
//                   every quoted id needed a Workers Logs export the vendor structurally cannot request. The
//                   ring stores the id, the ceremony STAGE and a coarse reason CLASS - never the exception
//                   message (which can embed an email, an rpId or a URL); that stays in Workers Logs.
//   contractFaults  (G221) the Worker<->DO contract faults that are SILENTLY COERCED today: a malformed
//                   internal body, an out-of-vocabulary enum, a route that matched nothing after a partial
//                   deploy, a run completion discarded as unowned. Each one leaves a pack record stale or
//                   falsified (a `[]` coercion CLEARS the detached-source marker; a rejected auth-signal name
//                   stops a counter incrementing) while the edge is told ok, so "the pack shows nothing during
//                   the outage" is itself the bug. Counted, never coerced silently.
//   droppedWrites   (G104/G221) the recorders' OWN fire-and-forget write failures. A diagnostic write that is
//                   dropped means the pack UNDER-COUNTS during the very outage it exists to explain, and the
//                   drop was invisible. Because the drop happens when storage.put ITSELF fails, the count
//                   cannot be persisted at fault time; it is held in memory against the DO instance and FOLDED
//                   into the durable aggregate on the next write that succeeds.
//   defaultDest     (G120) the reachability heartbeat for the ENV-DEFAULT destination. recordReplicationState
//                   requires a console destination id, so a single-destination tenant (the common case) got NO
//                   per-destination down indicator at all and triage was sent to the source side first.
//   freshnessFaults (G076) the downpipes whose staleness rule can NEVER ARM: a non-positive/non-finite
//                   cadence, or a newest run timestamp that does not parse. The console reads them Fresh
//                   forever ("the map said Fresh for weeks while my backups had stopped"), and nothing said so.

// TYPE-ONLY (erased at build; no runtime edge, no cycle): the EDGE half of the shared droppedWrites vocabulary,
// so a DO-side recorder can record its own loss under the kind it was catalogued as. See noteDroppedDiagWrite.
import type { DroppedWriteKind as EdgeDroppedWriteKind } from "../admin/diag-records.ts";

// ---- shared shapes -------------------------------------------------------------------------------

// The bounded {count,lastAt} aggregate shape, identical to the auth-signal / SSO-failure aggregates so the
// pack projection treats them the same way.
export type FaultCountAgg = Record<string, { count: number; lastAt: string }>;

// The per-name count cap: a flood re-bumps this ceiling but can never grow storage unboundedly.
export const FAULT_COUNT_CAP = 1_000_000;

// One storage key per ledger. All are `diag:`-prefixed so they can never collide with a dp:/hist:/repl:
// record and are trivially separable from the data plane.
export const CEREMONY_FAULTS_KEY = "diag:ceremonyfaults";
export const RECENT_ERRORS_KEY = "diag:recenterrors";
export const CONTRACT_FAULTS_KEY = "diag:contractfaults";
export const DROPPED_WRITES_KEY = "diag:droppedwrites";
export const DEFAULT_DEST_HEALTH_KEY = "diag:defaultdesthealth";
export const FRESHNESS_FAULTS_KEY = "diag:freshnessfaults";
export const VOCAB_DROPS_KEY = "diag:vocabdrops";
export const EXPIRY_OBSERVE_FAULTS_KEY = "diag:expiryobservefaults";
export const APPROVAL_FAULTS_KEY = "diag:approvalfaults";
export const STORAGE_ANOMALIES_KEY = "diag:storageanomalies";
export const RECOVERY_RESUME_KEY = "diag:recoveryresume";
export const ROSTER_DISCARDS_KEY = "diag:rosterdiscards";
export const CHAIN_BREAKS_KEY = "diag:chainbreaks";
export const TEST_OUTCOMES_KEY = "diag:testoutcomes";

// The minimal storage surface these recorders need (a structural subset of DurableObjectStorage, so a test
// can drive them with a Map-backed fake and with a fake that THROWS on put - the dropped-write path).
export interface LedgerStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  // OPTIONAL (G334): the posture projection needs to enumerate the `posture-accept:` override records. It is
  // optional so every existing Map-backed test fake (and every recorder above, none of which lists) keeps
  // working unchanged; readPostureDiag degrades to an empty override list when it is absent.
  list?<T>(options?: { prefix?: string }): Promise<Map<string, T>>;
}

// ---- ceremonyFaults (G013 / G014 / G039) ---------------------------------------------------------

// The CLOSED vocabulary of DO-side auth-ceremony structural faults. Deliberately DISJOINT from
// AUTH_SIGNAL_NAMES (admin/auth-signals.ts): every name here is a cause the Worker edge structurally cannot
// see, because the DO's coarse wire reason does not distinguish it (or the branch returns before any reason
// is minted at all). Counts only; the client-facing responses are untouched, so none of these is ever oracled
// back to a caller (the anti-enumeration property of the coarse ceremony response is preserved).
export const CEREMONY_FAULT_KINDS = [
  // --- passkey / step-up ceremony structure ---
  "passkey-stored-key-corrupt", // a STORED credential's COSE public key no longer decodes: the engine's own record is corrupt, but the user is told `bad_request` and blames their own browser. The single most misdiagnosed passkey ticket.
  "passkey-internal-fault", // a NON-PasskeyError exception inside a ceremony, coerced to the client-safe `bad_request`: an engine bug reads to the user (and to the edge's signal) as their own malformed request
  "passkey-challenge-evicted", // a live login/step-up challenge was EVICTED (not expired) by the bounded-store guard under a begin FLOOD: "users randomly cannot complete sign-in during busy periods". The edge sees only the generic challenge failure
  "passkey-register-forbidden", // a registration was refused because NO authorisation path proved it (no bootstrap, no valid invite, no matching session): the "the invite link fails for my colleague" ticket
  "passkey-invite-invalid", // a registration presented an invite token that is unknown, expired or already consumed (the peek returned nothing)
  "passkey-selfadd-off-roster", // a passkey session tried to SELF-ADD a new credential for an address a populated roster does not account for, and was refused. This is the shape a spent recovery code takes when it is being turned into standing access, and without this the ticket reads as an unexplained `forbidden` on a session that just signed in successfully
  "passkey-invite-off-roster", // a still-valid registration invite was redeemed for an address a populated roster no longer accounts for, and was refused. Distinct from passkey-invite-invalid: the token is genuine and unexpired, and the answer is about the roster rather than the link, so a support reply of "ask them to resend the link" would be wrong. The usual cause is an offboard: deleteRole removes the role rows but the invite is keyed by token, so it outlives the grant it was minted for
  "passkey-rpid-absent", // the ROUTER supplied no usable rp.id / origin for a ceremony: a server-side deploy-config fault (a host change), not a user fault
  "stepup-no-passkey", // a step-up was demanded of a caller with NO enrolled passkey (an Access/IdP-only member hitting a step-up-gated action): they can never satisfy it, and the console just keeps refusing
  "stepup-unknown-credential", // a step-up assertion named a credential that is not the caller's own (a wiped store, or a foreign assertion)
  "authn-failure-audit-append-failed", // the failed-login authn-failure audit APPEND itself failed: the tamper-evident record of a brute-force sweep was dropped
  // --- recovery-code break-glass (G039): which limiter tripped, and the silent generation failures ---
  "recovery-denied-email-bucket", // the recovery attempt was denied by the PER-EMAIL bucket (this one account is being sprayed)
  "recovery-denied-ip-bucket", // the recovery attempt was denied by the PER-IP bucket (a whole office behind one NAT can lock itself out this way)
  "recovery-limiter-unavailable", // the recovery limiter's own STORE failed and the attempt was denied FAIL-CLOSED: "every recovery code we try is rejected" while nothing is wrong with the codes
  "recovery-regenerate-refused", // a signed-in caller's regenerate was refused before it began (an unusable email): the console nags them to regenerate forever and they never can
  "recovery-regenerate-off-roster", // a PASSKEY-method caller asked to mint a fresh recovery set for an address a populated roster does not account for, and was refused. This is the THIRD conversion of a spent one-time secret into standing access, after the self-add and invite arms, and the shortest: the session a spent code mints satisfies the route's whole gate, so without this a removed person banks an unbounded supply of never-expiring codes on the request after the one that refused them a passkey. Distinct from recovery-regenerate-refused, which is a malformed address rather than a roster answer, because the remedies differ entirely
  "recovery-codes-generation-failed", // recovery-code minting THREW on enrolment: the user enrolled with an EMPTY set and does not know it ("I never got recovery codes")
] as const;
export type CeremonyFaultKind = (typeof CEREMONY_FAULT_KINDS)[number];
const CEREMONY_FAULT_SET: ReadonlySet<string> = new Set(CEREMONY_FAULT_KINDS);

// ---- recentErrors (G013) -------------------------------------------------------------------------

// The ceremony/route STAGE an errorId was minted at (closed).
export const ERROR_STAGES = ["register/begin", "register/finish", "login/begin", "login/finish", "stepup/finish", "do-route"] as const;
export type ErrorStage = (typeof ERROR_STAGES)[number];
const ERROR_STAGE_SET: ReadonlySet<string> = new Set(ERROR_STAGES);

// The coarse reason CLASS behind an errorId (closed). This is what the raw exception message is REDUCED to;
// the message itself is never stored.
export const ERROR_REASON_CLASSES = ["bad-request-shape", "challenge", "verify-failed", "stored-key-corrupt", "internal", "storage"] as const;
export type ErrorReasonClass = (typeof ERROR_REASON_CLASSES)[number];
const ERROR_REASON_CLASS_SET: ReadonlySet<string> = new Set(ERROR_REASON_CLASSES);

export interface RecentErrorEntry {
  errorId: string; // the OPAQUE server-minted id the customer quotes; never derived from customer input
  stage: ErrorStage;
  reasonClass: ErrorReasonClass;
  count: number; // a RECURRING id (the same digest-derived id for the same fault) bumps rather than re-appends
  at: string;
}

// RECENT_ERRORS_CAP bounds the ring: enough to dereference the ids a customer is likely to quote from a
// single incident without unbounded growth.
export const RECENT_ERRORS_CAP = 64;

// ERROR_ID_PATTERN is the redaction boundary on the one id we store: the engine mints these itself (a hex
// digest from admin/passkey.ts errId, or a crypto.randomUUID on the DO route), so a value that is not
// hex/dash-shaped did not come from the engine and is DROPPED rather than stored (defence in depth: no
// caller-authored string can ever reach this ring).
const ERROR_ID_PATTERN = /^[0-9a-fA-F-]{1,64}$/;

// ---- contractFaults (G221) -----------------------------------------------------------------------

// WHICH internal contract was breached (closed).
export const CONTRACT_ROUTE_CLASSES = [
  "auth-signal", // POST /auth-signal carried a name outside the closed vocabulary (an edge/DO version skew: the counter silently stops incrementing)
  "notify-health", // POST /notify/health-bump carried an unknown field (the notify drop-counter silently stops)
  "drift-reconcile", // POST /source-drift/reconcile body was malformed: the `?? []` coercion CLEARS the detached-source marker, so a real detach reads as healed
  "volume-reconcile", // POST /volume-regression/reconcile body was malformed: same `[]` coercion clears the volume-regression marker
  "run-completion-unowned", // a /complete named no live in-flight row (a late/duplicate completion): the real completion is DISCARDED and the run keeps reading abandoned
  "unmatched-route", // a request matched NO route key at all (a console screen 404ing on every load after a partial deploy)
] as const;
export type ContractRouteClass = (typeof CONTRACT_ROUTE_CLASSES)[number];
const CONTRACT_ROUTE_SET: ReadonlySet<string> = new Set(CONTRACT_ROUTE_CLASSES);

// HOW it was breached (closed).
export const CONTRACT_FAULT_KINDS = ["unknown-route", "bad-body", "enum-drift", "coerced-default", "unowned-drop"] as const;
export type ContractFaultKind = (typeof CONTRACT_FAULT_KINDS)[number];
const CONTRACT_FAULT_SET: ReadonlySet<string> = new Set(CONTRACT_FAULT_KINDS);

// contractFaultKey is the aggregate's composite key. Both halves are closed-set members (validated at the
// record boundary), so no free text can ever become a storage key.
export function contractFaultKey(route: ContractRouteClass, kind: ContractFaultKind): string {
  return `${route}|${kind}`;
}

// ---- droppedWrites (G104 / G221) -----------------------------------------------------------------

// WHICH recorder lost a write (closed). The pack reads this first: a non-zero droppedWrites means every
// OTHER counter in the pack is a LOWER BOUND for that window, which is exactly the caveat a diagnoser needs.
//
// SHARED KEY (deliberate): DROPPED_WRITES_KEY is the SAME `diag:droppedwrites` record admin/diag-records.ts
// writes for the Worker-edge recorders (auth-signal, support-pull-trail, licence-refusal, ...). ONE aggregate
// answering "how much of this pack is missing?" is the right shape, and the two are safe to co-write: the
// value shape is identical (closed kind -> {count,lastAt}); the DO is single-threaded, so the two
// read-modify-writes cannot interleave; each writer filters only its OWN incoming kinds and PRESERVES every
// other key it finds; and the two vocabularies are disjoint. The projection must carry the UNION (the read
// below returns the whole record, so the sched kinds ride even if the edge projector allowlists its own).
export const DROPPED_WRITE_KINDS = [
  "ceremony-fault",
  "recent-error",
  "contract-fault",
  "default-dest-health",
  "freshness-fault",
  "vocab-drop", // G092
  "expiry-observe-fault", // G093
  "approval-fault", // G094
  "storage-anomaly", // G105
  "recovery-resume", // G103
  "roster-discard", // G105
  "dest-resolve-fallback", // G090
  "canary-loss", // G091
  "drill-drop", // G059 + G097
  "notify-drop", // G060
  "governance-fault", // G034
  "governance-refusal", // G182: the closed reason a governance surface refused (the discriminator guard-refused erases)
  "refusal-ring", // G037
  "admin-refusal", // G146 + G126
  "client-diag", // G172-G181: the console's own ring never reached the pack it was about to ride in
  "config-rejection", // G139 + G141
  "authz-refusal", // G187 + G249
  "alerting-health", // G188
  "config-coercion", // G297
  "audit-egress", // G323
  "cap-truncation", // G325
  "posture-input-fault", // G334
  "chain-break", // G313: the chain-break LATCH write was lost, so a tamper verdict that later rolls over leaves no trace at all
  "test-outcome", // G246: a wiring-check outcome was lost, so the pack again cannot say whether the operator's Test button passed
] as const;
export type DroppedWriteKind = (typeof DROPPED_WRITE_KINDS)[number];

// ---- defaultDest reachability (G120) -------------------------------------------------------------

// The CLOSED per-destination failure vocabulary. Today every down destination reads the literal "unreachable",
// so support cannot tell an EXPIRED CREDENTIAL from a WORM refusal from a timeout, and sends the customer to
// the wrong system. These classes are SELECTED from the driver's coarse run-error class; the string is discarded.
export const REPLICATION_REASONS = ["auth", "worm-refused", "throttled", "timeout", "network", "tls", "unreachable", "other"] as const;
export type ReplicationReason = (typeof REPLICATION_REASONS)[number];

export interface DefaultDestHealth {
  ok: boolean;
  reason: ReplicationReason | null; // null on a healthy heartbeat
  at: string;
  downSince: string | null; // set when ok flips true->false; cleared on recovery, so "down for a week" is a fact, not an inference
}

// classifyReplicationReason REDUCES the driver's coarse run-error class to ONE closed reason member. It READS
// the string ONLY to SELECT an enum member and RETURNS that enum type - the string is never stored, never
// returned and never logged from here (the classifyCoarseError / isWormRefusal idiom). The inputs it sees are
// themselves already the seal's closed coarse vocabulary (slice.ts coarseRunError), which for a destination
// rejection carries the store's sanitised error CODE; matching on that code is what lets the pack finally say
// "your credential expired" rather than "unreachable".
export function classifyReplicationReason(coarse: unknown): ReplicationReason {
  if (typeof coarse !== "string" || coarse.length === 0) return "unreachable";
  const m = coarse;
  // Auth first: an expired/rotated/denied credential is the single most common destination outage, and the
  // operator fix (re-enter the key) is completely different from every other class.
  if (/AccessDenied|InvalidAccessKey|SignatureDoesNotMatch|ExpiredToken|TokenRefreshRequired|Unauthorized|Forbidden|credential/i.test(m)) return "auth";
  // A WORM/Object-Lock refusal NEVER clears by retrying: it is a policy decision at the destination.
  if (/ObjectLock|WORM|Retention|LegalHold|Compliance|InvalidRetention/i.test(m)) return "worm-refused";
  if (/SlowDown|Throttl|TooManyRequests|RequestLimitExceeded|429/i.test(m)) return "throttled";
  if (/timeout|timed out|deadline|ETIMEDOUT/i.test(m)) return "timeout";
  // TLS before network: a certificate failure is a misconfiguration, not a transient blip.
  if (/\bTLS\b|\bSSL\b|certificate|handshake/i.test(m)) return "tls";
  if (/network|fetch failed|ECONNRESET|ECONNREFUSED|ENOTFOUND|DNS|socket/i.test(m)) return "network";
  // The historical generic: the destination could not be written to and the driver said no more than that.
  if (/unreachable|destination access error/i.test(m)) return "unreachable";
  return "other";
}

// ---- freshnessFaults (G076) ----------------------------------------------------------------------

// WHY the staleness rule can never arm for a downpipe (closed).
export const FRESHNESS_FAULT_CAUSES = ["cadence-malformed", "timestamp-malformed"] as const;
export type FreshnessFaultCause = (typeof FRESHNESS_FAULT_CAUSES)[number];

export interface FreshnessFault {
  cause: FreshnessFaultCause;
  at: string;
}
// Keyed by the customer's OWN downpipe label (the same redaction class as sealFaults.downpipeId), capped so a
// pathological fleet cannot grow the record without bound.
export type FreshnessFaults = Record<string, FreshnessFault>;
export const FRESHNESS_FAULTS_CAP = 50;

// LABEL_MAX mirrors scheduler-helpers.safeDownpipeId: the clamp on the one customer-authored string any of
// these records carries.
const LABEL_MAX = 128;
export function safeLabel(id: unknown): string | null {
  return typeof id === "string" && id.length > 0 ? id.slice(0, LABEL_MAX) : null;
}

// freshnessFaultCause is the PURE predicate (unit-testable with no DO): a cadence that is not a finite
// positive number, or a newest-run timestamp that does not parse, DISARMS the shared classifyFreshness rule
// on both the map and the overview - such a downpipe can never read stale, so a fleet that has silently
// stopped keeps reading Fresh. Returns null when staleness is computable (the overwhelmingly common case).
export function freshnessFaultCause(cadenceSeconds: unknown, newestStartedAt: unknown): FreshnessFaultCause | null {
  if (typeof cadenceSeconds !== "number" || !Number.isFinite(cadenceSeconds) || cadenceSeconds <= 0) return "cadence-malformed";
  if (newestStartedAt !== undefined && newestStartedAt !== null) {
    if (typeof newestStartedAt !== "string" || !Number.isFinite(Date.parse(newestStartedAt))) return "timestamp-malformed";
  }
  return null;
}

// ---- pure aggregate maths ------------------------------------------------------------------------

// bumpCount is the shared, clamped {count,lastAt} bump used by every aggregate here (and by the
// dropped-write fold). Pure, so the cap and the monotonicity are unit-testable.
export function bumpCount(agg: FaultCountAgg, name: string, at: string, by = 1): FaultCountAgg {
  const prev = agg[name];
  const add = Number.isFinite(by) ? Math.max(0, Math.floor(by)) : 0;
  agg[name] = { count: Math.min(FAULT_COUNT_CAP, (prev?.count ?? 0) + add), lastAt: at };
  return agg;
}

// appendRecentError is the PURE ring-append: a REPEAT of the same errorId bumps its count and time in place
// (a recurring fault is one row with a count, not 64 identical rows), a new id appends, and the ring is
// trimmed newest-last.
export function appendRecentError(ring: RecentErrorEntry[], entry: RecentErrorEntry, cap: number = RECENT_ERRORS_CAP): RecentErrorEntry[] {
  const existing = ring.findIndex((r) => r.errorId === entry.errorId);
  if (existing >= 0) {
    const prior = ring[existing]!;
    const next = ring.slice();
    next.splice(existing, 1);
    next.push({ ...entry, count: Math.min(FAULT_COUNT_CAP, prior.count + 1) });
    return next;
  }
  const next = [...ring, entry];
  return next.length > cap ? next.slice(next.length - cap) : next;
}

// ---- dropped-write bookkeeping (G104) ------------------------------------------------------------
//
// A recorder's own storage.put can FAIL. Persisting that fact at fault time is impossible (the store is the
// thing that just failed), so the count is held IN MEMORY against the DO instance (keyed on its storage
// object, so nothing is shared across instances and nothing outlives the isolate) and FOLDED into the durable
// aggregate by the next write that succeeds. A drop that is never followed by a successful write is lost -
// but that is a DO whose storage is fully down, where the tick ring's missed-interval gap is the evidence.
//
// THE KIND UNION IS BOTH VOCABULARIES, deliberately. The shared `diag:droppedwrites` record is co-written by
// this ledger and the Worker-edge recorder (see DROPPED_WRITE_KINDS above), and the two vocabularies are
// disjoint by design. A DO-side recorder that owns its OWN storage key rather than going through writeLedger
// (the WebAuthn structural-fault counter is the one) still needs to report ITS loss, and its kind lives in the
// EDGE vocabulary because that is where the recorder was catalogued. Widening the union here -- rather than
// opening a second pending tally, or duplicating the kind into this file's set -- keeps one aggregate, one
// key, and one place a drop can be recorded from inside the DO.
type SharedDroppedWriteKind = DroppedWriteKind | EdgeDroppedWriteKind;

const pendingDrops = new WeakMap<LedgerStorage, Map<SharedDroppedWriteKind, { count: number; lastAt: string }>>();

// noteDroppedDiagWrite is noteDroppedWrite for a DO-side recorder that does not go through writeLedger: it
// records the loss against the shared aggregate's pending tally, to be folded in by the next successful ledger
// write (or by an explicit flushDroppedWrites once the recorder's own storage answers again).
export function noteDroppedDiagWrite(storage: LedgerStorage, kind: EdgeDroppedWriteKind): void {
  noteDroppedWrite(storage, kind, new Date().toISOString());
}

function noteDroppedWrite(storage: LedgerStorage, kind: SharedDroppedWriteKind, at: string): void {
  let pend = pendingDrops.get(storage);
  if (pend === undefined) {
    pend = new Map();
    pendingDrops.set(storage, pend);
  }
  const prev = pend.get(kind);
  pend.set(kind, { count: Math.min(FAULT_COUNT_CAP, (prev?.count ?? 0) + 1), lastAt: at });
}

// flushDroppedWrites folds any in-memory drops into the durable aggregate. Called after every SUCCESSFUL
// ledger write (the store is demonstrably back), and cheap when there is nothing pending (the common case is
// a WeakMap miss, no storage I/O at all). Best-effort: if the fold itself fails the counts stay pending.
export async function flushDroppedWrites(storage: LedgerStorage): Promise<void> {
  const pend = pendingDrops.get(storage);
  if (pend === undefined || pend.size === 0) return;
  try {
    const agg = (await storage.get<FaultCountAgg>(DROPPED_WRITES_KEY)) ?? {};
    for (const [kind, v] of pend) bumpCount(agg, kind, v.lastAt, v.count);
    await storage.put(DROPPED_WRITES_KEY, agg);
    pend.clear();
  } catch {
    /* best-effort: the store is still down; the counts remain pending for the next successful write */
  }
}

// writeLedger is the ONE guarded read-modify-write every recorder below shares: never throws, records its own
// failure as a dropped write, and folds any earlier drops on success.
export async function writeLedger<T>(storage: LedgerStorage, key: string, kind: DroppedWriteKind, mutate: (prior: T | undefined) => T): Promise<void> {
  try {
    const prior = await storage.get<T>(key);
    await storage.put(key, mutate(prior));
  } catch {
    noteDroppedWrite(storage, kind, new Date().toISOString());
    return;
  }
  await flushDroppedWrites(storage);
}

// ---- capTruncations (G325): the capped record that never says it was capped -----------------------
//
// Records that clamp their row lists at write time and carry NO truncation marker, so a large-fleet reader
// cannot tell an absent row from a DROPPED one: the 65th destination's export-health outcome (its MISSING
// RECOVERY COPY invisible), a 40-destination reconcile view evicting its 8 oldest buckets, the ghost roster
// past 25 rows that cannot be enumerated for a mass-corruption repair, and the 51st downpipe whose staleness
// rule can never arm (whose pack row then reads as a downpipe with a working staleness rule). Cumulative
// dropped-row counts, per surface.
//
// AND A COUNT IS NOT ENOUGH: for the three subject-keyed surfaces, naming only a count leaves the
// consequence in the one place a reader actually reads. `freshnessUncomputableIndex` joins the freshness map
// onto downpipes[], a downpipe past the cap is ABSENT from the map, carries no marker, AND ITS PACK ROW STILL
// READS AS A DOWNPIPE WITH A WORKING STALENESS RULE. The SUBJECTS ledger below carries the ids, and
// support.ts joins them back onto the row.
//
// REDACTION, and why naming the subject is not a widening. The id emitted is EXACTLY the id that would have
// been the KEY of the capped map had there been room for it: `recordFreshnessFault` names the downpipe label
// it just refused, `recordIntegrityFaults` the downpipe id the map would have keyed, `applyDestProbeFaults`
// the destination label it stripped and clamped. Every one of those key spaces is already carried in the pack
// verbatim (`schedDiag.freshnessFaults`, `integrityFaults`, `destProbeFaults`, and `downpipes[].id`), so
// declaring a REFUSAL of a key cannot disclose a class the ADMISSION of the same key does not. Nothing else
// crosses: no cause, no reason, no count per subject, no free text. Every id is re-gated through `safeLabel`
// here even though the call sites already gated it, because this is the chokepoint.
//
// This lives here, one layer down from sched-fault-ledger.ts, because `recordFreshnessFault` lives in this
// file and a core recorder cannot import from the ledger without a cycle. The ledger's
// `export * from "./sched-fault-core.ts"` re-exports the whole block, so every import site is unchanged.
export const CAP_TRUNCATION_SURFACES = [
  "export-health-perdest", // recordControlPlaneExportHealth: perDest sliced to 64
  "reconcile-signal-map", // recordReconcileInventory: the freshest RECONCILE_SIGNAL_MAX destinations kept, older evicted
  "dest-prune-map", // foldDestPruneRecord (B61): the freshest DEST_PRUNE_MAP_MAX destinations' prune sidecar rows kept, older evicted
  "roster-ghosts", // analyseRoster: the ghost list capped at ROSTER_LIST_CAP
  "roster-never-ran", // analyseRoster: the never-ran list capped at ROSTER_LIST_CAP
  "freshness-faults", // recordFreshnessFault: the map REFUSES a new downpipe at FRESHNESS_FAULTS_CAP
  // The two SIBLINGS of freshness-faults, named unfixed by one pass and closed by another. Both
  // are subject-keyed maps that REFUSE a new subject rather than evicting an old one, so past the cap the
  // subject is ABSENT, and an absent subject in a fault record is read as a subject with no fault.
  "integrity-faults-downpipe", // applyIntegrityFaults: the map REFUSES a new downpipe at INTEGRITY_FAULTS_DOWNPIPE_CAP
  "dest-probe-faults", // applyDestProbeFaults + the cron accumulator: a new destination is REFUSED at DEST_PROBE_FAULTS_CAP
] as const;
export type CapTruncationSurface = (typeof CAP_TRUNCATION_SURFACES)[number];
const CAP_TRUNCATION_SURFACE_SET: ReadonlySet<string> = new Set(CAP_TRUNCATION_SURFACES);

export const CAP_TRUNCATIONS_KEY = "diag:captruncations";
export const CAP_TRUNCATION_SUBJECTS_KEY = "diag:captruncsubjects";

// The per-surface id list is itself bounded, because an unbounded one would trade a silent truncation for an
// unbounded DO value. 32 ids x 128 chars x 7 surfaces is ~28KB worst case against the 128KB value ceiling.
export const CAP_TRUNCATION_SUBJECT_IDS_CAP = 32;

// One entry per surface. `ids` are the DISTINCT refused subjects (a subject refused repeatedly is named once,
// unlike the cumulative count beside it). `incomplete` is the honesty bit that keeps this record from becoming
// the very thing it repairs: TRUE means at least one dropped subject is NOT named here, either because this
// list was full or because the drop was counted with no usable id (the Worker-side cron accumulator counts
// refusals it never sees the rows of). A reader must treat `incomplete: true` as "any subject may be missing".
export interface CapTruncationSubjectEntry {
  ids: string[];
  incomplete: boolean;
  lastAt: string;
}
export type CapTruncationSubjects = Record<string, CapTruncationSubjectEntry>;

// foldTruncationSubjects is the PURE fold (unit-testable with no DO). `named` are the ids the caller could
// gate; `unnamed` is how many dropped rows it could not name at all.
export function foldTruncationSubjects(prior: CapTruncationSubjects | undefined, surface: string, named: readonly string[], unnamed: number, at: string): CapTruncationSubjects {
  const agg: CapTruncationSubjects = { ...(prior ?? {}) };
  const prev = agg[surface];
  const ids = [...(prev?.ids ?? [])];
  let incomplete = prev?.incomplete === true || unnamed > 0;
  for (const id of named) {
    if (ids.includes(id)) continue;
    if (ids.length >= CAP_TRUNCATION_SUBJECT_IDS_CAP) {
      incomplete = true; // the id list itself refused a subject: say so rather than repeat the defect
      continue;
    }
    ids.push(id);
  }
  agg[surface] = { ids, incomplete, lastAt: at };
  return agg;
}

// recordCapTruncation declares that a bounded record DROPPED `dropped` rows on `surface`, and - when the call
// site knows them - WHICH SUBJECTS. `subjects` is optional so the surfaces whose dropped rows have no subject
// key (the roster lists, the reconcile eviction) are unchanged; a surface that passes fewer subjects than it
// dropped is recorded as incomplete rather than as fully enumerated.
export async function recordCapTruncation(storage: LedgerStorage, surface: CapTruncationSurface, dropped: number, subjects?: readonly unknown[]): Promise<void> {
  if (!CAP_TRUNCATION_SURFACE_SET.has(surface)) return;
  const n = Number.isFinite(dropped) ? Math.floor(dropped) : 0;
  if (n <= 0) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, CAP_TRUNCATIONS_KEY, "cap-truncation", (prior) => bumpCount(prior ?? {}, surface, at, n));
  if (subjects === undefined) return;
  // THE CHOKEPOINT: every id is re-gated through the same clamp the capped map's own key would have taken, so
  // a drifted caller cannot push an unclamped or non-string subject through this seam.
  const named: string[] = [];
  for (const s of subjects) {
    const id = safeLabel(s);
    if (id !== null) named.push(id);
  }
  // Fewer names than drops means the rest are unnamed, and that is recorded rather than papered over.
  const unnamed = Math.max(0, n - named.length);
  // Best-effort and AFTER the count, exactly like every recorder here: a failed subject write must never cost
  // the declaration that produced it, and it is booked as a dropped write of the same kind.
  await writeLedger<CapTruncationSubjects>(storage, CAP_TRUNCATION_SUBJECTS_KEY, "cap-truncation", (prior) => foldTruncationSubjects(prior, surface, named, unnamed, at));
}

// ---- recorders (best-effort, never throwing) -----------------------------------------------------

// recordCeremonyFault bumps ONE closed DO-side ceremony-fault class. An out-of-vocabulary kind is DROPPED
// (defence in depth, so no caller-derived string can ever add a key).
export async function recordCeremonyFault(storage: LedgerStorage, kind: CeremonyFaultKind): Promise<void> {
  if (!CEREMONY_FAULT_SET.has(kind)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, CEREMONY_FAULTS_KEY, "ceremony-fault", (prior) => bumpCount(prior ?? {}, kind, at));
}

// recordRecentError files an OPAQUE errorId against its stage + coarse reason class, so a customer quoting
// "err:ab12cd" from a console toast can finally be answered from the pack alone. The id is validated against
// ERROR_ID_PATTERN and both enums against their closed sets; a value failing any of those is DROPPED rather
// than stored. The exception MESSAGE is never passed in and never stored.
export async function recordRecentError(storage: LedgerStorage, errorId: unknown, stage: ErrorStage, reasonClass: ErrorReasonClass): Promise<void> {
  if (typeof errorId !== "string" || !ERROR_ID_PATTERN.test(errorId)) return;
  if (!ERROR_STAGE_SET.has(stage) || !ERROR_REASON_CLASS_SET.has(reasonClass)) return;
  const entry: RecentErrorEntry = { errorId, stage, reasonClass, count: 1, at: new Date().toISOString() };
  await writeLedger<RecentErrorEntry[]>(storage, RECENT_ERRORS_KEY, "recent-error", (prior) => appendRecentError(Array.isArray(prior) ? prior : [], entry));
}

// errorReasonClass REDUCES a passkey ceremony's COARSE reason (itself already a closed PasskeyReason member,
// never free text) to the ring's coarse class. A non-member - which is what a NON-PasskeyError exception
// yields, i.e. an engine fault the client is nonetheless told is its own `bad_request` - classes as internal.
// Pure: it reads no message and returns an enum member.
export function errorReasonClass(passkeyReason: unknown): ErrorReasonClass {
  switch (passkeyReason) {
    case "bad_request":
      return "bad-request-shape";
    case "challenge":
      return "challenge";
    case "origin":
    case "rpid":
    case "user_present":
    case "user_verified":
    case "signature":
    case "clone":
    case "unknown_credential":
    case "already_registered":
      return "verify-failed";
    default:
      return "internal";
  }
}

// recordCeremonyError is the ONE call the five ceremony catch-blocks make: file the opaque errorId the caller
// is about to be shown against its stage + coarse class, and - when the fault was NOT a PasskeyError (an
// internal engine fault the client is told is its own bad_request, so neither the user nor the edge's
// auth-signal can tell them apart) - also count it as an internal ceremony fault. `passkeyReason` is the
// thrown PasskeyError's closed reason or null; the exception MESSAGE is never passed in.
export async function recordCeremonyError(storage: LedgerStorage, stage: ErrorStage, passkeyReason: string | null, errorId: unknown, reasonClass?: ErrorReasonClass): Promise<void> {
  if (passkeyReason === null) await recordCeremonyFault(storage, "passkey-internal-fault");
  // `reasonClass` is the CALL SITE'S OWN verdict, and it exists for the one class the reason cannot express:
  // `stored-key-corrupt`. The engine's stored credential is the broken thing, and the caller is deliberately
  // told the coarse `bad_request` (an internal fault must never be oracled back), so classifying from the wire
  // reason -- which is what errorReasonClass does, correctly, for every other case -- files the engine's own
  // corruption as a malformed client request. The site that KNOWS passes the class; the message never does.
  await recordRecentError(storage, errorId, stage, reasonClass ?? errorReasonClass(passkeyReason));
}

// recordContractFault counts ONE Worker<->DO contract breach at the coercion site, so "quiet" and
// "rejected/coerced" stop being the same picture in the pack. Both halves are closed-set validated.
export async function recordContractFault(storage: LedgerStorage, route: ContractRouteClass, kind: ContractFaultKind): Promise<void> {
  if (!CONTRACT_ROUTE_SET.has(route) || !CONTRACT_FAULT_SET.has(kind)) return;
  const at = new Date().toISOString();
  await writeLedger<FaultCountAgg>(storage, CONTRACT_FAULTS_KEY, "contract-fault", (prior) => bumpCount(prior ?? {}, contractFaultKey(route, kind), at));
}

// recordDefaultDestHealth stamps the reachability heartbeat for the ENV-DEFAULT destination (the tenant with
// no console-set destination id, whose outages had no per-destination indicator anywhere). ok:true clears the
// reason and the down-since stamp; ok:false records the CLOSED reason class and preserves the FIRST down time,
// so "down for a week" is a recorded fact rather than an inference from a run row.
export async function recordDefaultDestHealth(storage: LedgerStorage, ok: boolean, reason: ReplicationReason | null): Promise<void> {
  const at = new Date().toISOString();
  await writeLedger<DefaultDestHealth>(storage, DEFAULT_DEST_HEALTH_KEY, "default-dest-health", (prior) => {
    if (ok) return { ok: true, reason: null, at, downSince: null };
    const wasDown = prior !== undefined && prior.ok === false && typeof prior.downSince === "string" && prior.downSince.length > 0;
    return { ok: false, reason, at, downSince: wasDown ? prior.downSince : at };
  });
}

// recordFreshnessFault marks ONE downpipe as having an UNARMABLE staleness rule (G076). Keyed by the
// customer's own downpipe label (clamped); the record is capped, and a fault for a downpipe already recorded
// simply refreshes it rather than growing the map.
//
// THE CAP REFUSES A NEW SUBJECT, AND THAT REFUSAL IS NOW DECLARED (G325). This is not a ring: it does not
// evict the oldest to admit the newest, it admits nobody once full, so on a fleet larger than the cap the
// downpipes past it are ABSENT rather than stale. Absent is the dangerous state here, because the pack's
// per-downpipe join carries `freshnessComputable: false` only for a downpipe IN this map, and the projector's
// convention is that an absent field means the field does not apply. So the 51st downpipe whose staleness
// rule can never arm reads as a downpipe whose staleness rule is fine -- which is the exact ticket G076
// exists to answer, "the map said Fresh for weeks while my backups had stopped", asserted by the pack rather
// than merely unrecorded.
//
// The drop is therefore booked against the shared capTruncations ledger, so the pack carries the one sentence
// a diagnosis needs: this list is a LOWER BOUND. The count is cumulative dropped WRITES, which is the same
// semantic the roster surfaces already carry (analyseRoster books its dropped rows on every hygiene pass), so
// a repeatedly-faulting downpipe past the cap inflates it -- a non-zero count means "some downpipe rows are
// wrong", never "exactly N downpipes are missing".
//
// DELIBERATELY NOT CHANGED: the admission policy. Making it evict the oldest would swap an arbitrary first-50
// for an arbitrary most-recent-50 and would EVICT a still-faulting downpipe, moving the same silent harm to a
// different row rather than removing it. Declaring the truncation removes it for every row at once.
export async function recordFreshnessFault(storage: LedgerStorage, downpipeId: unknown, cause: FreshnessFaultCause): Promise<void> {
  const id = safeLabel(downpipeId);
  if (id === null) return;
  const at = new Date().toISOString();
  let dropped = false;
  await writeLedger<FreshnessFaults>(storage, FRESHNESS_FAULTS_KEY, "freshness-fault", (prior) => {
    const map: FreshnessFaults = prior ?? {};
    if (map[id] === undefined && Object.keys(map).length >= FRESHNESS_FAULTS_CAP) {
      dropped = true;
      return map;
    }
    map[id] = { cause, at };
    return map;
  });
  // Best-effort and AFTER the ledger write, exactly like every other recorder here: a failed declaration must
  // never break the completion that produced it. If the ledger write itself failed, this write fails with it
  // and is booked as a dropped write of kind `cap-truncation`, so no truncation is ever fabricated.
  //
  // THE SUBJECT RIDES WITH THE COUNT, and this is the site that makes the row-level repair possible: the
  // downpipe being refused is the very thing this call is refusing, so `id` is already in hand and already
  // clamped. Without it the pack could say a downpipe was dropped and not which, and the 51st downpipe's row
  // went on asserting a working staleness rule.
  if (dropped) await recordCapTruncation(storage, "freshness-faults", 1, [id]);
}

// clearFreshnessFault drops a downpipe's marker once its staleness rule is computable again (the cadence was
// repaired, or a well-formed run landed), so a healed downpipe stops reporting a fault it no longer has.
// Best-effort: a failed clear only leaves a marker whose `at` is visibly old, never a wrong dispatch.
export async function clearFreshnessFault(storage: LedgerStorage, downpipeId: unknown): Promise<void> {
  const id = safeLabel(downpipeId);
  if (id === null) return;
  try {
    const map = await storage.get<FreshnessFaults>(FRESHNESS_FAULTS_KEY);
    if (map === undefined || map[id] === undefined) return;
    delete map[id];
    await storage.put(FRESHNESS_FAULTS_KEY, map);
  } catch {
    /* best-effort */
  }
}

// recordCompletionDiagnostics is the ONE per-completion observation the scheduling core makes (G120 + G076),
// kept here so the classify/clamp/redaction logic lives with the vocabularies it draws on rather than in the
// run-state machine. It takes FACTS, never the completion body: the closed status, the coarse error class
// (read only to SELECT a reason enum), whether the run named a console destination, how many destinations it
// proved down, the stored cadence and the newest run timestamp.
//   - ENV-DEFAULT DESTINATION (G120): a run that names NO destination id is the single-destination tenant whose
//     outages had no per-destination indicator anywhere. Only a DESTINATION-side class is booked as a
//     destination fact (a run that failed reading its SOURCE says nothing about the destination, and booking it
//     as one would send triage to the wrong system); a later successful run clears the indicator.
//   - FRESHNESS (G076): mark (or clear) the downpipe whose staleness rule can never arm.
// Never throws: an observation must not break the completion it observed.
export async function recordCompletionDiagnostics(
  storage: LedgerStorage,
  f: { downpipeId: string; status: string; coarseError: string | undefined; hasDestinationId: boolean; downDestinationCount: number; cadenceSeconds: unknown; newestStartedAt: unknown },
): Promise<void> {
  if (!f.hasDestinationId && f.downDestinationCount === 0) {
    if (f.status === "failed") {
      const cls = classifyReplicationReason(f.coarseError);
      if (cls !== "other") await recordDefaultDestHealth(storage, false, cls);
    } else if (f.status === "ok") {
      await recordDefaultDestHealth(storage, true, null);
    }
  }
  const cause = freshnessFaultCause(f.cadenceSeconds, f.newestStartedAt);
  if (cause !== null) await recordFreshnessFault(storage, f.downpipeId, cause);
  else await clearFreshnessFault(storage, f.downpipeId);
}

// stripLedgerControls removes C0/C1 control characters from a clamped code, so no engine-set code can inject a
// line break (or a terminal escape) into an operator's view of a ring. The same idiom diag-records.ts uses.
export function stripLedgerControls(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) continue;
    out += s[i];
  }
  return out;
}
