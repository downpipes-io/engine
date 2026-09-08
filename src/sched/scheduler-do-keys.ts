// scheduler-do-keys.ts -- the scheduler DO's STORAGE-KEY and persisted-state-shape vocabulary: the third
// pure leaf beside scheduler-do-limits.ts and scheduler-do-records.ts (engine-sys-struct-06 god-module
// split). Every symbol here moved WHOLE and verbatim out of scheduler-do-base.ts, comments
// intact, and is re-exported from there so every mixin and router keeps its one import path; the leaf
// itself imports nothing. It holds storage-key prefixes, bounded size/count caps and the small closed
// persisted-state shapes they key -- no behaviour, no secrets, no custody.

// engine-sys-struct-06 / engine-sys-arch-01 (god-module split): the SchedulerDO class statics hoisted
// to module consts so the auth subsystem mixins (passkey/oidc/saml/session/step-up/owner-action) can
// import them. Each was a `private static readonly` on the single class; as a module const it holds
// the SAME value and the SAME type. They are storage-key prefixes and bounded size/count limits with
// no behaviour: the former SchedulerDO.X and the const X are interchangeable at runtime.
// PASSKEY_USER_PREFIX / PASSKEY_CRED_PREFIX / PASSKEY_CHALLENGE_PREFIX key the three passkey record
// families, alongside the role/group/custom-role and dp:/hist: keys. A user is keyed by the canonical
// email; a credential by its base64url credential id (so a login looks it up directly from the asserted
// id); a challenge by its scope ("reg:<email>" or "login:<id>"), so a registration challenge is bound
// to the email and a login challenge to a fresh opaque id.
export const PASSKEY_USER_PREFIX = "passkeyUser:";
export const PASSKEY_CRED_PREFIX = "passkeyCred:";
export const PASSKEY_CHALLENGE_PREFIX = "passkeyChallenge:";
// PASSKEY_WITNESS_SINCE_KEY dates the usability witness itself
// (PASSKEY-OWNER-ENROLLED-COUNTS-CREDENTIALS): the RFC-3339 instant at which this DO first ran
// witness-carrying passkey code. It exists so that a MISSING `lastAssertedAt` can be read honestly. Without
// it, "never demonstrated" and "enrolled before anything was recorded" are the same absence, and a verdict
// built on that absence would condemn every credential in the fleet on the day it shipped. A single scalar
// separates them: a credential whose createdAt post-dates this instant and still carries no stamp has
// genuinely never been asserted. Written once, never rewritten, never a secret.
export const PASSKEY_WITNESS_SINCE_KEY = "passkeyWitnessSince";
// PASSKEY_INVITE_PREFIX keys the single-use, email-bound registration invites (`passkeyInvite:<token>`),
// minted when an Owner/access-admin grants a role to an email that has no credential yet. A non-bootstrap,
// non-self-add registration MUST present a valid invite token; the bound email comes FROM the invite
// record (never the client field) and the record is consumed on a successful registration. See
// mintRegistrationInvite / consumeInvite and passkeyRegisterFinish.
export const PASSKEY_INVITE_PREFIX = "passkeyInvite:";
// BOOTSTRAP_INVITE_KEY is the SINGLE fixed slot for the first-Owner email-link invite (one live link at
// most; a re-mint overwrites it). Minted only on an empty role table with the bootstrap latch unset, for
// the deploy-time-pinned BOOTSTRAP_OWNER_EMAIL only. See mintBootstrapInvite / peekBootstrapInvite /
// consumeBootstrapInvite and resolveRegistrationAuthorisation's empty-table branch.
export const BOOTSTRAP_INVITE_KEY = "bootstrapInvite";
// PASSKEY_LOGIN_CHALLENGE_CAP bounds how many login challenges the DO will retain at once. A login/begin
// mints a `login:<id>` challenge before any credential is known, so an unauthenticated flood of
// login/begin calls would otherwise grow DO storage without bound (each is consumed only by a matching
// finish, which an attacker never sends). On each login/begin the DO first sweeps EXPIRED login
// challenges, then, if still over this cap, evicts the OLDEST surviving ones, so the stored login-challenge
// set is bounded regardless of how many begins are fired. The cap is generous (far above any plausible
// concurrent human sign-in count) so a legitimate burst is never evicted before its finish; it only
// bounds an abusive flood. Registration challenges are email-keyed (`reg:<email>`, one per email) and the
// per-IP limiter on /admin/auth/* bounds the begin rate, so this cap targets the login-challenge family.
export const PASSKEY_LOGIN_CHALLENGE_CAP = 512;
// PASSKEY_SESSION_KEY_KEY holds the HMAC-SHA-256 signing key for passkey SESSION tokens, generated ONCE
// (SESSION_KEY_BYTES of CSPRNG, base64url) on first use and persisted under this single DO key. It is the
// engine's own session-signing secret: never hardcoded, never returned to a client, and never leaving the
// DO (the sign and the constant-time verify both run in the DO over this stored key). Rotating it (delete
// the record) invalidates every outstanding session, which is the intended "sign everyone out" lever.
export const PASSKEY_SESSION_KEY_KEY = "passkeySessionKey";
// RECOVERY_SIGNING_KEY_KEY holds the HMAC-SHA-256 key the RECOVERY CODES are hashed and verified under. It
// is a SEPARATE key from the session-signing key because the two have opposite lifetimes: the session key is
// DELETED to sign everyone out, and a recovery code must survive that global sign-out (a session token must
// not), so the break-glass an operator reaches for after a suspected compromise cannot be destroyed by the
// same action that ends the compromise.
//
// MIGRATION (zero re-hash): the record is materialised lazily and, on an account that predates this key, it
// ADOPTS THE CURRENT SESSION KEY BYTES VERBATIM. Every recovery hash already stored was computed under those
// exact bytes, so they keep verifying with no record rewrite, no re-mint and no window in which a banked code
// is dead. See recoverySigningKey() in scheduler-do-recovery.ts for the ordering that makes this safe.
export const RECOVERY_SIGNING_KEY_KEY = "recoverySigningKey";
// BEACON_STATE_KEY holds the OUTCOME of the most recent opt-in vendor-beacon POST (cron/beacon-emit.ts
// posts it here after each attempt; absent until the first attempt, which only happens when the beacon is
// configured). A closed shape only -- when it happened, whether the POST returned 2xx, and the coarse HTTP
// status -- so the support pack can answer "is the beacon reaching the vendor?" (beacon-post-lost) without
// the fail-open beacon path holding any state itself. Redaction-safe (a timestamp + a bool + a small int).
export const BEACON_STATE_KEY = "beacon:last-attempt";
// BeaconAttempt is ONE beacon POST outcome. It carries a closed BeaconFailClass the cron already computes
// (cron-fault-ledger.ts: url-invalid | network | non-2xx | do-read | unknown) and a bounded ring of recent
// attempts, so the support pack can distinguish a malformed BEACON_URL (a permanent, one-line operator fix)
// from a network blip (self-healing), and tell a hard-down beacon from an INTERMITTENT one. status is the
// clamped HTTP status. Never BEACON_URL, never the ingest key, never the throw message.
export interface BeaconAttempt {
  at: number;
  ok: boolean;
  status?: number;
  errorClass?: string;
}
export interface BeaconAttemptState {
  at: number;
  ok: boolean;
  status?: number;
  errorClass?: string;
  // The last BEACON_ATTEMPT_RING_CAP attempts, newest last. A ring, not a single stamp, because
  // intermittency IS the diagnosis: "ok, fail, ok, fail" is a different ticket from "fail, fail, fail".
  recent?: BeaconAttempt[];
}
export const BEACON_ATTEMPT_RING_CAP = 5;
// DRIVE_BUDGET_YIELD_KEY holds the cumulative record of the cron seal loop YIELDING because the shared per-
// invocation subrequest budget ran low before every due downpipe was dispatched (failover-probe-budget-
// exhaustion). The yield happens BEFORE a run is allocated (the undispatched downpipes stay DUE and carry to
// the next tick), so it has no per-run home and is otherwise only a log line -- a fleet too large for the
// per-tick budget silently starves its tail. The cron posts here on each yield; the support pack reads it so
// "N downpipes were carried over because the tick ran out of budget" is visible. A closed shape only: a
// cumulative count, the last yield time, and the last carried-over count (all clamped ints/timestamp).
export const DRIVE_BUDGET_YIELD_KEY = "drive:budget-yield";
export interface DriveBudgetYieldState {
  count: number; // cumulative number of ticks whose seal loop yielded on a low budget
  lastAt: number; // epoch ms of the most recent yield
  lastCarried: number; // how many due downpipes the most recent yield carried to the next tick
}
// CHANGE_CONTROL_REFUSAL_KEY holds the cumulative tally of change-controlled actions REFUSED by
// enforceChangeControl because no valid change reference was supplied while "Require Change Number" is ON
// (change-number-required-refusal). This is the OBSERVE side ONLY: the CR ledger contract is deliberately
// UNCHANGED (a refused action still records NO change-recorded entry -- the refusal is not a raised CR), so
// this is a SEPARATE diagnostic counter, never an audit event. Closed shape: a cumulative count, the last
// refusal time (ISO), and the last refused action KIND (the closed engine-set label the change target already
// carries, bounded; never operator free-text). The support pack reads it without ever touching the CR ledger.
export const CHANGE_CONTROL_REFUSAL_KEY = "change-control-refusal";
export interface ChangeControlRefusalState {
  count: number;
  lastAt: string | null;
  lastActionKind?: string;
  // coerced is READ-SIDE ONLY and NEVER stored: the record was PRESENT and read back malformed, so the zero
  // beside it is a safe default rather than a measurement (getChangeControlRefusals; same field below).
  coerced?: true;
}
// CONFIG_SNAPSHOT_FAILURE_KEY holds the cumulative tally of config auto-snapshot captures that FAILED and were
// swallowed to a log line (config-snapshot-best-effort-gap). autoSnapshotConfig runs AFTER a config mutation
// has committed and must never throw, so a versioning capture that fails leaves the mutation applied but
// UN-versioned -- silently, today. This diagnostic counter (a count + the last failure time) makes that gap
// visible in the support pack. Purely additive; it never changes how config is applied.
export const CONFIG_SNAPSHOT_FAILURE_KEY = "config-snapshot-failure";
export interface ConfigSnapshotFailureState {
  count: number;
  lastAt: string | null;
  coerced?: true; // as above: the pack surfaces this block only above zero, so a coerced zero is an ABSENT block
}
// CONFIG_HISTORY_KEY_FP_KEY holds a NON-SECRET fingerprint (a SHA-384 prefix) of the in-DO session signing key
// the config-history chain HMACs its digests with, persisted ONCE (config-history-session-key-regen). If that
// key is regenerated/lost, EVERY config-history digest fails verifyConfigChain -- indistinguishable from
// content tamper. Comparing the live key's fingerprint to this stored one lets the health read report a
// signing-key ROTATION (recoverable context) distinctly from a genuine brokenAt (an integrity alarm). Only the
// one-way fingerprint is stored (never the key), and only the derived BOOLEAN signingKeyRotated leaves the DO.
export const CONFIG_HISTORY_KEY_FP_KEY = "config-history-key-fp";
// CONFIG_HISTORY_HEAD_KEY is the config-history chain's HEAD ANCHOR (G313 R6): the id and contentHash of the
// newest version this DO itself committed, written in the same storage turn as the version put. It is the
// config-history twin of AUDIT_HEAD_KEY, and it exists because every verify pass -- keyed and key-free alike --
// walks the RETAINED versions and can only see a break BETWEEN two of them. Delete the NEWEST versions and the
// survivors still link perfectly: the chain reads INTACT, and the deletion an attacker actually performs (remove
// the records of what they just did) was undetectable. Retention rolls the OLDEST versions off and never lowers
// this anchor, so a retained head BELOW it -- or at it with a different contentHash -- is a removed or rewritten
// tail, and NO KEY is needed to say so. It is deliberately NOT under the `confighist:` prefix (that prefix is
// listed as the chain itself). It holds an integer and a content hash: no snapshot, no author, no key.
export const CONFIG_HISTORY_HEAD_KEY = "config-history-head";
export interface ConfigHistoryHead {
  headId: number;
  headContentHash: string;
}
// LICENCE_ACTIVATION_REFUSAL_KEY holds the cumulative tally of console licence ACTIVATIONS refused by the
// verify-before-store gate (failed-activation-no-trace): POST /admin/licence refuses a token that does not
// verify (typo, wrong signer, expired, malformed shape) with a jsonError and records NOTHING today, so a
// customer insisting "I activated my licence but it still says community" is undiagnosable. This diagnostic
// counter (a count, the last refusal time, and the last CLOSED reason code) makes the refusals visible in the
// pack. The reason code is the closed LicenceReasonCode classification (or "malformed-token"), never a value.
export const LICENCE_ACTIVATION_REFUSAL_KEY = "licence-activation-refusal";
export interface LicenceActivationRefusalState {
  count: number;
  lastAt: number; // epoch ms of the most recent refusal
  lastReasonCode?: string; // closed LicenceReasonCode (or "malformed-token"); never a value
}
// STATUS_BASELINE_KEY records the engine's deploy identity at the moment the status snapshot BASELINE was
// (re-)established -- the FIRST observation on a fresh DO, or one after a snapshot RESET (a wiped / first-poll
// control plane) (engine-version-change-baseline-suppressed / same-version-redeploy-double-blind). diffStatus
// deliberately records NO audit "change" burst at baseline (onboarding noise), so a reset that silently
// dropped live source bindings is otherwise indistinguishable from steady state, and the deploy-id-change arm
// (which needs BOTH a prior and a current id) cannot fire on the very first poll. observeStatus stamps this
// marker ONCE per baseline (it is re-stamped, with a fresh `at`, only when a wipe makes prior null again), so a
// support engineer comparing `at` across two packs sees a reset, and cfVersionId names which deploy it was.
// Closed shape only: the observed engine version, the immutable Cloudflare deploy id when known, and the
// baseline time. It lands once but IS present, coordinating with the vendor-side deploy-ledger (beacon) keystone.
export const STATUS_BASELINE_KEY = "status-baseline";
export interface StatusBaselineState {
  version: string; // the engine software version observed at baseline
  cfVersionId?: string; // the immutable Cloudflare deploy id observed at baseline (absent under env-fallback/local)
  at: number; // epoch ms the baseline was (re-)established
}
// SESSION_EPOCH_PREFIX keys the per-email session epoch (a monotonic counter, default 0). A session
// token carries the epoch at issue; the verify below rejects a token whose epoch is below the current
// stored value, which is how session termination works WITHOUT a session store: bump the epoch and
// every token minted before the bump fails its next request (V7.4.3 / V7.4.5 / V7.5.2).
export const SESSION_EPOCH_PREFIX = "sessionEpoch:";
// OIDC_GROUPS_PREFIX keys the per-subject GROUP snapshot written at sign-in and re-read on every request, so a
// group change takes effect without waiting out the 12h cookie and the cookie itself never carries groups.
//
// IT HAS ONE WRITER AND NO DELETER, recorded here because this declaration is where the next reader looks.
// The writer is the native-IdP session mint; the readers are the live request path and spendTimeGroupsFor,
// which quotes it with NO SESSION IN HAND when a stored governance record re-resolves its principal and is
// then the SOLE source of a group-conferred person's spend-time authority. So those groups are their last
// login's until they log in again. Every candidate deleter needs a decision, so none is built:
//   OFFBOARD CANNOT NAME THE KEY, a hard limit rather than a preference. The row is a bare string[] with no
//     email and no time, and the only email-bearing subject-keyed record here is role:sub:<subject>, which a
//     group-conferred person does not have. Closing it needs a NEW durable email-to-subject record written at
//     sign-in: a custody question, plus a rule for subject change.
//   A STALENESS SWEEP cannot be written before a schema change (no timestamp), needs a retention number, and
//     its effect is the silent mid-session demotion already counted as group-snapshot-missing.
//   DELETING ON CONNECTION DISABLE would make disable-then-re-enable irreversible for group-conferred members,
//     contradicting the suspend-rather-than-void property the replay liveness axis keeps on purpose.
// The one variant needing no decision buys nothing: on connection DELETE the subject encodes the connId so a
// prefix scan could enumerate, but both readers already fail closed there, so it would remove rows that
// confer nothing. Hygiene, not revocation. What DOES revoke today: delete the group->role mapping
// (estate-wide), reject the stored record, or disable the connection (per person).
export const OIDC_GROUPS_PREFIX = "oidcgroups:";
// IDP_EPOCH_PREFIX / SESSION_EPOCH_SUB_PREFIX key the two revocation axes the v3 session adds on top of the
// per-email epoch. Both store a "not-before" INSTANT (epoch ms): a session whose signed iat predates the
// stored instant is rejected. (The per-email axis stays a monotonic COUNTER because terminate-others re-mints
// the surviving session with the bumped counter; the subject/connection axes have no "keep this one" carve-out.)
export const IDP_EPOCH_PREFIX = "idpEpoch:";
export const SESSION_EPOCH_SUB_PREFIX = "sessionEpochSub:";
// SEEN_ASSERTION_PREFIX keys the SAML one-time-use assertion cache (replay defence in depth): seenassertion:
// <connId>:<assertionId> = the assertion's notOnOrAfter (epoch ms), pruned by the alarm once past.
export const SEEN_ASSERTION_PREFIX = "seenassertion:";
// PASSKEY_CLIENT_DATA_MAX / PASSKEY_ATT_OBJ_MAX / PASSKEY_AUTH_DATA_MAX / PASSKEY_SIG_MAX / PASSKEY_-
// CRED_ID_B64_MAX bound each decoded client field. clientDataJSON is small JSON; the attestationObject
// carries the COSE key (a few hundred bytes) under fmt none; authenticatorData on an assertion is ~37+
// bytes; an RSA signature is up to ~512 bytes; a credential id is up to ~1023 bytes (CRED_ID_MAX).
export const PASSKEY_CLIENT_DATA_MAX = 4096;
export const PASSKEY_ATT_OBJ_MAX = 8192;
export const PASSKEY_AUTH_DATA_MAX = 4096;
export const PASSKEY_SIG_MAX = 1024;
export const PASSKEY_CRED_ID_MAX = 1023;
export const REG_PATHS = ["bootstrap", "invite", "self-add"] as const;
export const STEPUP_TOKEN_PREFIX = "stepupToken:";
