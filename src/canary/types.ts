import type { DestDownReason } from "../dest/classify.ts";
// The Canary backup: a synthetic known-answer backup the engine flies on a fixed cadence to prove the
// whole archive path works byte-for-byte. A small bird of known data is written, validated, restored
// over an isolated cell, and tested against the known bytes. While every byte returns exactly as it
// was sent the canary SINGS (alive) and the mine is safe to work in; the instant a single bit strays
// the canary is DEAD and the coalmine must be evacuated (do not trust that destination/path for real
// backups until it is investigated). It writes only its own corpus under a dedicated _CANARY/
// namespace and restores only into that namespace, so it never touches a customer archive or a real
// binding, and a canary failure never blocks or alters a real backup (fail-open): it alerts.
//
// MULTI-DESTINATION: the canary flies the WHOLE eight-aspect run against EACH selected destination,
// so it proves every destination you back up to actually restores. Each destination has its own
// independent result and liveness; the canary's headline status is the WORST across them (it dies if
// any one destination's canary dies). By default it flies to ALL configured destinations (auto-
// including new ones); the owner can pin an explicit subset in settings.

// CanaryLiveness is the bird's state. alive/dead are the load-bearing ones (alive = every byte
// returned exactly; dead = a bit strayed, the data-integrity death). ailing is a system fault that
// stopped the check completing (destination unreachable, no read-back key) and is deliberately
// distinct from a data death: it is quiet (no evacuation alert). pending is the pre-first-flight state
// (or no destination configured yet); disabled is the operator opt-out.
export type CanaryLiveness = "alive" | "dead" | "ailing" | "pending" | "disabled";

// CanaryAspectKey is the closed set of checks one flight runs, in order. Each is a distinct thing one
// green canary proves about the destination and the archive path.
export type CanaryAspectKey =
  | "write-probe" // destination reachable, credentials valid, write permission (can PUT)
  | "delete-probe" // delete permission / immutability posture (can DELETE; a note, never a death)
  | "seal" // a real archive write of the known corpus (manifests + RUNLOG)
  | "read-signature" // read-back: root + shard manifest signatures verify (tamper-evidence)
  | "runlog-freshness" // the RUNLOG entry is present, chained and fresh
  | "decrypt-integrity" // decrypt every record and compare to the known bytes, byte-exact
  | "restore" // run the real restore path into the isolated canary cell (restore over)
  | "restore-verify"; // read the restored cell back and byte-compare to the known corpus

// AspectOutcome: pass = proven; fail = a death (a bit strayed where it must not); skip = the aspect
// could not be attempted (a prior aspect blocked it, or no read-back key); note = an informational
// observation that is not a death (an immutable bucket refusing the delete-probe).
export type AspectOutcome = "pass" | "fail" | "skip" | "note";

export interface CanaryAspectResult {
  key: CanaryAspectKey;
  outcome: AspectOutcome;
  // detail is a short, redaction-safe, Australian-English line. It NEVER carries plaintext, a key, an
  // object key or a record value, only the coarse fact (e.g. "256 records verified, 0 bytes strayed").
  detail: string;
}

// CanaryAilingCause is the closed, redaction-safe reason a flight finalised ailing.
//
// It carries DestDownReason (auth, worm-refused, throttled, timeout, network, tls, other), each of which
// maps to a different operator action, plus:
//   probe-mismatch  the destination ANSWERED and returned the wrong bytes -- not a "down" reason at all:
//                   the store is up and is giving back something other than what it was given.
//   unreachable     LEGACY, no longer produced by any path. Retained because stored flight history carries
//                   it, and narrowing the type would make reading that history a lie.
// Still a closed enum member, never a value or an object key, so it stays safe on the redacted view exactly
// like deadReason.
export type CanaryAilingCause = DestDownReason | "probe-mismatch" | "unreachable";

// CanaryCheck is one destination's flight result, kept as that destination's latest result and in the
// flight history (redaction-safe: counts and coarse facts only, never a value or a key).
export interface CanaryCheck {
  at: string; // RFC 3339 UTC millis
  ok: boolean; // true only when status === "alive"
  status: CanaryLiveness;
  durationMs: number;
  destinationId: string | null; // the destination this flight exercised (null = the env default)
  runSeq: number; // the canary's own monotonic flight number
  aspects: CanaryAspectResult[];
  byteDelta: number | null; // bytes that strayed from the known corpus (0 when alive, null when not reached)
  deadReason: string | null; // the coarse reason the canary died (set only when status === "dead")
  // ailingCause is set only when status === "ailing", and only by the structural cause-mapped branches in
  // cycle.ts; it is optional so a record persisted before this field existed simply reads as absent (not a
  // fabricated "not posture"). A dead or alive result never carries one.
  ailingCause?: CanaryAilingCause;
}

// CanaryFlight is one whole flight: the per-destination results plus the aggregate status (worst of
// them). One flight produces one CanaryCheck per destination flown.
export interface CanaryFlight {
  at: string; // RFC 3339 UTC millis
  runSeq: number;
  status: CanaryLiveness; // aggregate of this flight (dead if any destination died)
  results: CanaryCheck[]; // one per destination flown
}

// CanaryTransition is ONE bounded ring entry recording a per-destination liveness THRESHOLD crossing
// (the bird fell dead, or a dead bird recovered) at a point in time (NOTIF needs-new-logging: canary-
// transition-only-pages-once). The canary pages exactly ONCE per transition (a persistent death does not
// re-page every hour), so after the initial page the standing dead state leaves no fresh signal; this ring
// is the durable record of WHEN each crossing happened, so support can see "it paged once at T and has been
// dead since" WITHOUT re-flying or reading the heavy flight history. Redaction-safe by construction: a
// clamped RFC-3339 time, the destination's own id (or null for the env default), a closed to-state enum,
// and the monotonic flight number; never a byte value, a key, or an object key.
export interface CanaryTransition {
  at: string; // RFC-3339 UTC millis of the flight that crossed the threshold
  destinationId: string | null; // the destination that transitioned (null = the env default)
  to: "dead" | "recovered"; // the closed crossing direction
  runSeq: number; // the canary's own monotonic flight number that observed the crossing
}

// CanaryDestState is the persisted per-destination liveness and cleanup bookkeeping.
export interface CanaryDestState {
  destinationId: string | null; // null = the env default (no console destinations configured)
  status: CanaryLiveness;
  lastRunAt: string | null;
  lastRunId: string | null; // the most recent flight's runId (its _CANARY/runs/<id>/ cell; next flight cleans it up)
  deadSince: string | null; // when this destination's bird first fell dead (cleared on recovery)
  consecutivePasses: number;
  lastCheck: CanaryCheck | null; // the latest flight result for this destination (the eight aspects)
}

// CanaryConfig is the operator-controlled surface. enabled is ON by default (an absent record reads as
// enabled). destinationIds selects which destinations the canary flies to: NULL means ALL configured
// destinations (auto-including new ones, the default); a non-empty array pins exactly those.
// intervalSeconds is the cadence (default 3600, every 60 minutes).
export interface CanaryConfig {
  enabled: boolean;
  destinationIds: string[] | null;
  intervalSeconds: number;
}

// CanaryState is the full record held under the scheduler DO's CANARY_KEY. It holds no secret and no
// key material, like the org-policy and destination records beside it.
export interface CanaryState {
  config: CanaryConfig;
  status: CanaryLiveness; // the AGGREGATE liveness (worst across destinations)
  lastRunAt: string | null;
  nextRunAt: number | null; // epoch ms; null = due on the next tick (a fresh or just-enabled canary)
  inFlight: boolean;
  inFlightSince?: number; // epoch ms; bounds inFlight as a lease so an evicted flight never wedges the bird
  runSeq: number; // monotonic flight counter
  dests: CanaryDestState[]; // per-destination liveness + cleanup bookkeeping
  history: CanaryFlight[]; // newest-last ring of whole flights, capped at CANARY_HISTORY_CAP
  // The bounded, newest-last ring of per-destination liveness THRESHOLD crossings (dead / recovered), capped
  // at CANARY_TRANSITION_CAP. It is APPENDED to on each transition (the same crossings the Worker pages on),
  // so the standing "only pages once" death is durably observable long after the single page. Optional: an
  // absent field on a record persisted before this ring existed reads as an empty ring (projected with ?? []).
  transitions?: CanaryTransition[];
}

// CanaryRunDescriptor is what the DO hands the Worker for ONE destination of a flight: the allocated
// runId, the cell to clean up, and the destination to fly to. The Worker resolves the credentials
// itself and runs the cycle; the DO never does the heavy I/O.
export interface CanaryRunDescriptor {
  runId: string;
  runSeq: number;
  destinationId: string | null; // null = the env default destination
  cleanupRunId: string | null; // the prior flight's cell for this destination to delete, or null on the first flight
}

// CanaryFlightPlan is what canaryDue returns when a flight is due: the sequence number and one
// descriptor per destination to fly to.
export interface CanaryFlightPlan {
  runSeq: number;
  dests: CanaryRunDescriptor[];
}

// CanaryCheckResult is what runCanaryCycle returns to the DO's /canary/complete for ONE destination.
export interface CanaryCheckResult {
  status: CanaryLiveness; // alive | dead | ailing | pending
  durationMs: number;
  destinationId: string | null;
  aspects: CanaryAspectResult[];
  byteDelta: number | null;
  deadReason: string | null;
  // ailingCause: see CanaryCheck. Set only on the "ailing" override branch of finalise(), never on the
  // dead or alive paths, so a genuine death or a clean pass can never carry a posture cause.
  ailingCause?: CanaryAilingCause;
}

// CanaryDestView is the redacted per-destination view the console renders: the destination's label and
// liveness plus its latest eight-aspect result.
export interface CanaryDestView {
  destinationId: string | null;
  label: string; // human label (resolved from the destination collection; "Default destination" for env)
  isDefault: boolean;
  status: CanaryLiveness;
  lastRunAt: string | null;
  deadSince: string | null;
  lastCheck: CanaryCheck | null;
}

// CanaryView is the redacted shape the admin GET /canary returns to the console: the aggregate state,
// the per-destination views, the recent flights, and the full destination list (for the settings
// multi-select). The console never sees a value, a key or a real hash, only liveness and counts.
export interface CanaryView {
  config: CanaryConfig;
  status: CanaryLiveness; // aggregate
  lastRunAt: string | null;
  nextRunAt: number | null;
  inFlight: boolean;
  runSeq: number;
  dests: CanaryDestView[]; // per-destination (the destinations the canary currently flies to)
  history: CanaryFlight[];
  allDestinations: Array<{ id: string; label: string; isDefault: boolean }>; // the collection (for the settings picker)
  destinationCount: number;
  flyingToAll: boolean; // true when config.destinationIds is null (all destinations, auto-including new ones)
  // danglingPins are PINNED destination ids that no longer name a destination in the collection.
  //
  // setCanaryConfig refuses an unknown id outright, so a pin can only go dangling later, when the
  // destination it named is deleted. resolveEffectiveDests then DROPS it silently, so without this field
  // the console would have no way to say a deliberately pinned destination (e.g. a cold-archive bucket) is
  // no longer being proven -- the pin would simply vanish from `dests` while the aggregate read healthy for
  // the destinations that remained.
  //
  // Empty when flying to all (there are no pins to dangle) and empty in the healthy pinned case, so a
  // non-empty value always means something the operator asked for is no longer being proven.
  danglingPins: string[];
}

// CANARY_HISTORY_CAP bounds the in-DO flight-history ring (two days of hourly flights) so DO storage
// stays bounded, mirroring the audit and notify-history rings.
export const CANARY_HISTORY_CAP = 48;

// CANARY_TRANSITION_CAP bounds the liveness-transition ring. Transitions are rare (a flip only when a bird
// falls dead or recovers, not every flight), so a generous cap covers a long history of crossings cheaply.
export const CANARY_TRANSITION_CAP = 50;

// CANARY_DEFAULT_INTERVAL_SECONDS is the 60-minute cadence the owner specified.
export const CANARY_DEFAULT_INTERVAL_SECONDS = 3600;

// CANARY_LEASE_MS bounds the inFlight flag: a flight still in flight past this is treated as crashed
// (evicted worker, hit a limit, redeploy mid-cycle) and reclaimed on the next due check, so an
// interrupted flight never wedges the bird in flight forever (mirrors INFLIGHT_LEASE_MS). It is sized
// generously because a multi-destination flight runs each destination in turn.
export const CANARY_LEASE_MS = 20 * 60 * 1000;

// CANARY_MAX_DESTS bounds how many destinations one flight will fly to, so a misconfiguration or a huge
// collection cannot blow the worker invocation budget. Beyond this the flight covers the first N and
// the rest are reported as not-flown (the console surfaces the cap).
export const CANARY_MAX_DESTS = 12;

// CANARY_DOWNPIPE_ID is the reserved downpipe id the canary archive seals under. It is not a real
// downpipe (it never appears in the downpipe collection); it only names the archive's own isolated
// RUNLOG chain inside the _CANARY/ namespace.
export const CANARY_DOWNPIPE_ID = "__canary";

// CANARY_NAMESPACE_PREFIX is the dedicated key prefix the canary writes and restores under, inside
// whichever destination bucket it flies to. Every object the canary writes lives under
// _CANARY/runs/<runId>/, so it can never collide with a customer archive (which lives under
// _RECOVERY/ and run/ and seg/) and a whole flight's residue is one prefix to delete.
export const CANARY_NAMESPACE_PREFIX = "_CANARY/runs/";

// aggregateLiveness folds the per-destination statuses into the headline liveness: dead if any
// destination died (the canary is dead, evacuate), else ailing if any could not complete, else pending
// if any has not flown or is disabled, else alive. No destinations at all reads as pending (nothing
// proven yet). A persisted "disabled" status (set during a disabled window, not yet overwritten) is
// folded as "pending" rather than falling through to the "alive" default, which would be unsound.
export function aggregateLiveness(statuses: CanaryLiveness[]): CanaryLiveness {
  if (statuses.length === 0) return "pending";
  if (statuses.some((s) => s === "dead")) return "dead";
  if (statuses.some((s) => s === "ailing")) return "ailing";
  if (statuses.some((s) => s === "pending" || s === "disabled")) return "pending";
  return "alive";
}
