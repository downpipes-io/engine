import { b64urlDecode } from "../crypto/bytes.ts";
import { parseVerifier } from "../crypto/keys.ts";
import { type HybridVerifier, hybridVerify } from "../crypto/sign.ts";
import type { Env } from "../env.d.ts";
import { ENGINE_VERSION } from "../format/version.ts";
import { log } from "../log.ts";
import type { UpdateCauseClass } from "./diag-records.ts";
import { UPDATE_CHANNEL_HOST } from "../lib/outbound.ts";

// The update check: PULL a vendor-signed recommended-version channel from inside the
// account and verify it against a pinned release-signer public key (UPDATES.md). The
// vendor never pushes; the engine only reads, and applying an update is operator-driven
// (review the version, then apply from the console, the safe-apply module, update-apply.ts).
// The channel signature uses the same hybrid Ed25519 + ML-DSA-87 scheme as everything else.

// RiskClass is the closed, ordered set of release risk levels. It drives the console tone, the
// dual-control rule (migration/breaking take a second owner when dual control is ON; routine does
// not), and how cautious the operator copy is. A channel may carry it per-artefact; an old channel (or
// any malformed value) is normalised to the safest interpretation by normaliseRiskClass below, never a
// fabricated "routine". The whole channel is signed, so this field is tamper-evident for free.
export type RiskClass = "routine" | "migration" | "breaking";

// ChangelogEntry is one structured change line. type groups it (fix/feature/security/other); text is
// the human one-liner. Structured rather than freeform so the console can group and the parse can bound it.
export interface ChangelogEntry {
  type: string; // fix | feature | security | other (free, displayed as-is; not an authority boundary)
  text: string;
}

// RequiredStep is an explicit user action a release needs. blocking:true means the operator must
// acknowledge the step before the live apply enables: the console renders a blocking step with a "Required"
// badge and, at the apply control (availableUpdateBody), a per-step acknowledgement checkbox that keeps
// Update-now disabled until every blocking step is ticked. The engine deploys only what it verifies
// regardless; the gate is the console honouring the release author's blocking marker so the operator
// cannot sleepwalk past a required action. Non-blocking steps are shown but do not gate. [] when the
// release needs nothing of the operator.
export interface RequiredStep {
  text: string;
  blocking?: boolean;
}

// Artefact is one published build entry. sha384/url are what the safe-apply module needs to FETCH and
// VERIFY the deployable bundle before it is ever uploaded; requiresMigration flags a release the module
// must NOT auto-apply (a Durable Object migration); mainModule names the bundle's ESM entry module.
//
// Rich metadata (all optional and additive: an old channel without them still parses, and every field is
// covered by the same detached hybrid signature over the whole channel, so it is tamper-evident with no new
// trust surface): minEngineVersion is the compat floor (planAndPromote refuses, nothing deployed, when the
// running engine is older); compat is a freeform human note paired with it; riskClass drives the console
// tone and the dual-control rule; changelog/impact/requiredSteps are the structured "what's in this update";
// releasedAt is for "released N days ago" and the staleness alert.
export interface Artefact {
  version: string;
  sha384?: string;
  url?: string;
  notes?: string;
  requiresMigration?: boolean;
  mainModule?: string;
  // ---- Rich, signed metadata (optional, additive) ----
  changelog?: ChangelogEntry[];
  impact?: string[];
  requiredSteps?: RequiredStep[];
  minEngineVersion?: string; // the oldest engine this release may be applied ONTO (semver; refuse-if-older)
  compat?: string; // a human compat note paired with minEngineVersion (e.g. "requires the 0.2 config schema")
  riskClass?: RiskClass; // routine | migration | breaking (default safest via normaliseRiskClass)
  releasedAt?: string; // RFC-3339 when the release shipped (for "released N days ago" + the staleness alert)
  provenance?: ComponentProvenance; // build provenance (optional, additive, inside the signed body)
}

// ComponentProvenance (optional, additive) is one component's build provenance block inside the
// signed channel: which commit and tag the artefact was built from, which CI run built and attested it,
// and where on the channel the verification material lives (channel-relative paths under provenance/,
// so a customer verifies from update.downpipes.io alone, never needing GitHub access). Every field is a
// plain public identifier covered by the same detached hybrid signature as the rest of the channel, so
// the offline release key transitively vouches for the provenance pointers: stripping or swapping them
// requires the pinned key. The signing ceremony (tools/publish-channel.mjs --from-release-dir) refuses to
// sign an artefact whose CI attestation it could not verify, so a present block means "the offline signer
// checked this attestation at signing time"; an absent block is an unattested release and is surfaced
// honestly as such, never invented. rekorLogIndex is the Sigstore Rekor transparency-log entry
// of the artefact's keyless signature (a string: it is an identifier, not a number to do arithmetic on).
export interface ComponentProvenance {
  commit?: string; // the git commit the artefact was built from
  tag?: string; // the signed release tag (vX.Y.Z)
  repo?: string; // owner/name of the source repository
  runId?: string; // the GitHub Actions run that built + attested the artefact
  rekorLogIndex?: string; // Rekor transparency-log index of the keyless signature
  attestations?: {
    intoto?: string; // channel-relative path to the SLSA .intoto.jsonl
    cosignBundle?: string; // channel-relative path to the artefact's cosign bundle
    sums?: string; // channel-relative path to the canonical SHA256SUMS.txt
    releaseRecord?: string; // channel-relative path to release-record.json
  };
}
// ---- channel schema v2: the per-component release map (multi-component updates) --------------------
// ComponentKind is the CLOSED set of deployable component shapes. "worker-module" is a single-module
// Worker bundle deployed via the versions endpoint (the engine; cf-deploy.ts); "static-assets" is an
// assets-manifest + shell-worker deploy (the console; cf-assets-deploy.ts). The union is closed on
// purpose: a kind this engine does not know how to deploy is not a component it may act on, so the
// sanitiser below DROPS an unknown-kind entry (with a logged warning) rather than surfacing something
// the apply path would have to refuse anyway.
export type ComponentKind = "worker-module" | "static-assets";

// UPDATE_COMPONENTS is the closed set of component IDS this build's update pathway can PLAN: the two
// scripts it can deploy, verify and roll back. The channel may name more (a future engine learns them),
// and a release that does is not an error -- but this build cannot plan that component, so it silently
// never updates while the release claims to carry it, which is what the sanitiser below now COUNTS.
// A request naming anything outside this set is refused honestly (parseComponentsRequest).
//
// Lives HERE, with the channel schema, because the sanitiser is the first reader of a component id and
// update-orchestrate.ts already imports this module (the reverse would be an import cycle).
export const UPDATE_COMPONENTS = ["engine", "console"] as const;
export type UpdateComponent = (typeof UPDATE_COMPONENTS)[number];
const UPDATE_COMPONENT_ID_SET: ReadonlySet<string> = new Set(UPDATE_COMPONENTS);

// ComponentArtefact is one component's release entry in the v2 `components` map: the same shape family
// as Artefact (url + sha384 to fetch-and-verify, rich metadata, all covered by the one channel
// signature) plus the deploy `kind` and the component's own version (recommendedVersion stays the
// release version; a console-only release repeats the engine's current version in components.engine).
export interface ComponentArtefact {
  kind: ComponentKind;
  version: string;
  url?: string;
  sha384?: string;
  mainModule?: string;
  riskClass?: RiskClass;
  changelog?: ChangelogEntry[];
  impact?: string[];
  requiredSteps?: RequiredStep[];
  minEngineVersion?: string; // for a non-engine component: the oldest ENGINE this component may pair with
  compat?: string;
  releasedAt?: string;
  notes?: string;
  provenance?: ComponentProvenance; // build provenance (optional, additive, inside the signed body)
}

export interface Channel {
  channel: string;
  recommendedVersion: string;
  // INVARIANT (multi-component updates): artefacts[] is engine-only, forever. Every deployed 0.1.x
  // engine selects artefacts.find(a => a.version === recommendedVersion) and deploys those bytes onto the
  // engine script. A console (or any non-engine) entry placed here with the recommended version would be
  // selected by those engines and its bytes deployed onto the engine worker -- the sha384 would verify (it
  // is that file's true hash), so only the canary would save the customer. Non-engine components ride only
  // in `components` below (invisible to 0.1.x, proven by test/validate-channel-v2-compat.ts); the engine's
  // entry is dual-written here indefinitely so old engines keep updating.
  artefacts?: Artefact[];
  // components (v2, ADDITIVE) is the per-component release map: "engine", "console", and any future
  // component id, each a ComponentArtefact under the SAME detached hybrid signature. Old engines ignore
  // it (isChannelShape tolerates unknown fields; proven by test/validate-channel-v2-compat.ts); new
  // engines PREFER components.engine and fall back to artefacts[] when it is absent. Typed loosely here
  // (the raw parse) and narrowed by sanitiseChannelComponents before anything reads an entry: a
  // malformed map or entry must never break engine-only reading (treated as absent, logged loudly).
  components?: Record<string, ComponentArtefact>;
  // ---- Channel freshness / replay protection (optional, additive, inside the signed body) ----
  // sequence is a vendor-monotonic counter and issuedAt an RFC-3339 publish timestamp. Both are covered by
  // the same detached hybrid signature over the whole channel, so they cannot be stripped or forged without
  // the pinned key. The engine enforces them on the read side (checkChannelFreshness): a descriptor whose
  // sequence regresses below the last-seen one, or whose issuedAt is older than the last-applied one (or an
  // opt-in max-age), is a replay and is refused. They are optional: an old channel without them still parses
  // and applies (absent = "no freshness claim", logged as a warning, never a hard failure), so adding them is
  // backward-compatible. The signer is vendor-side; the engine only reads and enforces.
  sequence?: number;
  issuedAt?: string;
}

// FreshnessClaim is the (sanitised) replay-protection metadata read off a signature-verified channel: the
// monotonic sequence and/or the RFC-3339 issuedAt. Both optional (absent = no claim).
export interface FreshnessClaim {
  sequence?: number;
  issuedAt?: string;
  // The claim the resolver erased. loadVerifiedChannel sanitises a signed claim to well-typed-or-absent,
  // so a present-but-malformed field arrives here as `undefined` and this check cannot tell "the publisher
  // shipped a broken sequence" from "this is an ordinary freshness-less descriptor". The resolver sets
  // these flags on what it erased and records the malformed row itself (at the erasure, so it fires even
  // on an engine with no watermark yet); the check reads them only so it never files an erased claim under
  // the honestly-absent name. Booleans, never a value.
  sequenceMalformed?: boolean;
  issuedAtMalformed?: boolean;
}

// FreshnessState is the engine's persisted last-seen freshness watermark (advanced when a descriptor is
// promoted/ramped, setUpdatePending): the highest sequence and the latest issuedAt the engine has accepted.
// maxAgeMs is the OPT-IN staleness backstop (absent/<=0 = OFF, the default): when set, an issuedAt older than
// `now - maxAgeMs` is refused. It is opt-in precisely so it can NEVER false-positive on a legitimate but
// dormant channel (a vendor that has not shipped a new release in a while); the monotonic checks below carry
// the replay protection on their own and are false-positive-proof for a forward update.
export interface FreshnessState {
  lastSeq?: number;
  lastIssuedAt?: string;
  maxAgeMs?: number;
}

// FreshnessVerdict: ok (optionally with a warning the caller logs) or a typed rejection with a redaction-safe
// reason. A rejection is a hard refusal (the replay/superseded descriptor is never applied).
// degradations: the closed names of the replay-protection weakenings this verdict silently tolerated.
// The verdict itself is unchanged -- backward tolerance is deliberate -- but "was replay protection active
// when that update applied?" has an answer other than a shrug.
export type FreshnessVerdict = { ok: true; warn?: string; degradations?: string[] } | { ok: false; reason: string };

// checkChannelFreshness enforces replay protection on a signature-verified channel descriptor. It refuses
// a descriptor whose sequence REGRESSES below the last-seen sequence, whose issuedAt is OLDER than the
// last-applied issuedAt, or (opt-in maxAgeMs) whose issuedAt is older than the configured maximum age. The
// two monotonic checks are false-positive-proof for a forward update: a genuine newer descriptor carries a
// sequence >= and an issuedAt >= the last accepted, and an EQUAL value is allowed (a same-descriptor retry).
// Backward-tolerant: an ABSENT field is "no freshness claim" -> ok + a warning (NEVER a hard failure, so the
// current freshness-less channel still applies); a PRESENT, parseable field that regresses IS a hard refusal.
// Pure + total; `now` is injected so the validator drives the max-age branch deterministically.
export function checkChannelFreshness(claim: FreshnessClaim, state: FreshnessState, now: number): FreshnessVerdict {
  const warns: string[] = [];
  // The closed names of every replay-protection weakening this check silently tolerated. The verdict is
  // unchanged (a weakened claim is still applied: backward tolerance is deliberate); what changes is that the
  // weakening is now sayable.
  const degradations: string[] = [];
  // ---- sequence: monotonic, never regress (equal is allowed: a same-descriptor retry) ----
  const seq = claim.sequence;
  if (typeof seq === "number" && Number.isFinite(seq)) {
    if (typeof state.lastSeq === "number" && Number.isFinite(state.lastSeq) && seq < state.lastSeq) {
      return { ok: false, reason: `the signed channel's sequence ${seq} is older than the last-seen sequence ${state.lastSeq}; refusing a replayed or superseded update descriptor (nothing was changed)` };
    }
  } else if (typeof state.lastSeq === "number" && claim.sequenceMalformed !== true) {
    // A sequence was seen before but this descriptor declares none: replay protection on it is weaker (the
    // issuedAt/anti-rollback floor still apply). Warn, do not hard-fail (backward tolerance).
    // This branch fires only for a genuinely absent sequence. A claim the resolver erased (malformed) also
    // arrives here as undefined, and the resolver has already counted it, so it is excluded here: an erased
    // claim is never also reported as one the publisher never made.
    degradations.push("update-degraded-freshness-sequence-absent");
    warns.push("the signed channel declares no sequence though one was seen before; sequence-replay protection is weaker for this descriptor");
  }
  // ---- issuedAt: monotonic (never older than the last applied) + opt-in max-age ----
  const issuedAt = claim.issuedAt;
  if (typeof issuedAt === "string" && issuedAt.trim() !== "") {
    const t = Date.parse(issuedAt);
    if (Number.isNaN(t)) {
      // An unparseable issuedAt is silently ignored, so the anti-replay floor it exists to enforce simply
      // does not run for this descriptor, and the apply proceeds looking exactly like a clean one.
      degradations.push("update-degraded-freshness-issuedat-unparseable");
      warns.push("the signed channel declared an unparseable issuedAt; ignoring it for freshness (no usable claim)");
    } else {
      if (typeof state.lastIssuedAt === "string" && state.lastIssuedAt.trim() !== "") {
        const last = Date.parse(state.lastIssuedAt);
        if (!Number.isNaN(last) && t < last) {
          return { ok: false, reason: `the signed channel's issuedAt ${issuedAt} is older than the last-applied ${state.lastIssuedAt}; refusing a replayed or superseded update descriptor (nothing was changed)` };
        }
      }
      if (typeof state.maxAgeMs === "number" && state.maxAgeMs > 0 && now - t > state.maxAgeMs) {
        return { ok: false, reason: `the signed channel's issuedAt ${issuedAt} is older than the configured maximum age; refusing a stale update descriptor (nothing was changed)` };
      }
    }
  } else if (typeof state.lastIssuedAt === "string" && claim.issuedAtMalformed !== true) {
    // Same split as the sequence arm above. The descriptor made no timestamp claim at all, which is
    // the ordinary legacy state and not the publisher shipping a broken one.
    degradations.push("update-degraded-freshness-issuedat-absent");
    warns.push("the signed channel declares no issuedAt though one was seen before; timestamp-replay protection is weaker for this descriptor");
  }
  return {
    ok: true,
    ...(warns.length > 0 ? { warn: warns.join("; ") } : {}),
    ...(degradations.length > 0 ? { degradations } : {}),
  };
}

// UpdateStatus is the status-view projection. It surfaces the recommended artefact's rich metadata
// (additive optional fields) so the console renders "what's in this update" without a second fetch;
// riskClass is always present when verified (normalised to the safest interpretation when the channel
// omits or malforms it), so the console never has to guess the risk.
export interface UpdateStatus {
  configured: boolean;
  verified: boolean;
  currentVersion: string;
  recommendedVersion?: string;
  updateAvailable?: boolean;
  // versionSkew (ADDITIVE, presence-safe: an older engine simply omits it and every existing reader is
  // unchanged) is the three-way fact updateAvailable cannot carry. "ahead" and "uncomparable" are the two
  // states in which updateAvailable is FALSE and "up to date" would be a lie. See versionSkew() above.
  versionSkew?: VersionSkew;
  notes?: string;
  reason?: string;
  // ---- The verdict's own evidence -------------------------------------------------------------------------
  // channelIntended is true when the operator set either channel env var, so the console can tell a customer
  // who wants no updates (both unset: legitimately silent, never a row) from one who configured updates and
  // got them wrong. `configured` cannot carry that distinction: it is this engine's verdict and it goes false
  // for a mangled signer key, a non-https URL and an unparseable URL -- states in which the operator plainly
  // intended to have updates.
  channelIntended?: boolean;
  // channelFault is the closed cause of an unverified consult (UPDATE_CHANNEL_FAULTS). It travels as its own
  // enum rather than leaving the console to re-derive the class by substring-matching `reason`, so a reworded
  // sentence can never silently degrade a recorded row to "unstated". The prose stays for the operator; the
  // enum is what travels.
  channelFault?: UpdateChannelFault;
  // ---- Rich metadata for the recommended version (present only when verified and the field is set) ----
  changelog?: ChangelogEntry[];
  impact?: string[];
  requiredSteps?: RequiredStep[];
  minEngineVersion?: string;
  compat?: string;
  riskClass?: RiskClass; // always set when verified (safest default when the channel omits it)
  releasedAt?: string;
  // compatible is false when the recommended release declares a minEngineVersion NEWER than the running
  // engine, the apply would be REFUSED (planAndPromote enforces it before any deploy). Surfaced so the
  // console can disable the apply honestly rather than letting the owner click into a guaranteed refusal.
  compatible?: boolean;
  // provenance (additive) is the recommended engine artefact's build-provenance block from the
  // signed channel: public identifiers (commit, tag, run, Rekor index) plus channel-relative attestation
  // paths. The one deliberate exception to the "never a url" discipline above: these are the public
  // verification pointers the console exists to show, covered by the channel signature, secret-free.
  provenance?: ComponentProvenance;
  // channelBase (additive) is the public channel directory (UPDATE_CHANNEL_URL minus its filename,
  // trailing slash kept) so the console can resolve the provenance block's channel-relative attestation
  // paths into openable links. A public https url the operator already pinned; never a secret.
  channelBase?: string;
  // components (v2, ADDITIVE) is the per-component release view: one row per component the verified
  // channel declares, carrying NON-SECRET metadata only (richMetadataView's discipline: never a url or a
  // hash -- those stay on the apply path). updateAvailable is set for the ENGINE row only: the engine
  // knows its own running version, but it CANNOT know the console's (the console bundle is code running
  // in the operator's browser); the console SPA compares components.console.recommendedVersion against
  // its own baked version client-side. Old consoles simply ignore the field.
  components?: Record<string, ComponentStatus>;
}

// ComponentStatus is one component's row in UpdateStatus.components (see above): the component's own
// recommended version + the tone/compat metadata the console renders. riskClass is always present
// (normalised to the safest interpretation), matching the release-level field's discipline.
export interface ComponentStatus {
  kind: ComponentKind;
  recommendedVersion: string;
  updateAvailable?: boolean; // ENGINE ONLY: the engine cannot know the console's running version
  versionSkew?: VersionSkew; // ENGINE ONLY, same reason, and the same derivation as the release-level field
  riskClass: RiskClass;
  changelog?: ChangelogEntry[];
  impact?: string[];
  minEngineVersion?: string;
  compat?: string;
  notes?: string;
  provenance?: ComponentProvenance; // public verification pointers (see UpdateStatus.provenance)
}

// RISK_CLASSES is the value-level companion to the RiskClass union (the union cannot be iterated at
// runtime), used by normaliseRiskClass and by tests. Kept in lockstep with RiskClass.
export const RISK_CLASSES: readonly RiskClass[] = ["routine", "migration", "breaking"];

// normaliseRiskClass maps an UNTRUSTED channel value to a RiskClass, defaulting to the SAFEST
// interpretation. "routine" is the LEAST cautious class (no dual control under W5), so an ABSENT or
// MALFORMED riskClass must NOT silently become routine, that would let an old/garbled channel skip the
// second-owner approval. The rule:
//   - a known value ("routine"/"migration"/"breaking") is honoured;
//   - requiresMigration:true forces at least "migration" (a DO migration is never routine), and never
//     downgrades an explicit "breaking";
//   - otherwise (absent / unknown string) -> "migration" (the safe default: treat an unlabelled release as
//     migration-class so it gets the second-owner approval rather than slipping through as routine).
// It is pure and total; the validator drives every branch.
export function normaliseRiskClass(raw: unknown, requiresMigration: boolean): RiskClass {
  const known = typeof raw === "string" && (RISK_CLASSES as readonly string[]).includes(raw) ? (raw as RiskClass) : null;
  if (known === "breaking") return "breaking";
  if (known === "migration") return "migration";
  if (known === "routine") return requiresMigration ? "migration" : "routine"; // a migration is never routine
  // absent or unknown: treat as migration-class (safe default, gets dual control, not skipped as routine).
  return "migration";
}

// compareSemver is a small, conservative semver comparison (the codebase has no existing util). It compares
// the leading MAJOR.MINOR.PATCH numeric triple; a pre-release/build suffix (-rc.1, +meta) is ignored for the
// ordering (a conservative simplification: the compat guard only needs "is the running engine at least
// minEngineVersion", and stripping a suffix can only make the guard more permissive within the same triple,
// never less safe, since a pre-release sorts before its release in strict semver). A missing component is 0
// (so "0.2" == "0.2.0"). A non-numeric / unparseable component makes the whole compare return null (the
// caller must then treat the version as incompatible / refuse, never silently allow). Returns -1, 0, 1, or
// null (uncomparable). Pure.
// VersionSkew is the honest answer to "where is this engine relative to what the channel recommends", and
// it exists because a boolean cannot carry it.
//
// updateAvailable is strictly-newer-only, never a plain inequality: an engine running ahead of its own
// channel -- the emergency downgrade-to-recover pin, and the state any estate reaches once it has moved past
// the channel it consults -- must never report an update as available, since the normal apply path refuses
// to deploy an older recommended version onto a newer running engine.
//
// The four states, and "uncomparable" is the one that matters most.
//   "behind"        the channel recommends a strictly newer version. This is an available update.
//   "current"       the same version. Nothing to do.
//   "ahead"         the engine runs a strictly newer version than the channel recommends. Not an update:
//                   the normal apply refuses it, and going backwards is the Roll back control's job.
//   "uncomparable"  one or both versions do not parse as semver. The engine cannot know which way it is.
//
// Uncomparable is deliberately not folded into "current". Making updateAvailable simply strictly-newer
// would turn an unreadable pair into a silent "up to date", which is a pass reported where a could-not-check
// is the truth. It travels as its own member so the console can say it cannot tell rather than claiming
// either answer.
export type VersionSkew = "behind" | "current" | "ahead" | "uncomparable";

// versionSkew is the ONE derivation. Both call sites below use it, so the release-level verdict and the
// per-component row can never disagree about the same pair of strings.
export function versionSkew(recommended: string, running: string): VersionSkew {
  const cmp = compareSemver(recommended, running);
  if (cmp === null) return "uncomparable";
  if (cmp > 0) return "behind";
  if (cmp < 0) return "ahead";
  return "current";
}

export function compareSemver(a: string, b: string): -1 | 0 | 1 | null {
  const parse = (v: string): [number, number, number] | null => {
    if (typeof v !== "string") return null;
    const core = v.trim().split("+")[0]!.split("-")[0]!; // drop build (+...) and pre-release (-...)
    if (core === "") return null;
    const parts = core.split(".");
    if (parts.length > 3) return null;
    const nums: number[] = [];
    for (const p of parts) {
      if (!/^\d+$/.test(p)) return null; // any non-numeric component => uncomparable (caller refuses)
      const n = Number(p);
      if (!Number.isSafeInteger(n)) return null;
      nums.push(n);
    }
    return [nums[0] ?? 0, nums[1] ?? 0, nums[2] ?? 0];
  };
  const pa = parse(a);
  const pb = parse(b);
  if (pa === null || pb === null) return null;
  for (let i = 0; i < 3; i++) {
    if (pa[i]! < pb[i]!) return -1;
    if (pa[i]! > pb[i]!) return 1;
  }
  return 0;
}

// isEngineCompatible reports whether runningVersion satisfies a release's minEngineVersion floor. No floor
// (undefined/empty) means compatible. An UNPARSEABLE floor or running version is treated as INCOMPATIBLE
// (return false), a release that declares a compat floor we cannot evaluate must be REFUSED, never applied
// blind. Compatible iff running >= minEngineVersion. Pure; used by both the status view (to disable the
// apply honestly) and planAndPromote (the hard refuse-before-deploy guard).
export function isEngineCompatible(runningVersion: string, minEngineVersion: string | undefined): boolean {
  if (minEngineVersion === undefined || minEngineVersion.trim() === "") return true;
  const cmp = compareSemver(runningVersion, minEngineVersion);
  if (cmp === null) return false; // uncomparable -> refuse (do not apply onto an unknown-compat engine)
  return cmp >= 0;
}

// isChannelShape is a narrow boundary check on the parsed channel object. The bytes are signed by the
// vendor, but they are still external input deserialised from JSON, so make the trust boundary explicit:
// channel must be a string, recommendedVersion a non-empty string, and artefacts (when present) an array.
// Anything else is rejected before any downstream caller assumes the shape.
function isChannelShape(v: unknown): v is Channel {
  if (typeof v !== "object" || v === null) return false;
  const c = v as Record<string, unknown>;
  if (typeof c.channel !== "string") return false;
  if (typeof c.recommendedVersion !== "string" || c.recommendedVersion === "") return false;
  if (c.artefacts !== undefined && !Array.isArray(c.artefacts)) return false;
  return true;
}

// COMPONENT_KINDS is the value-level companion to ComponentKind (the union cannot be iterated at
// runtime), used by the sanitiser below and by tests. Kept in lockstep with ComponentKind.
export const COMPONENT_KINDS: readonly ComponentKind[] = ["worker-module", "static-assets"];

// sanitiseChannelComponents narrows the RAW v2 `components` map to well-typed entries, in the same
// fail-safe style as the rest of this boundary: the bytes are signed, but they are still external input,
// and -- the hard rule -- a malformed components map must NEVER break engine-only reading (a 0.1.x-style
// artefacts[] read must keep working whatever this field holds). So nothing here throws or rejects the
// channel: a malformed MAP (not a plain object) is treated as ABSENT, and a malformed ENTRY (not an
// object, no version, an unknown kind) is dropped, each with a loud logged warning naming what was
// dropped. String fields are kept only when they are non-empty strings; the array metadata keeps
// richMetadataView's tolerance (array-or-drop). Pure apart from the warn log; exported for validators.
export function sanitiseChannelComponents(channel: Channel, degraded?: Set<string>): Record<string, ComponentArtefact> | undefined {
  const raw: unknown = channel.components;
  if (raw === undefined) return undefined;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    // "The console update never shows up": a malformed components map is dropped log-only, so the engine
    // silently reverts to the legacy engine-only artefacts[] reading and the console half of the release never
    // ships -- while the update reports success. Workers Logs is the only witness, and remote support cannot
    // read it.
    degraded?.add("update-degraded-components-map-malformed");
    log("warn", "the signed channel's components map is malformed (not an object of entries); ignoring it, engine-only reading continues");
    return undefined;
  }
  const out: Record<string, ComponentArtefact> = {};
  const str = (v: unknown): string | undefined => (typeof v === "string" && v !== "" ? v : undefined);
  for (const [id, entry] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      degraded?.add("update-degraded-component-entry-dropped");
      log("warn", `the signed channel's components entry "${id}" is malformed (not an object); dropping it`);
      continue;
    }
    const e = entry as Record<string, unknown>;
    const version = str(e.version);
    const kind = str(e.kind);
    if (version === undefined || kind === undefined || !(COMPONENT_KINDS as readonly string[]).includes(kind)) {
      // A FUTURE component kind lands here too: this build does not know it, so that component silently never
      // updates while the release claims to carry it.
      degraded?.add("update-degraded-component-entry-dropped");
      log("warn", `the signed channel's components entry "${id}" is malformed (missing version or an unknown kind); dropping it`);
      continue;
    }
    // The unplannable release: the entry is well-formed and is kept (GET /admin/updates shows the
    // operator a row for it), but its ID is outside UPDATE_COMPONENTS, so no apply, settle or rollback in
    // this build can act on it: that component silently never updates while the release says it ships. The
    // only witness is a Workers Log line remote support cannot read. Counted, never refused: forward
    // compatibility with a release that names components a later engine learns is the deliberate design
    // (see UPDATE_COMPONENTS).
    if (!UPDATE_COMPONENT_ID_SET.has(id)) {
      degraded?.add("update-degraded-components-unplannable");
      log("warn", `the signed channel names component "${id}", which this build cannot plan; it will not be updated by this engine`);
    }
    out[id] = {
      kind: kind as ComponentKind,
      version,
      ...(str(e.url) !== undefined ? { url: str(e.url)! } : {}),
      ...(str(e.sha384) !== undefined ? { sha384: str(e.sha384)! } : {}),
      ...(str(e.mainModule) !== undefined ? { mainModule: str(e.mainModule)! } : {}),
      ...(str(e.riskClass) !== undefined ? { riskClass: str(e.riskClass) as RiskClass } : {}),
      ...(Array.isArray(e.changelog) ? { changelog: e.changelog as ChangelogEntry[] } : {}),
      ...(Array.isArray(e.impact) ? { impact: e.impact as string[] } : {}),
      ...(Array.isArray(e.requiredSteps) ? { requiredSteps: e.requiredSteps as RequiredStep[] } : {}),
      ...(str(e.minEngineVersion) !== undefined ? { minEngineVersion: str(e.minEngineVersion)! } : {}),
      ...(str(e.compat) !== undefined ? { compat: str(e.compat)! } : {}),
      ...(str(e.releasedAt) !== undefined ? { releasedAt: str(e.releasedAt)! } : {}),
      ...(str(e.notes) !== undefined ? { notes: str(e.notes)! } : {}),
      ...((() => {
        const p = sanitiseProvenanceBlock(id, e.provenance, degraded);
        return p !== undefined ? { provenance: p } : {};
      })()),
    };
  }
  return Object.keys(out).length > 0 ? out : undefined;
}

// sanitiseProvenanceBlock narrows a raw provenance block to well-typed strings-or-absent. A malformed
// block degrades to absent (with a warning), never drops or fails the release entry it rides on:
// provenance is evidence about a release, not a precondition for applying it (the digest and signature
// checks are the gate). Shared by the v2 components sanitiser and by richMetadataView's legacy
// artefacts[] path, so a signed-but-garbled block can never reach a renderer as a non-string on
// either resolution path.
function sanitiseProvenanceBlock(id: string, v: unknown, degraded?: Set<string>): ComponentProvenance | undefined {
  if (v === undefined) return undefined;
  const str = (x: unknown): string | undefined => (typeof x === "string" && x !== "" ? x : undefined);
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    // The entry stands and its provenance is dropped, so the update applies without the provenance the
    // operator believes is being checked.
    degraded?.add("update-degraded-provenance-dropped");
    log("warn", `the signed channel's "${id}" entry carries a malformed provenance block; ignoring the block (the entry itself stands)`);
    return undefined;
  }
  const p = v as Record<string, unknown>;
  const rawAtt = p.attestations;
  const att = typeof rawAtt === "object" && rawAtt !== null && !Array.isArray(rawAtt) ? (rawAtt as Record<string, unknown>) : undefined;
  const attestations = att
    ? {
        ...(str(att.intoto) !== undefined ? { intoto: str(att.intoto)! } : {}),
        ...(str(att.cosignBundle) !== undefined ? { cosignBundle: str(att.cosignBundle)! } : {}),
        ...(str(att.sums) !== undefined ? { sums: str(att.sums)! } : {}),
        ...(str(att.releaseRecord) !== undefined ? { releaseRecord: str(att.releaseRecord)! } : {}),
      }
    : undefined;
  const outP: ComponentProvenance = {
    ...(str(p.commit) !== undefined ? { commit: str(p.commit)! } : {}),
    ...(str(p.tag) !== undefined ? { tag: str(p.tag)! } : {}),
    ...(str(p.repo) !== undefined ? { repo: str(p.repo)! } : {}),
    ...(str(p.runId) !== undefined ? { runId: str(p.runId)! } : {}),
    ...(str(p.rekorLogIndex) !== undefined ? { rekorLogIndex: str(p.rekorLogIndex)! } : {}),
    ...(attestations !== undefined && Object.keys(attestations).length > 0 ? { attestations } : {}),
  };
  return Object.keys(outP).length > 0 ? outP : undefined;
}

// resolveEngineArtefact is the NEW engine resolution rule: prefer the v2 components.engine entry (when
// present, well-formed and of the engine's deploy kind), fall back to the legacy artefacts[] selection
// (artefacts.find on the recommended version -- exactly what every deployed 0.1.x engine runs). The
// fallback also covers a components.engine entry whose kind is not "worker-module" (that entry could
// never be deployed onto the engine script, so it is treated as unusable and the mirror is used). Pure.
export function resolveEngineArtefact(channel: Channel, degraded?: Set<string>): Artefact | undefined {
  const components = sanitiseChannelComponents(channel, degraded);
  const engine = components?.engine;
  if (engine !== undefined && engine.kind === "worker-module") {
    // ComponentArtefact is a superset of Artefact for the engine's fields (kind aside), so the entry is
    // returned as the artefact record the rest of the pipeline already understands.
    const { kind: _kind, ...artefact } = engine;
    return artefact;
  }
  // The legacy mirror: the engine is about to deploy from artefacts[] rather than the v2 components
  // entry, which can be a different artefact than the one the channel advertises. It is a deliberate,
  // necessary fallback (every deployed 0.1.x engine runs it) and it is also exactly the state in which "we
  // updated and got a build nobody expected" happens, with nothing in the pack saying which path was taken.
  // Only counted when a components map exists and did not yield a usable engine entry -- a channel that
  // carries no components map at all is an ordinary legacy channel, not a degradation.
  if (channel.components !== undefined) degraded?.add("update-degraded-legacy-artefact-fallback");
  return channel.artefacts?.find((a) => a.version === channel.recommendedVersion);
}

// verifyChannel checks the detached hybrid signature over the channel bytes against the
// pinned release signer, then parses and shape-validates the channel. Pure and testable.
export async function verifyChannel(channelBytes: Uint8Array, sig: Uint8Array, signer: HybridVerifier): Promise<Channel | null> {
  const r = await verifyChannelDetailed(channelBytes, sig, signer);
  return r.ok ? r.channel : null;
}

/**
 * verifyChannelDetailed splits verification into three distinct causes rather than a single boolean, because
 * conflating them is actively misleading: a CDN that serves a truncated channel.json and a signature signed
 * by the wrong key are entirely different problems, and reporting both as "signature did not verify under the
 * pinned signer" sends the customer (and support) on a key-pinning chase for a CDN corruption. The three
 * causes need entirely different remediations:
 *
 *   sig-invalid   the bytes are signed by something other than the pinned release signer: a genuine trust
 *                 failure, and the only one that should ever mention the signature.
 *   json-parse    the signature verified and the bytes are not JSON. This is impossible for an intact signed
 *                 document, so it means the bytes changed after signing -- in practice a truncated / corrupted
 *                 CDN object. (It is retained as its own arm rather than folded into sig-invalid because the
 *                 verifier is checked first: reaching here at all is itself the diagnostic.)
 *   shape-invalid valid JSON that is not a channel document: a producer/consumer drift, not a trust failure.
 *
 * The cause is a closed enum member. The bytes, the parse error and the document never leave this function.
 *
 * @param channelBytes - the fetched channel document bytes.
 * @param sig - the detached signature.
 * @param signer - the pinned release verifier.
 * @returns the verified channel, or the closed cause it failed for.
 */
export async function verifyChannelDetailed(
  channelBytes: Uint8Array,
  sig: Uint8Array,
  signer: HybridVerifier,
): Promise<{ ok: true; channel: Channel } | { ok: false; cause: UpdateCauseClass }> {
  if (!(await hybridVerify(signer, channelBytes, sig))) return { ok: false, cause: "sig-invalid" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(channelBytes));
  } catch {
    return { ok: false, cause: "json-parse" };
  }
  return isChannelShape(parsed) ? { ok: true, channel: parsed } : { ok: false, cause: "shape-invalid" };
}

// CHANNEL_CAUSE_REASONS are the operator-facing sentences for each closed channel cause. A single sentence
// naming only the signature would be wrong for two of the three causes below.
const CHANNEL_CAUSE_REASONS: Readonly<Record<string, string>> = {
  "sig-invalid": "channel signature did not verify under the pinned signer",
  "json-parse": "the signed update channel verified but its bytes are not valid JSON; the published document is corrupt or was truncated in transit (this is not a signing-key problem)",
  "shape-invalid": "the signed update channel verified and parsed but is not a channel document this engine understands",
};

// UPDATE_CHANNEL_FAULTS is the closed cause of an unverified channel consult, and it is the field the
// console reads instead of substring-matching the engine's prose. Every failing arm of fetchAndVerifyChannel
// carries one, including the three that answer `configured:false` while both env vars are set.
//
// It is a narrow set of its own rather than the whole UpdateCauseClass, because this is the channel consult's
// vocabulary: these six are the only ways a consult can end badly, and a set the console mirrors should carry
// nothing it cannot receive (a `binding-uncarryable` member on a status read would be dead vocabulary).
//
//   url-config     UPDATE_CHANNEL_URL is absent-with-a-key-set, unparseable, or not https. The operator meant to
//                  configure updates and the address is wrong.
//   key-config     UPDATE_SIGNER_PUBLIC is absent-with-a-url-set, or will not parse as a pinned verifier. The
//                  likeliest real cause is a truncated or whitespace-mangled paste of the base64url key.
//   fetch-failed   the channel host (or its .sig) could not be fetched at all.
//   sig-invalid    the document answered and its signature does not verify under the pinned signer.
//   json-parse     the signature verified and the bytes are not JSON (a corrupt / truncated CDN object).
//   shape-invalid  valid JSON that is not a channel document (producer/consumer drift, not a trust failure).
export const UPDATE_CHANNEL_FAULTS = ["url-config", "key-config", "fetch-failed", "sig-invalid", "json-parse", "shape-invalid"] as const;
export type UpdateChannelFault = (typeof UPDATE_CHANNEL_FAULTS)[number];
const UPDATE_CHANNEL_FAULT_SET: ReadonlySet<string> = new Set(UPDATE_CHANNEL_FAULTS);

// VerifiedChannel is the success shape of fetchAndVerifyChannel; otherwise it returns a reason plus
// whether the channel was at least configured (the two env vars present), mirroring UpdateStatus.
//
// `intended` carries a fact `configured` cannot: `configured` is this engine's verdict (it is false for a
// mangled signer key, for a non-https URL and for an unparseable URL), so a console keying off it alone would
// treat a broken channel exactly like a customer who wants no updates: no chip, no row, a pack byte-identical
// to a healthy one, and an operator frozen on an old release for as long as it takes someone to ask. `intended`
// is the operator's intent (either channel env var is set), which is the only honest way to separate "I did
// not configure updates" from "I configured updates and got it wrong".
type ChannelResult =
  | { ok: true; channel: Channel }
  | { ok: false; configured: boolean; intended: boolean; reason: string; fault?: UpdateChannelFault; cause?: UpdateCauseClass };

// fetchAndVerifyChannel is the single fetch+verify path shared by checkUpdates (the status view) and
// loadVerifiedChannel (the safe-apply artefact resolver), so the trust chain, pinned signer -> channel
// signature -> channel bytes, is identical in both. https-only, redirect:manual (a redirected signed
// fetch cannot be steered elsewhere), pinned-key-only verification.
async function fetchAndVerifyChannel(env: Env, fetchUrl: (u: string) => Promise<Uint8Array | null>): Promise<ChannelResult> {
  // Intent, not verdict. An operator who set either channel env var meant to have updates, so a channel
  // that is half-configured or badly configured is a fault, not a preference. Only an engine with neither var
  // set is legitimately quiet, and that is the one state that must never produce a row (a fault that fires on a
  // customer who simply does not want update notifications is noise, and noise devalues every true row).
  const intended = Boolean(env.UPDATE_CHANNEL_URL) || Boolean(env.UPDATE_SIGNER_PUBLIC);
  if (!env.UPDATE_CHANNEL_URL || !env.UPDATE_SIGNER_PUBLIC) {
    // Half-configured is a MISCONFIGURATION and says which half is missing; neither-configured is a choice.
    const fault: UpdateChannelFault | undefined = !intended ? undefined : env.UPDATE_CHANNEL_URL ? "key-config" : "url-config";
    return { ok: false, configured: false, intended, reason: "updates not configured", ...(fault !== undefined ? { fault } : {}) };
  }
  let channelUrl: URL;
  try {
    channelUrl = new URL(env.UPDATE_CHANNEL_URL);
  } catch {
    return { ok: false, configured: false, intended, reason: "UPDATE_CHANNEL_URL is not a valid URL", fault: "url-config" };
  }
  if (channelUrl.protocol !== "https:") {
    return { ok: false, configured: false, intended, reason: "UPDATE_CHANNEL_URL must use https", fault: "url-config" };
  }
  // The channel is a fixed vendor host. A mirror, a typo or a substituted host is a configuration
  // fault, not a place to fetch from, so nothing is requested from it (the same pin the control plane applies
  // to its own channel reader).
  if (channelUrl.hostname.toLowerCase() !== UPDATE_CHANNEL_HOST) {
    return { ok: false, configured: false, intended, reason: `UPDATE_CHANNEL_URL must be on ${UPDATE_CHANNEL_HOST}`, fault: "url-config" };
  }
  let signer: HybridVerifier;
  try {
    signer = parseVerifier(b64urlDecode(env.UPDATE_SIGNER_PUBLIC));
  } catch {
    return { ok: false, configured: false, intended, reason: "invalid pinned update-signer key", fault: "key-config" };
  }
  const channelBytes = await fetchUrl(env.UPDATE_CHANNEL_URL);
  const sigText = await fetchUrl(`${env.UPDATE_CHANNEL_URL}.sig`);
  if (!channelBytes || !sigText) {
    return { ok: false, configured: true, intended, reason: "could not fetch the update channel", fault: "fetch-failed" };
  }
  // Carry the closed cause (and the sentence that matches it), so the pack -- and the operator -- are never
  // told "signature did not verify" about a truncated CDN object.
  const verified = await verifyChannelDetailed(channelBytes, b64urlDecode(new TextDecoder().decode(sigText).trim()), signer);
  if (!verified.ok) {
    // The three verify causes ARE channel faults, member for member (the membership test is a SET check, not a
    // cast, so a future UpdateCauseClass member added to verifyChannelDetailed cannot leak into this narrower
    // vocabulary). The console reads this instead of substring-matching the sentence beside it, so a reworded
    // reason can no longer silently downgrade the whole class to "unstated".
    const fault = UPDATE_CHANNEL_FAULT_SET.has(verified.cause) ? (verified.cause as UpdateChannelFault) : undefined;
    return {
      ok: false,
      configured: true,
      intended,
      reason: CHANNEL_CAUSE_REASONS[verified.cause] ?? "the signed update channel could not be verified",
      cause: verified.cause,
      ...(fault !== undefined ? { fault } : {}),
    };
  }
  return { ok: true, channel: verified.channel };
}

// richMetadataView projects a signature-verified artefact's rich metadata into the additive UpdateStatus
// fields, normalising riskClass to the safest interpretation. It folds only structured, non-secret release
// metadata (changelog/impact/required-steps/compat), never a download url, artefact hash or token; the one
// deliberate exception is the provenance block, whose channel-relative attestation paths and public
// build identifiers exist precisely to be shown and independently checked. Pure; shared by the status view
// (and any future console pre-render).
function richMetadataView(artefact: Artefact | undefined): Partial<UpdateStatus> {
  const out: Partial<UpdateStatus> = {};
  if (!artefact) {
    // No artefact entry for the recommended version: still report a riskClass so the console never guesses.
    out.riskClass = normaliseRiskClass(undefined, false);
    return out;
  }
  if (Array.isArray(artefact.changelog)) out.changelog = artefact.changelog;
  if (Array.isArray(artefact.impact)) out.impact = artefact.impact;
  if (Array.isArray(artefact.requiredSteps)) out.requiredSteps = artefact.requiredSteps;
  if (typeof artefact.minEngineVersion === "string" && artefact.minEngineVersion !== "") out.minEngineVersion = artefact.minEngineVersion;
  if (typeof artefact.compat === "string" && artefact.compat !== "") out.compat = artefact.compat;
  if (typeof artefact.releasedAt === "string" && artefact.releasedAt !== "") out.releasedAt = artefact.releasedAt;
  // Sanitised even here: the legacy artefacts[] path arrives as the raw parse (only the v2 components
  // map goes through sanitiseChannelComponents), so the block is narrowed before any reader sees it.
  const provenance = sanitiseProvenanceBlock("engine", artefact.provenance);
  if (provenance !== undefined) out.provenance = provenance;
  out.riskClass = normaliseRiskClass(artefact.riskClass, artefact.requiresMigration === true);
  return out;
}

// componentStatusView projects the sanitised v2 components map into the additive UpdateStatus.components
// rows: per-component version + kind + normalised riskClass + the NON-SECRET metadata subset (never a
// url or a hash, matching richMetadataView's discipline). updateAvailable is computed for the ENGINE row
// only -- the engine knows its own running version but cannot know the console's (contract: the console
// SPA compares its baked version against components.console.recommendedVersion client-side). Pure.
function componentStatusView(components: Record<string, ComponentArtefact> | undefined): Record<string, ComponentStatus> | undefined {
  if (components === undefined) return undefined;
  const out: Record<string, ComponentStatus> = {};
  for (const [id, c] of Object.entries(components)) {
    out[id] = {
      kind: c.kind,
      recommendedVersion: c.version,
      // ENGINE ROW ONLY, and through the same derivation as the release-level verdict above, so one screen
      // cannot show two answers about one pair of versions.
      ...(id === "engine" ? { updateAvailable: versionSkew(c.version, ENGINE_VERSION) === "behind", versionSkew: versionSkew(c.version, ENGINE_VERSION) } : {}),
      riskClass: normaliseRiskClass(c.riskClass, false),
      ...(Array.isArray(c.changelog) ? { changelog: c.changelog } : {}),
      ...(Array.isArray(c.impact) ? { impact: c.impact } : {}),
      ...(c.minEngineVersion !== undefined ? { minEngineVersion: c.minEngineVersion } : {}),
      ...(c.compat !== undefined ? { compat: c.compat } : {}),
      ...(c.notes !== undefined ? { notes: c.notes } : {}),
      ...(c.provenance !== undefined ? { provenance: c.provenance } : {}),
    };
  }
  return out;
}

// checkUpdates fetches the channel and its detached signature, verifies, and compares the
// recommended version to the engine's own. fetchUrl is injectable for testing. It surfaces the
// recommended artefact's rich metadata plus a compat verdict (compatible:false when the release's
// minEngineVersion is newer than the running engine, so the console can disable the apply honestly).
// The engine artefact is resolved via resolveEngineArtefact (prefer components.engine, fall back to
// artefacts[]) and the per-component status rows ride along additively (componentStatusView above).
export async function checkUpdates(env: Env, fetchUrl: (u: string) => Promise<Uint8Array | null> = defaultFetch): Promise<UpdateStatus> {
  const r = await fetchAndVerifyChannel(env, fetchUrl);
  if (!r.ok) {
    // The intent flag and the closed fault ride with the refusal, so neither is lost on a failed consult.
    return {
      configured: r.configured,
      verified: false,
      currentVersion: ENGINE_VERSION,
      reason: r.reason,
      channelIntended: r.intended,
      ...(r.fault !== undefined ? { channelFault: r.fault } : {}),
    };
  }
  const recommended = r.channel.recommendedVersion;
  const artefact = resolveEngineArtefact(r.channel);
  const notes = artefact?.notes;
  const meta = richMetadataView(artefact);
  const components = componentStatusView(sanitiseChannelComponents(r.channel));
  const channelBase = channelBaseOf(env.UPDATE_CHANNEL_URL);
  return {
    configured: true,
    verified: true,
    // A verified channel was plainly intended (both env vars are set and the document verified under the pinned
    // signer). Carried on the healthy verdict too so the field is never a fault marker by its presence alone.
    channelIntended: true,
    currentVersion: ENGINE_VERSION,
    recommendedVersion: recommended,
    // updateAvailable is now STRICTLY-NEWER-ONLY, and versionSkew rides beside it so the states the boolean
    // cannot express are not lost. See versionSkew's own header for the incident.
    updateAvailable: versionSkew(recommended, ENGINE_VERSION) === "behind",
    versionSkew: versionSkew(recommended, ENGINE_VERSION),
    ...(notes ? { notes } : {}),
    ...meta,
    compatible: isEngineCompatible(ENGINE_VERSION, meta.minEngineVersion),
    ...(components !== undefined ? { components } : {}),
    // The channel directory, for resolving the provenance block's channel-relative attestation paths
    // into openable links (a public url the operator pinned; UPDATE_CHANNEL_URL is present here because
    // fetchAndVerifyChannel just used it). Derived via URL so a query string is dropped and a path-less
    // url degrades to origin + "/" rather than the bare scheme; an unparseable url yields no base.
    ...(channelBase !== undefined ? { channelBase } : {}),
  };
}

// channelBaseOf resolves the channel DIRECTORY from the configured channel url: origin + the path with
// its final segment removed, always ending in "/". Undefined for an absent or unparseable url. Pure.
function channelBaseOf(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw === "") return undefined;
  try {
    const u = new URL(raw);
    return u.origin + u.pathname.replace(/[^/]*$/, "");
  } catch {
    return undefined;
  }
}

// RecommendedArtefact is the resolved, signature-verified artefact the safe-apply module will fetch and
// deploy: the version + its url + its sha384 (both required to download and verify it) + the safety
// flags. currentVersion lets the route short-circuit when already up to date.
export interface RecommendedArtefact {
  recommendedVersion: string;
  currentVersion: string;
  artefact: Artefact;
  // The channel's freshness claim (sanitised to well-typed-or-absent), echoed so the safe-apply route
  // can both enforce replay protection (checkChannelFreshness) and advance the persisted watermark on promote.
  sequence?: number;
  issuedAt?: string;
  // The claim was made and was unusable, so it was erased above. Carried so the freshness check does
  // not report an erased claim as a claim the publisher never made (the two have opposite remediations: a
  // publisher-side bug versus an ordinary legacy descriptor). The malformed count is recorded at the
  // erasure itself, because it must fire on an engine that has no watermark yet.
  sequenceMalformed?: true;
  issuedAtMalformed?: true;
  // v2 (ADDITIVE): the resolved CONSOLE component, present only when the verified channel carries a
  // well-formed components.console entry of kind "static-assets" WITH the url + sha384 needed to
  // download and verify its bundle (an unverifiable component is never offered for apply, the same rule
  // the engine artefact obeys). consoleIssue carries the honest reason when the channel had SOME console
  // entry that could not be offered (wrong kind / missing url or sha384), so a console-targeting apply
  // can refuse with the real story instead of "this release has no console component".
  console?: ComponentArtefact;
  consoleIssue?: string;
}

// ChannelLoadError is loadVerifiedChannel's failure shape: the operator sentence, plus the CLOSED cause the
// update-fault ring records under. The cause is always present, because a channel consult that ends badly
// always ends badly in one of the named ways; a caller must never have to parse the sentence to find out.
export interface ChannelLoadError {
  error: string;
  causeClass: UpdateCauseClass;
}

// channelFaultCause maps a failed channel consult onto the update-fault ring's closed cause. The three VERIFY
// causes already arrive as UpdateCauseClass members (fetchAndVerifyChannel sets them); the config and fetch
// arms carry only the narrower UpdateChannelFault, so they are lifted here.
//
// `fetch-failed` becomes `other`, deliberately and not `network`: defaultFetch collapses a 404, a 5xx and a
// DNS failure into one null, so this engine genuinely DOES NOT KNOW which of them happened, and a confident
// `network` row would send an operator to check their egress for a CDN 404. A residual class that admits the
// coarseness is the honest answer; the ring's httpStatus field stays absent, which says the same thing again.
function channelFaultCause(r: { cause?: UpdateCauseClass; fault?: UpdateChannelFault }): UpdateCauseClass {
  if (r.cause !== undefined) return r.cause;
  if (r.fault === "url-config" || r.fault === "key-config") return r.fault;
  return "other";
}

// loadVerifiedChannel resolves the recommended artefact from the SIGNATURE-VERIFIED channel for the
// safe-apply module. It returns the artefact entry for recommendedVersion (carrying url + sha384 +
// requiresMigration + mainModule), or an { error } when updates are not configured, the channel does not
// verify, the recommended artefact is absent, or it lacks the url/sha384 needed to download and verify a
// deployable bundle (an unverifiable artefact is never offered for apply). fetchUrl is injectable.
export async function loadVerifiedChannel(env: Env, fetchUrl: (u: string) => Promise<Uint8Array | null> = defaultFetch, degraded?: Set<string>): Promise<RecommendedArtefact | ChannelLoadError> {
  const r = await fetchAndVerifyChannel(env, fetchUrl);
  // The closed cause rides with the error so the router can record why without ever reading the
  // sentence (a channel that 404s, a truncated document and a wrong signer are three different remediations).
  // The return type carries causeClass on every failure path, and channelFaultCause below fills the arms
  // that only had a `fault`.
  if (!r.ok) return { error: r.reason, causeClass: channelFaultCause(r) };
  const recommended = r.channel.recommendedVersion;
  // v2 engine resolution: prefer components.engine, fall back to the legacy artefacts[] selection.
  // The sanitiser records every entry it drops and every fallback it takes into `degraded`, which the
  // router (which holds the scheduler stub this pure module deliberately does not) folds into the pack.
  const artefact = resolveEngineArtefact(r.channel, degraded);
  // Both of these are `shape-invalid`, precisely: the document verified under the pinned signer and then
  // failed to be a usable channel -- it recommends a version it lists no artefact for, or lists one that
  // cannot be downloaded and verified. That is a publisher-side producer/consumer drift, never a trust
  // failure and never anything the customer can fix; reporting it as a signature or transport fault would
  // send support to the customer's egress for a fault in the release.
  if (!artefact) return { error: `the signed channel recommends ${recommended} but lists no artefact for it`, causeClass: "shape-invalid" };
  if (typeof artefact.url !== "string" || artefact.url === "" || typeof artefact.sha384 !== "string" || artefact.sha384 === "") {
    return { error: `the signed channel's artefact for ${recommended} is missing the url and/or sha384 needed to download and verify it; it cannot be auto-applied`, causeClass: "shape-invalid" };
  }
  // v2: resolve the console component from the SAME verified document (one signature, one release truth).
  // A console entry that cannot be fetch-verified (wrong kind, missing url/sha384) is never offered; the
  // reason rides in consoleIssue so a console-targeting apply refuses with the real story.
  const components = sanitiseChannelComponents(r.channel, degraded);
  const consoleEntry = components?.console;
  let consoleComponent: ComponentArtefact | undefined;
  let consoleIssue: string | undefined;
  if (consoleEntry !== undefined) {
    if (consoleEntry.kind !== "static-assets") {
      consoleIssue = `the signed channel's console component declares kind "${consoleEntry.kind}" but the console deploys as static assets; it cannot be applied by this engine`;
    } else if (typeof consoleEntry.url !== "string" || consoleEntry.url === "" || typeof consoleEntry.sha384 !== "string" || consoleEntry.sha384 === "") {
      consoleIssue = `the signed channel's console component for ${consoleEntry.version} is missing the url and/or sha384 needed to download and verify it; it cannot be auto-applied`;
    } else {
      consoleComponent = consoleEntry;
    }
  }
  // Sanitise the (signed) channel freshness claim to well-typed-or-absent so the caller enforces and advances
  // it safely (a malformed value is treated as absent).
  //
  // This is the erasure point, and it is where the malformed count must be recorded. The apply route's
  // freshness check runs on the sanitised claim, so it can only ever see "absent" and could never say that a
  // claim had been made and thrown away. The harm is not hypothetical: with the opt-in max-age staleness
  // guard on and an issuedAt shipped as an epoch number, the guard runs on nothing, a stale descriptor that
  // would have been refused is applied, and the pack carries exactly what a fully-protected apply carries.
  // Recording it here means the count fires whether or not the engine has ever seen a watermark.
  // A count under a closed name; the malformed value itself never leaves this function.
  // Read the two claims as the UNKNOWN they really are: Channel's `sequence?: number` / `issuedAt?: string` is
  // a claim about a document this engine did not write, and the whole point of this block is the case where
  // the document disagrees with the type.
  const rawSequence: unknown = (r.channel as { sequence?: unknown }).sequence;
  const rawIssuedAt: unknown = (r.channel as { issuedAt?: unknown }).issuedAt;
  const sequence = typeof rawSequence === "number" && Number.isFinite(rawSequence) ? rawSequence : undefined;
  const issuedAt = typeof rawIssuedAt === "string" && rawIssuedAt.trim() !== "" ? rawIssuedAt : undefined;
  const sequenceMalformed = rawSequence !== undefined && rawSequence !== null && sequence === undefined;
  const issuedAtMalformed = rawIssuedAt !== undefined && rawIssuedAt !== null && issuedAt === undefined;
  if (sequenceMalformed) degraded?.add("update-degraded-freshness-sequence-malformed");
  if (issuedAtMalformed) degraded?.add("update-degraded-freshness-issuedat-unparseable");
  return {
    recommendedVersion: recommended,
    currentVersion: ENGINE_VERSION,
    artefact,
    ...(sequence !== undefined ? { sequence } : {}),
    ...(issuedAt !== undefined ? { issuedAt } : {}),
    ...(sequenceMalformed ? { sequenceMalformed: true as const } : {}),
    ...(issuedAtMalformed ? { issuedAtMalformed: true as const } : {}),
    ...(consoleComponent !== undefined ? { console: consoleComponent } : {}),
    ...(consoleIssue !== undefined ? { consoleIssue } : {}),
  };
}

async function defaultFetch(u: string): Promise<Uint8Array | null> {
  // redirect:"manual" means the runtime returns a status 3xx opaque-redirect response
  // rather than silently following to another host. Treat any non-2xx (including 3xx)
  // as a failure so a redirected signed-update fetch cannot be steered elsewhere.
  const r = await fetch(u, { redirect: "manual" });
  if (!r.ok) return null;
  return new Uint8Array(await r.arrayBuffer());
}
