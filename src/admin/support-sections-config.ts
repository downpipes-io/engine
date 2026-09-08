// Support-pack section gatherers: the config / licence / keys / dest / sources domain (the
// CONFIG_WRAP_KEY decrypt health, the vendor-beacon outcome, the config-integrity OBSERVE
// signals, the licence activation-refusal + tracked-expiry rows, the detached source
// bindings, the resolved destination write settings, and the key-material health block).
// Moved verbatim out of support.ts, which assembles the bundle from these gatherers; each
// keeps its original redaction contract (see the per-function comments). Behaviour is
// unchanged.

import { BEACON_FAIL_CLASSES } from "../cron/cron-fault-ledger.ts";
import { recipientFingerprint } from "../crypto/capsule.ts";
import { classifyEnvDestAnomalies, DEST_CONFIG_ANOMALIES } from "../dest/config-anomalies.ts";
import { STORAGE_CLASSES } from "../dest/factory-validators.ts";
import { DEFAULT_DEST_RATE_PER_SEC } from "../dest/pace.ts";
import { resolveAddressing } from "../dest/s3-addressing.ts";
import type { Env } from "../env.d.ts";
import { buildKeyMaterialHealth, loadRecipientPublic } from "../keys-env.ts";
import { TEST_DELETE_PROBES } from "../sched/sched-fault-ledger.ts";
import type { DownpipeConfig } from "../sched/types.ts";
import { CHAIN_BREAK_CAUSES } from "./audit-types.ts";
import { canOpenConfigSecret, configWrapKeyCheckValue, isWrappedSecret, loadConfigWrapKey, type WrappedSecret } from "./config-secret.ts";
import { ATTACH_FAULT_CLASSES, ATTACH_OPS, ATTACH_REFUSALS_CAP, attachRefusalOf, DISCOVERY_OUTCOMES, DISCOVERY_PRODUCTS, DISCOVERY_TOKEN_SET_FAIL_CLASSES, DISCOVERY_TOKEN_SET_OUTCOMES } from "./discovery-health.ts";
import { OWNER_ACTION_KINDS } from "./owner-action.ts";
import { planRosterReattach } from "./roster-reattach.ts";
import { doURL } from "../do-url.ts";
import { enumerateBoundSources } from "./router-sources.ts";
import { clampInt, gateClosed } from "./support-shared.ts";

// BEACON_FAIL_CLASS_SET re-gates the beacon's error class at the PACK boundary against the SAME closed set the
// cron classifies into, so the pack's gate and the classifier cannot drift apart (G324).
const BEACON_FAIL_CLASS_SET: ReadonlySet<string> = new Set(BEACON_FAIL_CLASSES);

// fetchWrapKeyHealth probes whether the configured CONFIG_WRAP_KEY can still DECRYPT the destination
// credentials it wrapped (CPR: wrapkey-rotated-recovery-unrecoverable). A rotated-wrong or removed wrap key
// leaves every encrypted-at-rest dest credential undecryptable -- so a control-plane recovery restores an
// UNUSABLE credential (the run then fails loud, but the operator cannot tell "rotate the key back" from
// "re-enter the credential" without this). It reuses the no-custody export slice (each dest secret already
// projected to a WrappedSecret envelope or a reestablish marker -- never plaintext) and verifies ONE
// envelope opens: the CLASS (ok / wrong-key / missing-key / malformed-key / no-envelopes) is the whole
// signal. SECURITY (keys review, item 5b): the check goes through canOpenConfigSecret, which
// never decodes the plaintext to a string and zero-fills the transient buffer -- the probe holds a VERDICT,
// never a value. (The same envelope is opened by resolveConfigSecret on every run/preflight in this same
// isolate, so this adds no new exposure class; a canary-envelope refit was reviewed and rejected: legacy
// envelopes would keep the real-open fallback alive anyway, for write-path churn with no risk reduction.)
// Redaction-safe (a closed class + an int). Best-effort {}.
export async function fetchWrapKeyHealth(env: Env, scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/control-plane/export"), { method: "GET" });
    const j = (await r.json()) as { destinations?: Array<{ secret?: unknown }> };
    const dests = Array.isArray(j.destinations) ? j.destinations : [];
    const envelopes = dests.map((d) => d.secret).filter((s): s is { wrapped: WrappedSecret } => typeof s === "object" && s !== null && isWrappedSecret((s as { wrapped?: unknown }).wrapped));
    const encryptedDestCount = envelopes.length;
    if (encryptedDestCount === 0) return { class: "no-envelopes", encryptedDestCount: 0 };
    // Envelopes exist: is a wrap key configured, and does it decrypt them?
    let key: Uint8Array | undefined;
    try {
      key = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
    } catch {
      // loadConfigWrapKey throws on a present-but-malformed key (wrong length): the credentials are unrecoverable.
      return { class: "malformed-key", encryptedDestCount };
    }
    if (key === undefined) return { class: "missing-key", encryptedDestCount };
    // Verdict-only open: no plaintext string is ever materialised; the transient buffer is zeroed inside.
    if (await canOpenConfigSecret(key, envelopes[0]!.wrapped)) return { class: "ok", encryptedDestCount };
    // Well-formed envelope + a present key that does not open it = the key was rotated after the wrap.
    return { class: "wrong-key", encryptedDestCount };
  }
}

// fetchBeaconState pulls the last opt-in vendor-beacon POST outcome (cron/beacon-emit.ts records it after
// each attempt): whether it succeeded, when, and the coarse HTTP status. It complements the env-presence
// `configured` flag the bundle computes: together they answer "is the beacon ON, and is it reaching the
// vendor?" (beacon-off-no-corroboration + beacon-post-lost) -- the licence-ledger corroboration signal.
// Redaction-safe (a bool + a timestamp + a clamped int). Best-effort: {} on failure or when the beacon has
// never emitted (honest absence, e.g. the beacon is off so nothing was ever posted).
//
// G324: the last attempt alone could not tell an INTERMITTENT beacon from a dead one -- "ok, fail, ok, fail" and
// "fail, fail, fail" are different tickets and both read as a single lastOk:false. `recent` is the last 5
// attempts, and `errorClass` is the closed class the cron ALREADY computed and then threw away (url-invalid is
// a typo'd BEACON_URL, a permanent one-line fix; network will heal; do-read means the beacon never even got its
// payload). The BEACON_URL and the ingest key are never parameters of the record and can never be stored.
const BEACON_RECENT_CAP = 5;
export async function fetchBeaconState(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const r = await scheduler.fetch(doURL("/beacon-state"), { method: "GET" });
    const j = (await r.json()) as { at?: unknown; ok?: unknown; status?: unknown; errorClass?: unknown; recent?: unknown } | null;
    if (j === null || typeof j !== "object") return {};
    const status = (v: unknown): number | undefined => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(999, Math.floor(v))) : undefined);
    // The class is re-gated at the pack boundary against the same closed set the cron classifies into (the DO
    // already re-validates it on the way in): an out-of-vocabulary value is DROPPED, never coerced, so no
    // caller string can ride through this seam.
    const cls = (v: unknown): string | undefined => (typeof v === "string" && BEACON_FAIL_CLASS_SET.has(v) ? v : undefined);
    const recent = (Array.isArray(j.recent) ? j.recent : []).slice(-BEACON_RECENT_CAP).map((raw) => {
      const a = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
      return {
        ok: a.ok === true,
        ...(typeof a.at === "number" && Number.isFinite(a.at) ? { at: Math.max(0, Math.floor(a.at)) } : {}),
        ...(status(a.status) !== undefined ? { status: status(a.status) } : {}),
        ...(cls(a.errorClass) !== undefined ? { errorClass: cls(a.errorClass) } : {}),
      };
    });
    return {
      ...(typeof j.ok === "boolean" ? { lastOk: j.ok } : {}),
      ...(typeof j.at === "number" && Number.isFinite(j.at) ? { lastAt: j.at } : {}),
      ...(status(j.status) !== undefined ? { lastStatus: status(j.status) } : {}),
      ...(cls(j.errorClass) !== undefined ? { errorClass: cls(j.errorClass) } : {}),
      ...(recent.length > 0 ? { recent } : {}),
    };
  }
}

// LICENCE_REFUSAL_CODE_SET is the CLOSED vocabulary of licence-activation refusal reason codes the pack will
// forward (failed-activation-no-trace): the LicenceReasonCode union plus "malformed-token". Anything else is
// dropped (defence in depth on the redaction), so a licence value can never ride into the pack via this field.
// "internal-error" (G081) is the newest member and is LOAD-BEARING: both licence backstop catches used to
// report an ENGINE regression as "body-malformed", i.e. as a CORRUPT CUSTOMER TOKEN, sending support to chase
// a token that was always fine. Omitting it here would silently DROP the new code at the pack boundary -- the
// exact out-of-vocabulary drop this gate exists to make visible -- and the fix would regress invisibly.
// VOCABULARY-DRIFT: "internal-error" was here and NOT in the DO's own
// LICENCE_REFUSAL_REASON_CODES, so the drop this comment warns about was already happening one layer
// earlier, where it also cost the bounded refusal ring its entry. Both sets now carry it, and both carry
// "supersedes-current-term" (the term-regression refusal on POST /admin/licence: a signed, unexpired token
// whose term ends earlier than the active licence). Neither is a verify outcome, so neither is a member of
// the LicenceReasonCode union, exactly like "malformed-token".
const LICENCE_REFUSAL_CODE_SET: ReadonlySet<string> = new Set([
  "no-token", "no-pin", "pin-invalid", "segments", "decode", "signature", "body-malformed",
  "not-canonical", "unparseable-expiry", "future-tier", "expired", "malformed-token", "internal-error",
  "supersedes-current-term",
]);

// fetchConfigIntegrity pulls the three CONFIG-domain OBSERVE signals into one redaction-safe pack block:
//   - snapshotFailures (config-snapshot-best-effort-gap): the cumulative count of config auto-snapshot captures
//     that FAILED and were swallowed to a log line, so a config change that silently never got versioned is
//     visible. Surfaced only when > 0.
//   - history (config-history-session-key-regen): the config-history chain verify verdict, surfaced ONLY when
//     it is NOT intact or the in-DO signing key has ROTATED -- signingKeyRotated distinguishes a key rotation
//     (recoverable) from a genuine brokenAt (content tamper), so a failed config-history verify is diagnosable.
//   - changeControlRefusals (change-number-required-refusal): the cumulative count of change-controlled actions
//     refused for want of a valid change reference -- read WITHOUT touching the CR ledger (a refusal records no
//     change-recorded entry) -- plus the last time and the closed action-kind label. Surfaced only when > 0.
// Every field is a count / timestamp / boolean / id / closed label; no secret, no snapshot, no operator value.
// Each sub-read is independent + best-effort; a failing or clean one is simply omitted (honest absence).
export async function fetchConfigIntegrity(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = {};
  // unavailableProbes (G031): each sub-read below is independent + best-effort, but a FAULTED sub-read used to
  // be omitted byte-identically to a clean one (honest absence). Record which sub-probe could not be read (a
  // closed probe name, never an error detail) so a diagnoser can tell "the config chain is intact" from "the
  // config-history probe faulted". Only faulted probes are listed; an all-clean read carries nothing.
  // A THROW IS NOT THE ONLY WAY A SUB-READ FAILS TO ANSWER. Two of the three read a stored {count,lastAt}
  // marker whose defensive reader coerces a present-but-malformed record to ZERO, and both surface their block
  // only above zero -- so a corrupt marker answered 200 and landed in the same silence as a clean account. The
  // DO now says `coerced` on the wire and those land here too, which is the whole point of this list.
  const unavailableProbes: string[] = [];
  try {
    const j = (await (await scheduler.fetch(doURL("/config-snapshot-health"), { method: "GET" })).json()) as { count?: unknown; lastAt?: unknown; coerced?: unknown };
    const count = typeof j.count === "number" && Number.isFinite(j.count) ? Math.max(0, Math.min(1_000_000_000, Math.floor(j.count))) : 0;
    if (count > 0) out.snapshotFailures = { count, ...(typeof j.lastAt === "string" ? { lastAt: j.lastAt.slice(0, 40) } : {}) };
    // A COERCED read is an unavailable probe, not a clean one. The block above surfaces only above zero, so a
    // marker that EXISTS and read back malformed lands in the same silence as an account that never had a
    // snapshot fail -- which is precisely the distinction unavailableProbes was added to make. A throw is not
    // the only way a sub-read can fail to answer; a defensive coercion is the quiet way.
    else if (j.coerced === true) unavailableProbes.push("config-snapshot");
  } catch {
    unavailableProbes.push("config-snapshot");
  }
  try {
    const j = (await (await scheduler.fetch(doURL("/config-history-health"), { method: "GET" })).json()) as { count?: unknown; bodies?: unknown; verify?: unknown };
    const v = (typeof j.verify === "object" && j.verify !== null ? j.verify : {}) as { intact?: unknown; brokenAt?: unknown; signingKeyRotated?: unknown; unkeyedIntact?: unknown; unkeyedCause?: unknown; unkeyedBrokenAt?: unknown; verifyFaulted?: unknown; headTruncated?: unknown; headTruncatedAt?: unknown; earliestId?: unknown };
    // THE CONFIG CHAIN'S ROLLOVER, DERIVED THE WAY THE AUDIT CHAIN ALREADY DERIVES ITS OWN.
    //
    // `CONFIG_HISTORY_CAP` is 2,000 and the rollover that enforces it is CORRECT: it prunes, and the chain
    // still verifies afterwards. So `intact` stays true, no key rotated, no tail was deleted and no body is
    // missing on a rolled-over chain, which on its own would omit any signal that a rollover had happened at
    // all -- even though `earliestId` is already computed by the verifier and available to derive it from.
    //
    // THE AUDIT CHAIN CARRIES THIS SIGNAL ALREADY. `verifyAudit` derives `rolledOver` from `earliestSeq > 1`
    // and `status.ts` carries `auditNearCap` and `auditRolledOverCount`, documented as how many entries the
    // rollover has ALREADY DESTROYED. The config chain carries the equivalent signal here, on a chain whose
    // entries are SIGNED VERSIONS a customer may ask to roll back to.
    //
    // WHAT IS DERIVED AND WHAT IS NOT, STATED RATHER THAN BLURRED. `rolledOver` is `earliestId > 1`, and
    // `rolledOverAtLeast` is `earliestId - 1`, which is EXACT while the id space is contiguous from 1 and is
    // named as a lower bound because nothing here can prove that it is. It is a DERIVATION and not a stored
    // record, and the audit chain deliberately keeps BOTH because a derivation has nothing to read once the log
    // empties. That objection does not reach this surface: the cap RETAINS 2,000 versions, so this chain cannot
    // empty while it has ever rolled over. A stored config-rollover record is still the better answer and it is
    // a DO change this projection cannot make; what it can do is stop the pack answering as though the
    // destroyed versions never existed.
    const earliestId = clampInt(v.earliestId, 1_000_000);
    const rolledOver = earliestId !== undefined && earliestId > 1;
    // G098: the BODY-RETENTION scan. The block above is about the chain's HEADERS; this is about whether the
    // SNAPSHOT each header promises is still there. `listed` is the number of versions the console offers as
    // restorable, `readable` is how many of them you could ACTUALLY roll back to, and any gap between the two
    // is a false assurance the operator discovers in the middle of an incident. Counts and engine-minted
    // version ids only: not one field of a snapshot (which holds downpipe names, role e-mails, notify channels)
    // is projected.
    const b = (typeof j.bodies === "object" && j.bodies !== null ? j.bodies : {}) as Record<string, unknown>;
    const listed = clampInt(b.listed, 1_000_000);
    const readable = clampInt(b.readable, 1_000_000);
    const missing = clampInt(b.missing, 1_000_000) ?? 0;
    const unreadable = clampInt(b.unreadable, 1_000_000) ?? 0;
    const bodyGap = missing + unreadable;
    const bodies = listed !== undefined && readable !== undefined
      ? {
          listed,
          readable,
          missing,
          unreadable,
          ...(clampInt(b.firstDefectiveId, 1_000_000) !== undefined ? { firstDefectiveId: clampInt(b.firstDefectiveId, 1_000_000) } : {}),
          ...(clampInt(b.newestDefectiveId, 1_000_000) !== undefined ? { newestDefectiveId: clampInt(b.newestDefectiveId, 1_000_000) } : {}),
        }
      : undefined;
    // Only surface the history block when there is something to diagnose: a broken chain, a rotated signing key
    // (which is WHY an otherwise-fine chain now fails to verify), a version whose BODY is gone (a rollback
    // point the console still lists and the engine can no longer produce), or a DELETED TAIL. A healthy,
    // fully-restorable history needs no pack surface.
    //
    // headTruncated IS THE ARM THAT WAS MISSING, and it is the one that matters most (G313, R7). The keyed verify
    // recomputes over the RETAINED versions, so deleting the NEWEST ones leaves it reading intact:true -- and on
    // an otherwise-healthy estate every arm of this condition was false, so the block was OMITTED ENTIRELY. A
    // truncated config history therefore produced a configIntegrity section with nothing in it, the pack's own
    // headline read clean, and the latch in schedDiag.chainBreaks was the only thing in the bundle that knew.
    if (v.intact !== true || v.signingKeyRotated === true || v.headTruncated === true || bodyGap > 0 || rolledOver) {
      out.history = {
        intact: v.intact === true,
        // rolledOver rides BESIDE intact for the same reason headTruncated does: a chain can be perfectly
        // linked and still be missing everything before `earliestId`, and `intact: true` must not stand alone
        // against a loss the same call established. `earliestId` is carried with it so a reader can see WHICH
        // versions survive rather than only that some do not.
        // All three ride TOGETHER and only where a rollover happened, which is the one state they mean
        // anything in: on a chain that has never rolled over `earliestId` is 1 by construction and adds a key
        // to every pack to say nothing. `validate-dataloss-evidence.ts` holds this block to a CLOSED key set
        // and went red on the first draft of this repair, which is that gate doing exactly its job; the key
        // set it allows now names these three, and this is the narrower emit that goes with it.
        ...(rolledOver ? { rolledOver: true, rolledOverAtLeast: (earliestId ?? 1) - 1, earliestId } : {}),
        // The head anchor's verdict, beside the recompute's. `intact:true` may not stand alone next to a
        // truncation the same call established: the recompute is structurally blind to a removed tail, and this
        // is the witness that is not. A boolean and the anchored head id, both engine-minted.
        ...(v.headTruncated === true ? { headTruncated: true } : {}),
        ...(v.headTruncated === true && clampInt(v.headTruncatedAt, 1_000_000) !== undefined ? { headTruncatedAt: clampInt(v.headTruncatedAt, 1_000_000) } : {}),
        ...(typeof j.count === "number" && Number.isFinite(j.count) ? { versions: Math.max(0, Math.min(1_000_000, Math.floor(j.count))) } : {}),
        ...(typeof v.brokenAt === "number" && Number.isFinite(v.brokenAt) ? { brokenAt: Math.max(0, Math.floor(v.brokenAt)) } : {}),
        ...(v.signingKeyRotated === true ? { signingKeyRotated: true } : {}),
        // G313 (R5): WHAT THE KEY-FREE EVIDENCE SAYS. The keyed verify stops at the first break, so a rotated or
        // deleted in-DO key (one owner button: terminate-all-sessions) fails version 1's digest and the block
        // said signingKeyRotated with no further comment -- IDENTICAL whether the rest of the chain was pristine
        // or the attacker's. The content hashes, the parent links and the id contiguity need no key; unkeyedIntact
        // is what they found over the WHOLE chain, and unkeyedCause/unkeyedBrokenAt name the first thing they
        // caught. Carried only when the key HAS drifted (there is nothing to qualify otherwise). A boolean, a
        // closed cause and a clamped id.
        ...(typeof v.unkeyedIntact === "boolean" ? { unkeyedIntact: v.unkeyedIntact } : {}),
        ...(typeof v.unkeyedCause === "string" && CHAIN_BREAK_CAUSE_SET.has(v.unkeyedCause) ? { unkeyedCause: v.unkeyedCause } : {}),
        ...(clampInt(v.unkeyedBrokenAt, 1_000_000) !== undefined ? { unkeyedBrokenAt: clampInt(v.unkeyedBrokenAt, 1_000_000) } : {}),
        // verifyFaulted (G098): the chain could not be CHECKED at all, which is a different and worse statement
        // than "the chain is broken at version N" -- and the usual cause is precisely a body that is gone, since
        // the verify has to hash it.
        ...(v.verifyFaulted === true ? { verifyFaulted: true } : {}),
        ...(bodies !== undefined ? { bodies } : {}),
      };
    }
  } catch {
    unavailableProbes.push("config-history");
  }
  try {
    const j = (await (await scheduler.fetch(doURL("/change-control/refusals"), { method: "GET" })).json()) as { count?: unknown; lastAt?: unknown; lastActionKind?: unknown; coerced?: unknown };
    const count = typeof j.count === "number" && Number.isFinite(j.count) ? Math.max(0, Math.min(1_000_000_000, Math.floor(j.count))) : 0;
    if (count > 0) out.changeControlRefusals = { count, ...(typeof j.lastAt === "string" ? { lastAt: j.lastAt.slice(0, 40) } : {}), ...(typeof j.lastActionKind === "string" ? { lastActionKind: j.lastActionKind.slice(0, 64) } : {}) };
    // Same reason as config-snapshot above: the coerced zero is an ABSENT block, and this is the block a
    // compliance reader consults to answer "was any change ever refused for want of a change number?".
    else if (j.coerced === true) unavailableProbes.push("change-control-refusals");
  } catch {
    unavailableProbes.push("change-control-refusals");
  }
  if (unavailableProbes.length > 0) out.unavailableProbes = unavailableProbes;
  return out;
}

// fetchLicenceActivationRefusals pulls the cumulative console licence-activation refusal tally (failed-
// activation-no-trace): a customer insisting "I pasted my licence but it still says community" is otherwise
// undiagnosable because the verify-before-store refusal records NOTHING. Surfaces the count, the last refusal
// time, and the last CLOSED reason code (only a member of the licence reason-code vocabulary reaches the pack;
// anything else is dropped, defence in depth), so support can tell a typo from an expired token from a
// future-tier token. Redaction-safe (a count + a timestamp + a closed code). Best-effort: {} on failure OR
// when no activation has ever been refused (honest absence), so a clean account reads nothing here.
export async function fetchLicenceActivationRefusals(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  try {
    const j = (await (await scheduler.fetch(doURL("/licence-activation-refusal"), { method: "GET" })).json()) as { count?: unknown; lastAt?: unknown; lastReasonCode?: unknown } | null;
    if (j === null || typeof j !== "object") return {};
    const count = typeof j.count === "number" && Number.isFinite(j.count) ? Math.max(0, Math.min(1_000_000_000, Math.floor(j.count))) : 0;
    if (count === 0) return {};
    return {
      count,
      ...(typeof j.lastAt === "number" && Number.isFinite(j.lastAt) ? { lastAt: j.lastAt } : {}),
      // G317: an out-of-vocabulary reason code no longer vanishes, leaving "N activations were refused" with no
      // cause at all -- which is precisely the "I pasted my licence but it still says community" ticket this
      // field exists to answer. The drift placeholder rides instead; the raw code is discarded, never carried.
      ...(gateClosed(j.lastReasonCode, LICENCE_REFUSAL_CODE_SET) !== undefined ? { lastReasonCode: gateClosed(j.lastReasonCode, LICENCE_REFUSAL_CODE_SET) } : {}),
    };
  } catch {
    // A read fault is NOT honest absence (which is a clean account with no refusals). Flag it so a diagnoser
    // can tell "no activation was ever refused" from "could not read the refusal tally" (G031).
    return { licenceRefusalsUnavailable: true };
  }
}

// EXPIRY_STATE_SET is the closed set of ExpiryStatus.state values the pack forwards (expiry-tracker-stale).
const EXPIRY_STATE_SET: ReadonlySet<string> = new Set(["ok", "approaching", "expired", "no-expiry"]);

// fetchLicenceExpiryTracker surfaces the ENGINE-OBSERVED `licence` expiry-registry row (expiry-tracker-stale):
// after a licence activate/clear the engine records the token's own notAfter as an OBSERVED `licence`-kind
// expiry item, but that stored row can DRIFT from the live licence.notAfter (a renewal the tracker missed, a
// clear that left the row). The pack already carries licence.notAfter; surfacing the tracked row's expiresAt +
// coarse state ALONGSIDE it makes a stale row visible (the comparison is bot-side). Redaction-safe: a date + a
// closed state enum + a closed source enum only -- never the operator label/id of the registry row. Best-effort:
// {} on failure or when no licence-kind row is tracked (honest absence). Prefers the OBSERVED row over a manual one.
export async function fetchLicenceExpiryTracker(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  try {
    const j = (await (await scheduler.fetch(doURL("/expiry"), { method: "GET" })).json()) as unknown;
    const rows = (Array.isArray(j) ? j : []) as Array<{ kind?: unknown; expiresAt?: unknown; state?: unknown; source?: unknown }>;
    const licenceRows = rows.filter((r) => typeof r === "object" && r !== null && r.kind === "licence");
    const row = licenceRows.find((r) => r.source === "observed") ?? licenceRows[0];
    if (row === undefined) return {};
    return {
      ...(typeof row.expiresAt === "string" ? { trackedNotAfter: row.expiresAt.slice(0, 40) } : {}),
      ...(typeof row.state === "string" && EXPIRY_STATE_SET.has(row.state) ? { state: row.state } : {}),
      ...(row.source === "observed" || row.source === "manual" ? { source: row.source } : {}),
    };
  } catch {
    // A read fault is NOT honest absence (no drift). Flag it so a diagnoser can distinguish the two (G031).
    return { licenceExpiryUnavailable: true };
  }
}

// EXPIRY_KIND_SET / EXPIRY_LIFECYCLE_SET / EXPIRY_REGISTRY_STATE_SET are the closed ExpiryStatus vocabularies
// the registry projection forwards (expiry.ts). Anything outside the set is dropped (defence-in-depth).
const EXPIRY_KIND_SET: ReadonlySet<string> = new Set(["credential", "key", "licence", "certificate", "token"]);
const EXPIRY_LIFECYCLE_SET: ReadonlySet<string> = new Set(["ephemeral", "functional"]);
const EXPIRY_REGISTRY_STATE_SET: ReadonlySet<string> = new Set(["ok", "approaching", "expired", "no-expiry"]);

// fetchExpiryRegistry projects the WHOLE credential-expiry registry into the pack (G260). status.expiryWarnings
// + cleanupPending carry two COUNTS only; a support engineer could see "3 credentials are approaching expiry"
// but not WHICH kind, whether they are ephemeral tokens needing cleanup, or whether an expired row still has a
// resolvable token reference to act on. This carries up to 32 rows, each redaction-safe: the registry id (an
// operator label, the SAME class as destResolution ids / detached binding names), the closed kind / lifecycle /
// state enums, a hasTokenRef boolean (was a public Cloudflare token id recorded, so the row is actionable), and
// the usedAt instant for an ephemeral token. It NEVER carries the free-text label / purpose / note / permission
// summary, nor the tokenRef value itself. A fetch/parse fault PROPAGATES to section(); an empty registry reads
// "empty" (honest absence). Rows sorted worst-state-first so the cap keeps the rows a diagnoser needs.
export async function fetchExpiryRegistry(scheduler: DurableObjectStub): Promise<{ rows: Array<Record<string, unknown>> }> {
  {
    const j = (await (await scheduler.fetch(doURL("/expiry"), { method: "GET" })).json()) as unknown;
    const raw = (Array.isArray(j) ? j : []) as Array<{ id?: unknown; kind?: unknown; lifecycleClass?: unknown; state?: unknown; tokenRef?: unknown; usedAt?: unknown }>;
    const stateRank: Record<string, number> = { expired: 0, approaching: 1, "no-expiry": 2, ok: 3 };
    const rows = raw
      .filter((r) => typeof r === "object" && r !== null)
      .map((r) => {
        const state = typeof r.state === "string" && EXPIRY_REGISTRY_STATE_SET.has(r.state) ? r.state : undefined;
        return {
          ...(typeof r.id === "string" ? { id: r.id.slice(0, 128) } : {}),
          ...(typeof r.kind === "string" && EXPIRY_KIND_SET.has(r.kind) ? { kind: r.kind } : {}),
          ...(typeof r.lifecycleClass === "string" && EXPIRY_LIFECYCLE_SET.has(r.lifecycleClass) ? { lifecycleClass: r.lifecycleClass } : {}),
          ...(state !== undefined ? { state } : {}),
          hasTokenRef: typeof r.tokenRef === "string" && r.tokenRef !== "",
          ...(typeof r.usedAt === "string" ? { usedAt: r.usedAt.slice(0, 40) } : {}),
          _rank: state !== undefined ? (stateRank[state] ?? 4) : 4,
        };
      })
      .sort((a, b) => a._rank - b._rank)
      .slice(0, 32)
      .map(({ _rank, ...row }) => row);
    return { rows };
  }
}

// fetchSourcesDetached surfaces WHICH source bindings are currently detached (sources-detached-binding-names-
// absent): the pack already carries a COUNT (status.sourcesDetachedCount), but not which bindings, so an
// operator cannot tell WHICH source a deploy dropped. This computes the detached set the SAME way the console's
// one-click re-attach does -- the live env bindings vs the persisted roster, via the re-attach planner -- and
// projects the binding NAMES (capped/sorted, deduped). A binding name is an operator label, the SAME redaction
// class already surfaced as source.binding in the config snapshot, and this is the CONFIDENTIAL support pack
// (not the count-only /admin/status response, whose count-only contract is deliberately preserved). Best-effort:
// {} on failure or when nothing is detached (honest absence). The live-binding enumeration needs env, so it is
// computed Worker-side here, not in the DO (which holds no env).
export async function fetchSourcesDetached(env: Env, scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  try {
    const states = (await (await scheduler.fetch(doURL("/downpipes"), { method: "GET" })).json()) as unknown;
    const configs = (Array.isArray(states) ? states : [])
      .map((s) => (typeof s === "object" && s !== null ? (s as { config?: unknown }).config : undefined))
      .filter((c): c is DownpipeConfig => typeof c === "object" && c !== null && typeof (c as { id?: unknown }).id === "string" && typeof (c as { source?: unknown }).source === "object");
    const bound = enumerateBoundSources(env);
    const liveNames = new Set<string>([...bound.kv, ...bound.r2, ...bound.d1, ...bound.secrets]);
    const plan = planRosterReattach(configs, liveNames);
    const bindings = [...new Set([...plan.toAttach.map((a) => a.binding), ...plan.unreconstructable.map((u) => u.binding)])].sort().slice(0, 64);
    // G131: the plan's OMISSIONS, which no reader has ever been shown. A CONFLICTING binding name (two
    // downpipes claim it as different Cloudflare resources) is excluded from toAttach entirely, so the
    // one-click heal silently declines to fix it; a MALFORMED source (binding-backed, no binding name) is in
    // NONE of the plan's lists at all -- "downpipe X was silently omitted from the heal plan". Both leave a
    // downpipe permanently unprotected while the console shows an all-clear, and both are projected here so
    // the pack can say so even when `bindings` is empty (which is the case the old early-return threw away).
    // Binding names are the operator-label class this section already ships; downpipe ids are engine-minted.
    const conflicting = plan.conflicting.map((c) => c.binding).sort().slice(0, 64);
    const malformed = plan.malformed.map((m) => ({ downpipe: m.downpipe, type: m.type })).slice(0, 64);
    if (bindings.length === 0 && conflicting.length === 0 && malformed.length === 0) return {};
    return {
      ...(bindings.length > 0 ? { count: bindings.length, bindings } : {}),
      ...(conflicting.length > 0 ? { conflictingClaims: plan.conflicting.length, conflictingBindings: conflicting } : {}),
      ...(malformed.length > 0 ? { malformedSources: plan.malformed.length, malformed } : {}),
    };
  } catch {
    // A fault reading the roster or enumerating the live bindings is NOT honest absence (nothing detached).
    // Flag it so a diagnoser does not read "no sources are detached" when the computation could not run (G031).
    return { sourcesDetachedUnavailable: true };
  }
}

// OWNER_ACTION_KIND_SET gates the per-kind breakdown to the closed OwnerActionKind vocabulary.
const OWNER_ACTION_KIND_SET: ReadonlySet<string> = new Set(OWNER_ACTION_KINDS);

// fetchOwnerActionQueue projects the dual-control owner-action queue AGGREGATE (G259/G265). The configEvents
// excerpt carries individual propose/approve/reject events, but on a busy estate an old un-approved proposal
// rolls past the 40-event window and there is no live queue state, so "a high-blast-radius change is stuck
// waiting for a second owner" was undiagnosable. This reads the caller-independent DO aggregate: how many
// actions are outstanding, the oldest proposal's timestamp (age is bot-side), a per-kind breakdown (closed
// vocabulary), how many awaited a second approver, and how many EXPIRED undecided (a governance stall). Counts
// + a timestamp + closed kinds only; no id / summary / actor / params. A fault PROPAGATES to section(); an
// empty queue reads "empty".
export async function fetchOwnerActionQueue(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  {
    const j = (await (await scheduler.fetch(doURL("/owner-actions/queue-stats"), { method: "GET" })).json()) as { pendingCount?: unknown; approvalsOutstanding?: unknown; expiredUndecidedCount?: unknown; oldestProposedAt?: unknown; kinds?: unknown };
    const pendingCount = typeof j.pendingCount === "number" && Number.isFinite(j.pendingCount) ? Math.max(0, Math.floor(j.pendingCount)) : 0;
    const expiredUndecidedCount = typeof j.expiredUndecidedCount === "number" && Number.isFinite(j.expiredUndecidedCount) ? Math.max(0, Math.floor(j.expiredUndecidedCount)) : 0;
    if (pendingCount === 0 && expiredUndecidedCount === 0) return {};
    const kinds: Record<string, number> = {};
    if (j.kinds && typeof j.kinds === "object") {
      for (const [k, v] of Object.entries(j.kinds as Record<string, unknown>)) {
        if (OWNER_ACTION_KIND_SET.has(k) && typeof v === "number" && Number.isFinite(v) && v > 0) kinds[k] = Math.floor(v);
      }
    }
    return {
      pendingCount,
      ...(typeof j.approvalsOutstanding === "number" && Number.isFinite(j.approvalsOutstanding) ? { approvalsOutstanding: Math.max(0, Math.floor(j.approvalsOutstanding)) } : {}),
      ...(expiredUndecidedCount > 0 ? { expiredUndecidedCount } : {}),
      ...(typeof j.oldestProposedAt === "string" ? { oldestProposedAt: j.oldestProposedAt.slice(0, 40) } : {}),
      ...(Object.keys(kinds).length > 0 ? { kinds } : {}),
    };
  }
}

// fetchDestinationIdSet reads the configured-destination roster (GET /destinations) and returns the set of
// destination ids (G044/G268). It is the roster a downpipe's configured destinationId / destinationIds is
// cross-checked against to detect a DANGLING reference (a pin to a destination since removed, which fails the
// run loudly but was never counted or attributed in the pack). Ids only (server-minted, the same class the
// pack already carries), never an endpoint/bucket/credential. Returns null on a read fault so the caller
// SKIPS the dangling check rather than producing false positives against an unreadable roster.
export async function fetchDestinationIdSet(scheduler: DurableObjectStub): Promise<Set<string> | null> {
  try {
    const j = (await (await scheduler.fetch(doURL("/destinations"), { method: "GET" })).json()) as { destinations?: Array<{ id?: unknown }> };
    const rows = Array.isArray(j.destinations) ? j.destinations : [];
    return new Set(rows.map((d) => d.id).filter((id): id is string => typeof id === "string"));
  } catch {
    return null;
  }
}

// danglingDestinationRef returns true when a downpipe config PINS a destination id that is NOT in the roster
// set. An ABSENT pin (neither destinationId nor destinationIds) means "the default destination" and is never
// dangling. destinationIds (the fan-out list) SUPERSEDES destinationId when present; a dangling entry in
// EITHER is a broken reference. Pure; the caller passes the roster set from fetchDestinationIdSet.
export function danglingDestinationRef(config: { destinationId?: unknown; destinationIds?: unknown }, destIdSet: Set<string>): boolean {
  const ids: string[] = [];
  if (Array.isArray(config.destinationIds)) {
    for (const id of config.destinationIds) if (typeof id === "string") ids.push(id);
  } else if (typeof config.destinationId === "string") {
    ids.push(config.destinationId);
  }
  return ids.some((id) => !destIdSet.has(id));
}

// fetchRosterIntegrity surfaces the roster's STRUCTURAL health (roster-hygiene.ts): ghost dp: rows the
// delete route can never remove (key-id mismatch / malformed, the "permanent grey line on my map that I
// cannot delete" support case) and well-formed rows that have NEVER run (what a standing "Unknown" map
// edge is when the roster is sound; a freshly created pipe looks like this too, so the diagnoser weighs
// it, never auto-acts). Ids and storage keys only -- the customer's own downpipe identifiers, the SAME
// redaction class as the config snapshot -- with the lists bounded by the DO report itself. Best-effort:
// {} on failure or when the roster is clean AND every downpipe has run (honest absence).
export async function fetchRosterIntegrity(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  try {
    const r = (await (await scheduler.fetch(doURL("/roster-hygiene"), { method: "GET" })).json()) as {
      scanned?: unknown; ghosts?: unknown; ghostCount?: unknown; neverRan?: unknown; neverRanCount?: unknown;
      ghostsTruncated?: unknown; ghostsDropped?: unknown; neverRanTruncated?: unknown; neverRanDropped?: unknown;
    };
    const ghostCount = typeof r.ghostCount === "number" ? r.ghostCount : 0;
    const neverRanCount = typeof r.neverRanCount === "number" ? r.neverRanCount : 0;
    if (ghostCount === 0 && neverRanCount === 0) return {};
    const ghosts = (Array.isArray(r.ghosts) ? r.ghosts : []).slice(0, 25).map((g) => ({
      key: String((g as { key?: unknown }).key ?? "").slice(0, 128),
      embeddedId: typeof (g as { embeddedId?: unknown }).embeddedId === "string" ? String((g as { embeddedId?: unknown }).embeddedId).slice(0, 128) : null,
      kind: String((g as { kind?: unknown }).kind ?? "").slice(0, 32),
    }));
    const neverRan = (Array.isArray(r.neverRan) ? r.neverRan : []).slice(0, 25).map((n) => ({
      id: String((n as { id?: unknown }).id ?? "").slice(0, 128),
      enabled: (n as { enabled?: unknown }).enabled === true,
    }));
    // The IN-RECORD truncation markers (G325). The DO bounds its own lists, and a bounded list that does not
    // SAY it was bounded is an evidence bug: `ghosts` reads as the complete set of undeletable rows when it is
    // only the first N of them, and a diagnoser sizing "how bad is this roster" would under-count in silence.
    // The counts above are the TRUE uncapped totals; these say how many rows the record itself dropped.
    // Booleans + clamped counts, never a dropped row's contents.
    const nn = (v: unknown): number => (typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(1_000_000, Math.floor(v))) : 0);
    return {
      scanned: typeof r.scanned === "number" ? r.scanned : 0,
      ghostCount,
      ...(ghosts.length > 0 ? { ghosts } : {}),
      ...(r.ghostsTruncated === true ? { ghostsTruncated: true, ghostsDropped: nn(r.ghostsDropped) } : {}),
      neverRanCount,
      ...(neverRan.length > 0 ? { neverRan } : {}),
      ...(r.neverRanTruncated === true ? { neverRanTruncated: true, neverRanDropped: nn(r.neverRanDropped) } : {}),
    };
  } catch {
    // A read fault is NOT honest absence (a clean roster). Flag it so the two are distinguishable (G031).
    return { rosterIntegrityUnavailable: true };
  }
}

// fetchDestResolution surfaces the EFFECTIVE resolved destination write settings -- signals the engine
// resolves at write time but never records anywhere: the effective request RATE (a set-but-invalid
// DEST_RATE_PER_SEC silently falls back to the default -- dest-rate-knob-typo), and per destination the
// RESOLVED addressing style (auto -> path/vhost -- wrong-addressing-style), a dotted-bucket-under-vhost
// TLS-SNI risk that makes a transient-looking fault actually PERMANENT (dotted-bucket-vhost-tls), and the
// effective STORAGE CLASS (storageclass-silently-dropped). Every field is a closed enum / clamped int / bool
// / operator label; the endpoint host and bucket NAME are used only to COMPUTE the derived signals and are
// NEVER surfaced. Best-effort: the account-wide rate is always resolvable from env; the per-destination rows
// are omitted (empty) on a failed /destinations read.
// OBJECT_LOCK_STATES / DELETE_PROBE_STATES mirror the closed values the DO validates on write
// (scheduler-do-dest-config.ts): the bucket's real Object-Lock enforcement verdict, and whether the write-path
// delete probe was permitted. Re-gated at the pack boundary so an out-of-vocabulary value is DROPPED (G266).
const OBJECT_LOCK_STATES: ReadonlySet<string> = new Set(["enforced", "not-enforced", "unknown"]);
// The closed chain-break cause vocabulary, re-gated at the pack boundary (G313): the config-history block carries
// the KEY-FREE pass's cause beside the rotated-key boolean, and only a member of the shipped set may ride.
const CHAIN_BREAK_CAUSE_SET: ReadonlySet<string> = new Set(CHAIN_BREAK_CAUSES);
const DELETE_PROBE_STATES: ReadonlySet<string> = new Set(TEST_DELETE_PROBES);
// STORAGE_CLASS_SET is the engine's OWN S3 storage-class allow-list (the SAME constant the destination write
// path validates against), so the pack's gate and the writer's gate cannot drift.
const STORAGE_CLASS_SET: ReadonlySet<string> = new Set(STORAGE_CLASSES);
// DEST_CONFIG_ANOMALY_SET re-gates the env-derived destination-config anomalies (G185) at the pack boundary.
const DEST_CONFIG_ANOMALY_SET: ReadonlySet<string> = new Set(DEST_CONFIG_ANOMALIES);
export async function fetchDestResolution(env: Env, scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const raw = typeof env.DEST_RATE_PER_SEC === "string" ? env.DEST_RATE_PER_SEC.trim() : "";
  const parsed = raw !== "" ? Number(raw) : Number.NaN;
  const rateValid = raw !== "" && Number.isFinite(parsed) && parsed > 0;
  const effectiveRatePerSec = rateValid ? parsed : DEFAULT_DEST_RATE_PER_SEC;
  const rateKnobInvalid = raw !== "" && !rateValid;
  let destinations: Array<Record<string, unknown>> = [];
  // destinationsUnavailable (G052): this section is MIXED-source -- the effectiveRatePerSec/rateKnobInvalid
  // fields are env-derived and always present, so the section() isEmpty predicate never fires and a failed
  // /destinations fetch would otherwise read "ok" with a silently empty destinations list (indistinguishable
  // from an account with no destinations). We keep the env-derived rate knobs but flag the DO-read fault
  // explicitly so a diagnoser can tell "no destinations configured" from "could not read the destinations".
  let destinationsUnavailable = false;
  try {
    const r = await scheduler.fetch(doURL("/destinations"), { method: "GET" });
    const j = (await r.json()) as { destinations?: Array<{ id?: unknown; endpointHost?: unknown; bucket?: unknown; addressing?: unknown; storageClass?: unknown; worm?: unknown; objectLock?: unknown; deleteProbe?: unknown }> };
    destinations = (Array.isArray(j.destinations) ? j.destinations : []).slice(0, 32).flatMap((d) => {
      const host = typeof d.endpointHost === "string" ? d.endpointHost : "";
      const bucket = typeof d.bucket === "string" ? d.bucket : "";
      const addressing = d.addressing === "path" || d.addressing === "vhost" || d.addressing === "auto" ? d.addressing : undefined;
      // resolveAddressing now throws on a stored bucket that is unsafe under an explicit vhost policy
      // (ML-19); a per-item try/catch means one bad legacy record omits only ITS OWN row (returning []
      // to flatMap) rather than the outer catch below dropping every destination row over one bad record.
      try {
        const vhost = resolveAddressing(host, bucket, addressing);
        return [{
          ...(typeof d.id === "string" ? { id: d.id } : {}),
          addressing: vhost ? "vhost" : "path",
          // A dotted bucket addressed vhost-style breaks TLS SNI, so a transient-looking TLS fault is actually
          // PERMANENT until the addressing/bucket is fixed. Surface the risk boolean, never the bucket name.
          ...(vhost && bucket.includes(".") ? { dottedBucketVhostRisk: true } : {}),
          // The effective storage class, SHAPE-GATED against the engine's own S3 storage-class allow-list
          // (dest/factory-validators.ts STORAGE_CLASSES -- the same list the write path validates against),
          // so a value stored by a drifted writer is never carried verbatim. It is a CLOSED ENUM like every
          // other projected field: a member rides, anything else collapses to UNKNOWN_CODE -- which is
          // itself the diagnosis (an unrecognised class means the write path is silently falling back to
          // STANDARD).
          ...(gateClosed(d.storageClass, STORAGE_CLASS_SET) !== undefined ? { storageClass: gateClosed(d.storageClass, STORAGE_CLASS_SET) } : {}),
          // PER-DESTINATION immutability posture (G266). The engine ALREADY persists and returns all three on
          // every destination row; the pack simply dropped them, so the dangerous immutability SHADOW -- a WORM
          // policy CONFIGURED against a bucket that does not actually ENFORCE Object-Lock -- was only visible for
          // the DEFAULT destination (via the single live wormPosture probe), never for the others. Now every
          // destination carries it. wormPolicyConfigured is presence-only (the policy's mode/days stay off this
          // row); bucketEnforces + deleteProbe are the DO's own CLOSED enums, re-gated here (defence in depth).
          // Never an endpoint, bucket, region or credential -- 4.22's contract is unchanged.
          ...(d.worm !== undefined && d.worm !== null ? { wormPolicyConfigured: true } : {}),
          ...(OBJECT_LOCK_STATES.has(d.objectLock as string) ? { bucketEnforces: d.objectLock as string } : {}),
          ...(DELETE_PROBE_STATES.has(d.deleteProbe as string) ? { deleteProbe: d.deleteProbe as string } : {}),
        }];
      } catch {
        return [];
      }
    });
  } catch {
    // The /destinations read faulted: keep the account-wide rate knobs, flag the fault (NOT honest absence).
    destinationsUnavailable = true;
  }
  // configAnomalies (G185): every destination-config INTENT the engine silently discards, derived purely from
  // env at pack-build time (so no write can lose them, and they cannot drift from the fallback they describe).
  // DEST_RATE_PER_SEC / DEST_BURST typos, a half-set WORM pair (an immutability intent armed NOWHERE), an
  // unsupported storage class and an invalid addressing style all fall back in silence today. Closed enum
  // members only; the rejected VALUE (which can be an endpoint, a bucket or a role ARN) never rides.
  // The STORED half of the same gap lands in adminCounters (the dest-config-* keys).
  const configAnomalies = classifyEnvDestAnomalies(env).filter((a) => DEST_CONFIG_ANOMALY_SET.has(a));
  return {
    effectiveRatePerSec,
    rateKnobInvalid,
    destinations,
    ...(configAnomalies.length > 0 ? { configAnomalies } : {}),
    ...(destinationsUnavailable ? { destinationsUnavailable: true } : {}),
  };
}

// buildKeysHealth (P3) is the pack's KEY-material health block: presence + parse-health booleans + FINGERPRINTS OF
// PUBLIC KEY MATERIAL ONLY (never a private half, never a secret). It is env-derived (the keys live in env / the
// Secrets Store, not the DO), so it is computed here in the Worker context. SECURITY-SENSITIVE: it touches key
// handling, but by construction it emits only public-material fingerprints + a KCV (a PRF commitment that leaks
// nothing about the key) + booleans. It closes the keys-bootstrap DATA-LOSS keystones the audit calls still-dark:
//  - breakGlass.recipientFingerprint: cross-check the customer's recovery sheet - a valid PUBLIC break-glass key
//    with a lost/wrong PRIVATE half is unrecoverable and otherwise invisible (breakglass-wrong-key-private-lost).
// SEMANTICS (keys review, item 5a): this is the CURRENT env key = what the NEXT seal wraps to,
//    derived through the SAME loadRecipientPublic parse + recipientFingerprint function the seal path uses
//    (validate-support pins pack fingerprint === a real sealToRecipients wrap fingerprint, so the derivation
//    can never silently diverge). It does NOT claim archives sealed BEFORE a key rotation wrap to this key -
//    those wrap to the prior key, and each archive's own capsule wraps carry their true fingerprints.
//  - configWrapKey.keyCheckValue: which wrap key is configured (config-wrap-key-rotated-wrong: a key rotated after
//    a credential was wrapped renders it undecryptable - compare this KCV to the recovery sheet / a prior pack);
//    `.malformed` is the parse probe (config-wrap-key-malformed).
//  - vendorSupportPublic.{configured,willSeal,malformed,recipientFingerprint}: whether the pack is actually sealed
//    to the vendor key (vendor-support-public-unset-unsealed / -malformed).
export async function buildKeysHealth(env: Env): Promise<Record<string, unknown>> {
  const breakGlass: Record<string, unknown> = { configured: Boolean(env.BREAK_GLASS_PUBLIC) };
  if (env.BREAK_GLASS_PUBLIC) {
    try {
      const pub = loadRecipientPublic(env.BREAK_GLASS_PUBLIC);
      breakGlass.recipientFingerprint = await recipientFingerprint(pub.x25519, pub.mlkemEk);
    } catch {
      breakGlass.malformed = true; // present but not a 1600-byte hybrid recipient public
    }
  }
  const configWrapKey: Record<string, unknown> = { configured: Boolean(env.CONFIG_WRAP_KEY) };
  if (env.CONFIG_WRAP_KEY) {
    try {
      const key = loadConfigWrapKey(env.CONFIG_WRAP_KEY);
      if (key) configWrapKey.keyCheckValue = await configWrapKeyCheckValue(key);
    } catch {
      configWrapKey.malformed = true; // present but not base64url of 32 bytes (AES-256)
    }
  }
  const vendorSupportPublic: Record<string, unknown> = { configured: Boolean(env.VENDOR_SUPPORT_PUBLIC), willSeal: false };
  if (env.VENDOR_SUPPORT_PUBLIC) {
    try {
      const pub = loadRecipientPublic(env.VENDOR_SUPPORT_PUBLIC);
      vendorSupportPublic.recipientFingerprint = await recipientFingerprint(pub.x25519, pub.mlkemEk);
      vendorSupportPublic.willSeal = true; // parses -> sealedSupportBundle will actually seal to it
    } catch {
      vendorSupportPublic.malformed = true; // present but unparseable -> sealedSupportBundle would throw; bundle ships signed-only
    }
  }
  // buildKeyMaterialHealth (G194) widens the malformed-key coverage from the 3 slots above to the SIGNER plus
  // all 3 RECIPIENT slots, and upgrades the flat `malformed` boolean to a CLOSED malformClass that says WHAT is
  // wrong: "bad-encoding" (a PEM / standard-base64 / whitespace paste that is not base64url at all),
  // "wrong-length" (it decodes, but it is not this slot's byte length -- the classic "I pasted the 96-byte
  // PRIVATE identity into OPERATIONAL_PUBLIC" fault), or "unusable" (right length, the algorithm still rejects
  // it). It runs the REAL decode + parse the seal/drill path runs, so the verdict cannot drift from what a run
  // would actually do, and every thrown message is DISCARDED at the site (the decoders' own strings carry byte
  // lengths). This turns status.signerConfigured (presence-only) into a which-slot / what-is-wrong answer.
  // Redaction: closed slot ids + a closed malformClass + booleans + counts. The decoded byte length is
  // deliberately NOT reported -- it is an open integer derived from a customer-pasted value, and the class
  // already carries everything support needs.
  const material = buildKeyMaterialHealth(env);
  return { breakGlass, configWrapKey, vendorSupportPublic, signer: material.signer, recipients: material.recipients };
}

// ---------------------------------------------------------------------------------------------------------
// G008: SOURCE-DISCOVERY HEALTH -- the setup form's own honesty.
//
// GET /sources/discover is fail-open per product, so an EMPTY listing has three completely different causes
// and one identical appearance: the account holds none of that product; the token cannot see them; the page
// cap cut them off. The customer configures their backup estate against whichever one it was, and a scope-gap
// or a truncation means the resources they most needed to protect were never even offered. Nothing was
// recorded, so remotely the empty form and the empty account were the same observation.
//
// This projects the recorded verdicts. Read it as: lastOutcome names each product's CURRENT verdict; a
// "denied" or "truncated" is a form that lied by omission; emptyObservations is how many times the console
// was told "your account has nothing", and degradedObservations is how much of that to believe.
// engineAccountKnown:false is the state in which NO source can ever be ATTACHED at all.
//
// Redaction: closed product keys, closed outcome values, clamped counts, booleans and a clamped epoch. The
// listings themselves (buckets, namespaces, databases, secret names, zones, account ids and names) were
// classified at the fault site and never left it, and every key/value here is re-gated against its closed set
// at the pack boundary too (defence in depth: a DO record written by a drifted build cannot widen the shape).
// Best-effort: {} when no discover has ever run (honest absence), which is itself the answer to "has this
// customer ever opened the Add-a-source screen?".
const DISCOVERY_PRODUCT_SET: ReadonlySet<string> = new Set(DISCOVERY_PRODUCTS);
const DISCOVERY_OUTCOME_SET: ReadonlySet<string> = new Set(DISCOVERY_OUTCOMES);
// G129: the token-set vocabularies, bounding the projection to exactly what the recorder can write.
const DISCOVERY_TOKEN_SET_OUTCOME_SET: ReadonlySet<string> = new Set(DISCOVERY_TOKEN_SET_OUTCOMES);
const DISCOVERY_TOKEN_SET_FAIL_CLASS_SET: ReadonlySet<string> = new Set(DISCOVERY_TOKEN_SET_FAIL_CLASSES);

export async function fetchDiscoveryHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/discovery-health"), { method: "GET" });
  const j = (await r.json()) as { health?: unknown; lastTokenSet?: unknown };
  const h = (typeof j.health === "object" && j.health !== null ? j.health : null) as Record<string, unknown> | null;
  // G129: THE TOKEN-SET VERDICT, AND IT IS GATHERED BEFORE THE h === null EARLY RETURN BELOW, WHICH IS THE
  // WHOLE POINT. A refused token means no discover EVER RAN on this engine -- that is what "Verify and save
  // always fails" means -- so the discovery record is null and, on the old path, the section returned {} and
  // the pack said nothing at all about the most common onboarding ticket. The one fact support needs is
  // precisely the one that only exists when the rest of this section does not.
  //
  // failClass is what the console structurally cannot produce: it is decided at the route that made the
  // Cloudflare call and read the STATUS, so `scope-insufficient` (re-mint with Account Settings read) and
  // `token-invalid` (paste the token value) are two rows rather than one flat `refused`.
  const ts = (typeof j.lastTokenSet === "object" && j.lastTokenSet !== null ? j.lastTokenSet : null) as Record<string, unknown> | null;
  const lastTokenSet =
    ts === null
      ? undefined
      : {
          ...(gateClosed(ts.outcome, DISCOVERY_TOKEN_SET_OUTCOME_SET) !== undefined ? { outcome: gateClosed(ts.outcome, DISCOVERY_TOKEN_SET_OUTCOME_SET)! } : {}),
          ...(gateClosed(ts.failClass, DISCOVERY_TOKEN_SET_FAIL_CLASS_SET) !== undefined ? { failClass: gateClosed(ts.failClass, DISCOVERY_TOKEN_SET_FAIL_CLASS_SET)! } : {}),
          accountsSeen: clampInt(ts.accountsSeen, 1_000) ?? 0,
          ...(typeof ts.at === "number" && Number.isFinite(ts.at) ? { at: Math.max(0, Math.floor(ts.at)) } : {}),
        };
  // G131: the ATTACH record is gathered even when discovery has NEVER run -- an engine whose bindings were
  // wiped by a deploy may never have had the Add-a-source form opened on it, and the failing heal is exactly
  // what the pack is being taken to explain. So the attach read comes FIRST and is returned on its own.
  const attach = await fetchAttachHealth(scheduler);
  if (h === null) {
    // Discovery has never run: honest absence for the form's health, but a refused (or clean) TOKEN SET is a
    // fact in its own right and is the only evidence this engine holds of the operator's attempts.
    const partial = { ...(Object.keys(attach).length > 0 ? { attach } : {}), ...(lastTokenSet !== undefined ? { lastTokenSet } : {}) };
    return Object.keys(partial).length > 0 ? partial : {};
  }

  const lastOutcome: Record<string, string> = {};
  for (const [product, outcome] of Object.entries((typeof h.lastOutcome === "object" && h.lastOutcome !== null ? h.lastOutcome : {}) as Record<string, unknown>)) {
    if (!DISCOVERY_PRODUCT_SET.has(product)) continue;
    const gated = gateClosed(outcome, DISCOVERY_OUTCOME_SET);
    if (gated !== undefined) lastOutcome[product] = gated;
  }
  const totals: Record<string, Record<string, number>> = {};
  for (const [product, byOutcome] of Object.entries((typeof h.totals === "object" && h.totals !== null ? h.totals : {}) as Record<string, unknown>)) {
    if (!DISCOVERY_PRODUCT_SET.has(product) || typeof byOutcome !== "object" || byOutcome === null) continue;
    const row: Record<string, number> = {};
    for (const [outcome, n] of Object.entries(byOutcome as Record<string, unknown>)) {
      if (!DISCOVERY_OUTCOME_SET.has(outcome)) continue;
      const v = clampInt(n, 1_000_000) ?? 0;
      if (v > 0) row[outcome] = v;
    }
    if (Object.keys(row).length > 0) totals[product] = row;
  }
  // G286: the per-account tallies, re-gated a THIRD time on the way into the sealed pack (closed product key,
  // clamped counts). Without them the pack cannot tell a total product blackout from a single membership-scoped
  // account: both fold to the same worst verdict beside the same accountsScanned.
  const accountsByProduct: Record<string, Record<string, number>> = {};
  for (const [product, tally] of Object.entries((typeof h.accountsByProduct === "object" && h.accountsByProduct !== null ? h.accountsByProduct : {}) as Record<string, unknown>)) {
    if (!DISCOVERY_PRODUCT_SET.has(product) || typeof tally !== "object" || tally === null) continue;
    const t = tally as Record<string, unknown>;
    accountsByProduct[product] = {
      withData: clampInt(t.withData, 1_000) ?? 0,
      empty: clampInt(t.empty, 1_000) ?? 0,
      degraded: clampInt(t.degraded, 1_000) ?? 0,
    };
  }
  return {
    ...(Object.keys(lastOutcome).length > 0 ? { lastOutcome } : {}),
    ...(Object.keys(totals).length > 0 ? { totals } : {}),
    ...(Object.keys(accountsByProduct).length > 0 ? { accountsByProduct } : {}),
    ...(h.accountsDegraded !== undefined ? { accountsDegraded: clampInt(h.accountsDegraded, 1_000) ?? 0 } : {}),
    tokenPresent: h.tokenPresent === true,
    engineAccountKnown: h.engineAccountKnown === true,
    accountsScanned: clampInt(h.accountsScanned, 1_000) ?? 0,
    accountsCapped: h.accountsCapped === true,
    boundSources: clampInt(h.boundSources, 1_000) ?? 0,
    observations: clampInt(h.observations, 1_000_000) ?? 0,
    degradedObservations: clampInt(h.degradedObservations, 1_000_000) ?? 0,
    emptyObservations: clampInt(h.emptyObservations, 1_000_000) ?? 0,
    noTokenObservations: clampInt(h.noTokenObservations, 1_000_000) ?? 0,
    ...(typeof h.lastAt === "number" && Number.isFinite(h.lastAt) ? { lastAt: Math.max(0, Math.floor(h.lastAt)) } : {}),
    ...(typeof h.lastDegradedAt === "number" && Number.isFinite(h.lastDegradedAt) ? { lastDegradedAt: Math.max(0, Math.floor(h.lastDegradedAt)) } : {}),
    // attach (G131): the ATTACH / RE-ATTACH record rides inside this same section, because it answers the
    // other half of the same question -- discoveryHealth says what the setup form could SEE, and this says
    // whether the engine could then WRITE the binding. Fetched as a sibling so one DO blip degrades both
    // together rather than half-reporting; {} when no attach has ever been attempted (honest absence).
    ...(Object.keys(attach).length > 0 ? { attach } : {}),
    // lastTokenSet (G129): the verdict on the token the whole form depends on. Absent when no token was ever
    // pasted, which is itself distinct from "pasted and refused".
    ...(lastTokenSet !== undefined ? { lastTokenSet } : {}),
  };
}

// ATTACH_OP_SET / ATTACH_FAULT_CLASS_SET bound the projection to the vocabularies the RECORDER writes, taken
// from the module that defines them so the pack's gate and the classifier cannot drift apart.
const ATTACH_OP_SET: ReadonlySet<string> = new Set(ATTACH_OPS);
const ATTACH_FAULT_CLASS_SET: ReadonlySet<string> = new Set(ATTACH_FAULT_CLASSES);

// fetchAttachHealth (G131) projects the attach / re-attach record. It answers the two tickets the pack could
// not touch:
//
  //   "attach failed halfway during the self-binding rewrite"   -> faults.attach, and specifically the
  //        binding-alarm class: the write LANDED and the post-write verify says the engine's bindings are not
  //        what was intended.
//        successes.reattach. This is the owner's stated #1 fear WITH ITS HEAL BROKEN, and it recorded nothing.
//
// plus lastPlan, which is the heal's own honesty: conflictingClaims and malformedSources are downpipes the
// plan will NEVER fix, while still answering the console with an all-clear-shaped body.
//
// Redaction: closed op keys, closed class values, clamped counts and clamped epochs. The deploy token, the
// account id, the script name, the Cloudflare message and the binding names were classified at the fault site
// and never left it; every key/value is re-gated against its closed set here too (defence in depth).
async function fetchAttachHealth(scheduler: DurableObjectStub): Promise<Record<string, unknown>> {
  const r = await scheduler.fetch(doURL("/attach-health"), { method: "GET" });
  const j = (await r.json()) as { health?: unknown };
  const h = (typeof j.health === "object" && j.health !== null ? j.health : null) as Record<string, unknown> | null;
  if (h === null) return {}; // no attach has ever been attempted: honest absence

  const faults: Record<string, Record<string, number>> = {};
  for (const [op, row] of Object.entries((typeof h.faults === "object" && h.faults !== null ? h.faults : {}) as Record<string, unknown>)) {
    if (!ATTACH_OP_SET.has(op) || typeof row !== "object" || row === null) continue;
    const clean: Record<string, number> = {};
    for (const [cls, n] of Object.entries(row as Record<string, unknown>)) {
      if (!ATTACH_FAULT_CLASS_SET.has(cls)) continue;
      const v = clampInt(n, 1_000_000) ?? 0;
      if (v > 0) clean[cls] = v;
    }
    if (Object.keys(clean).length > 0) faults[op] = clean;
  }
  const counts = (v: unknown): Record<string, number> => {
    const out: Record<string, number> = {};
    for (const [op, n] of Object.entries((typeof v === "object" && v !== null ? v : {}) as Record<string, unknown>)) {
      if (!ATTACH_OP_SET.has(op)) continue;
      const c = clampInt(n, 1_000_000) ?? 0;
      if (c > 0) out[op] = c;
    }
    return out;
  };
  const attempts = counts(h.attempts);
  const successes = counts(h.successes);

  const lf = (typeof h.lastFault === "object" && h.lastFault !== null ? h.lastFault : null) as Record<string, unknown> | null;
  const lastFault =
    lf !== null && gateClosed(lf.op, ATTACH_OP_SET) !== undefined && gateClosed(lf.cls, ATTACH_FAULT_CLASS_SET) !== undefined
      ? { op: gateClosed(lf.op, ATTACH_OP_SET), cls: gateClosed(lf.cls, ATTACH_FAULT_CLASS_SET), ...(clampInt(lf.at, Number.MAX_SAFE_INTEGER) !== undefined ? { at: clampInt(lf.at, Number.MAX_SAFE_INTEGER) } : {}) }
      : undefined;

  const lp = (typeof h.lastPlan === "object" && h.lastPlan !== null ? h.lastPlan : null) as Record<string, unknown> | null;
  const lastPlan =
    lp !== null
      ? {
          toAttach: clampInt(lp.toAttach, 100_000) ?? 0,
          alreadyAttached: clampInt(lp.alreadyAttached, 100_000) ?? 0,
          unreconstructable: clampInt(lp.unreconstructable, 100_000) ?? 0,
          conflictingClaims: clampInt(lp.conflictingClaims, 100_000) ?? 0,
          malformedSources: clampInt(lp.malformedSources, 100_000) ?? 0,
          ...(clampInt(lp.at, Number.MAX_SAFE_INTEGER) !== undefined ? { at: clampInt(lp.at, Number.MAX_SAFE_INTEGER) } : {}),
        }
      : undefined;

  // refusals (G244): the bounded, append-only REFUSAL HISTORY. This is the half of the attach story the coarse
  // fault classes above cannot tell: WHICH stage refused, WHICH cause, and -- the one that answers "attaching a
  // D1 source fails but KV works" outright -- WHICH capability the token is missing. It is a ring, not a
  // counter map, on purpose: the sequence of refusals is the diagnosis, and coalescing on stage|cause would
  // erase the operator's hour of flailing into a single row. Every field is re-gated against its closed set
  // here (defence in depth), so nothing but {epoch, closed op, closed stage, closed cause, capability keys}
  // can ride. attachRefusalOf is the SAME gate the DO applier uses, so the two cannot drift.
  const rawRefusals = Array.isArray(h.refusals) ? h.refusals : [];
  const refusals: Array<Record<string, unknown>> = [];
  for (const raw of rawRefusals.slice(-ATTACH_REFUSALS_CAP)) {
    const r = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
    const op = gateClosed(r.op, ATTACH_OP_SET);
    const kept = attachRefusalOf({ refusal: r });
    if (op === undefined || kept === null) continue;
    refusals.push({
      op,
      stage: kept.stage,
      cause: kept.cause,
      ...(kept.missingCaps !== undefined ? { missingCaps: [...kept.missingCaps] } : {}),
      ...(clampInt(r.at, Number.MAX_SAFE_INTEGER) !== undefined ? { at: clampInt(r.at, Number.MAX_SAFE_INTEGER) } : {}),
    });
  }

  if (Object.keys(attempts).length === 0 && lastPlan === undefined && refusals.length === 0) return {};
  return {
    ...(Object.keys(faults).length > 0 ? { faults } : {}),
    ...(Object.keys(attempts).length > 0 ? { attempts } : {}),
    ...(Object.keys(successes).length > 0 ? { successes } : {}),
    ...(lastFault !== undefined ? { lastFault } : {}),
    ...(lastPlan !== undefined ? { lastPlan } : {}),
    ...(refusals.length > 0 ? { refusals } : {}),
    ...(clampInt(h.lastAt, Number.MAX_SAFE_INTEGER) !== undefined ? { lastAt: clampInt(h.lastAt, Number.MAX_SAFE_INTEGER) } : {}),
  };
}
