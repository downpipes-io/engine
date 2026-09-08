// Downpipe-config authority-boundary validation and the reserved-binding set. validateConfig bounds and
// checks a downpipe config at the authority boundary, so a malformed or oversized id cannot land in a
// Durable Object storage key. RESERVED_BINDINGS is re-exported so other modules (attach.ts, bindings-sync.ts,
// preflight.ts, restore.ts, router-sources.ts, seal/adapters.ts) can reuse the same set without duplicating it.

import { selectorPrefixFault } from "../sources/selector.ts";
import { isValidTimeZone, validateCron } from "./cron.ts";
import { MINUTES_PER_DAY, SCHEDULE_MAX_BLACKOUT_WINDOWS } from "./schedule-window.ts";
import type { DownpipeConfig } from "./types.ts";

// RESERVED_BINDINGS are the engine's own env bindings; a downpipe source must never name
// one (else it could seal the signer key or destination creds into a backup).
export const RESERVED_BINDINGS = new Set([
  "SCHEDULER",
  "CF_ACCESS_TEAM_DOMAIN",
  "CF_ACCESS_AUD",
  "ADMIN_TOKEN",
  // Other dedicated bearer-style secrets, each gating its own surface the same way ADMIN_TOKEN
  // gates admin: a source must never read them into a backup either.
  "SCIM_BEARER_TOKEN",
  "BEACON_INGEST_KEY",
  "CONSOLE_ORIGIN",
  "DEST_ENDPOINT",
  "DEST_BUCKET",
  "DEST_REGION",
  "DEST_ACCESS_KEY_ID",
  "DEST_SECRET_ACCESS_KEY",
  // CONFIG_WRAP_KEY envelope-encrypts the destination secret above at rest; a source reading it
  // would recover every wrapped destination credential, defeating the whole point of wrapping them.
  "CONFIG_WRAP_KEY",
  "DEST_R2",
  "DEST_KIND",
  "SIGNER_PRIVATE",
  "BREAK_GLASS_PUBLIC",
  "OPERATIONAL_PUBLIC",
  "OPERATIONAL_PRIVATE",
  // The config recipient: a key pair whose ONLY job is opening this engine's own sealed configuration
  // export. Reserved for the same reason as every other key slot, so a source can never read it into a
  // backup. CONFIG_RECIPIENT_PRIVATE also matches the completeness scan's secret-name pattern, so it must
  // be listed here in the same change that declares it in env.d.ts or that gate fails.
  "CONFIG_RECIPIENT_PUBLIC",
  "CONFIG_RECIPIENT_PRIVATE",
  "UPDATE_CHANNEL_URL",
  "UPDATE_SIGNER_PUBLIC",
  "LICENCE_TOKEN",
  "LICENCE_SIGNER_PUBLIC",
  "RUNSEAL",
  "SLICED_RUNS_DISABLED",
  "SCALE_SLICE_SUBREQUESTS",
  "SCALE_SLICE_WALL_MS",
  "SCALE_SHARD_MAX_RECORDS",
  "SCALE_SEGMENT_TARGET_BYTES",
  "VENDOR_SUPPORT_PUBLIC",
  // Outbound email + first-run bootstrap (a source must never read these as a
  // plaintext-secret into an archive).
  "EMAIL",
  "EMAIL_FROM",
  "INVITE_EMAIL_FROM",
  "BOOTSTRAP_OWNER_EMAIL",
  // Account-wide discovery (opt-in): the customer's own read-only API token and
  // account id. The token is the most sensitive string on the worker after the
  // signer; reserving it here is defence in depth on top of never returning it.
  "DISCOVERY_API_TOKEN",
  "CF_ACCOUNT_ID",
  // Engine-internal Durable Object and version-metadata bindings: a source must never name these.
  "RATELIMIT_DO",
  "CF_VERSION_METADATA",
]);

// MAX_SECRETS_PER_SOURCE bounds how many secrets one `secrets` source may declare, so a crafted or
// pathological config cannot hand the engine an unbounded list to store and later loop over. The
// coverage gap view iterates a source's secrets to build its match keys (matchKeysForSource), so an
// unbounded secrets list would make that loop unbounded too; bounding it here at the authority boundary
// keeps the coverage match loop bounded. An oversized list is REJECTED (not silently truncated) so the
// operator knows their config did not fully land, mirroring the coverage inventory cap discipline; the
// value matches that cap (COVERAGE_RESOURCES_PER_TYPE_MAX, 5000) deliberately, as a secrets source and a
// secrets inventory group describe the same population of named secrets. 5000 is far above any realistic
// per-source secret count while capping the worst case on the single-threaded DO.
const MAX_SECRETS_PER_SOURCE = 5000;

// MAX_DESTINATIONS_PER_DOWNPIPE bounds the 3-2-1 fan-out list so an operator-supplied destinationIds
// array cannot drive an unbounded seal loop. The realistic maximum is the number of configured
// destinations (small); 20 is well above any practical 3-2-1 fan-out while keeping the per-run seal
// loop bounded. An oversized list is REJECTED (not truncated), mirroring the secrets cap discipline.
const MAX_DESTINATIONS_PER_DOWNPIPE = 20;

// BULK_DOWNPIPES_MAX / BULK_DOWNPIPES_MAX_GATED bound one POST /downpipes/bulk request. Each item runs
// the full single-upsert path (validation + gates + audit) inside one DO invocation, so the cap bounds
// the DO's per-request work; a larger fleet is created in further batches (the response advertises the
// cap as maxBatch so the console re-batches deterministically). The GATED cap is far lower because with
// change approval ON each item is a propose: dryRunConfigMutation checkpoints and rolls back the WHOLE
// keyspace per item, which is orders of magnitude heavier than an inline apply. An oversized batch is
// REJECTED whole (never partially processed or silently truncated), mirroring the secrets cap discipline.
export const BULK_DOWNPIPES_MAX = 100;
export const BULK_DOWNPIPES_MAX_GATED = 10;

// RESTORE_TEST_MIN_CADENCE_SECONDS bounds an explicit (non-zero) cadence so a malformed/abusive value
// cannot drive a metered read storm. It matches the run cadence floor (60s); a real cadence is days,
// so this is a backstop, not a normal value. Zero is allowed (it means "off") and is handled before
// this floor in validateConfig.
const RESTORE_TEST_MIN_CADENCE_SECONDS = 60;

// RETENTION_MAX_KEEP_RUNS / RETENTION_MAX_KEEP_DAYS bound the retention window so a malformed or
// abusive value cannot land in the config. keepRuns at least 1 (retaining zero runs would
// supersede the entire downpipe in one prune, which is never the intent and is refused); the
// upper bound is a generous backstop (a downpipe keeping ten thousand runs is well past any real
// policy). keepDays is the same shape in days; a century is the backstop. These are bounds, not
// defaults: absent retention means keep everything (no prune at all).
const RETENTION_MAX_KEEP_RUNS = 10000;
const RETENTION_MAX_KEEP_DAYS = 36500;

// DOWNPIPE_ID_MAX_LEN / DOWNPIPE_NAME_MAX_LEN are the canonical length bounds for a downpipe id and name.
// They are the authority here at config validation; other readers (such as the notify emission parser)
// import them so a single change cannot leave a regex or length check silently diverging.
// SELECTABLE_SOURCE_TYPES is the ONE closed set of source types a stored downpipe config may name, and the
// single place the Artifact Registry beta gate is held.
//
// "artifacts" is deliberately ABSENT. Artifact Registry is a Cloudflare CLOSED BETA that almost no account
// can reach, and its backup is not yet verified end to end, so a config must never select it. This is a gate
// and not a deletion: every artifacts code path stays intact and dormant (its own validator branch below, its
// adapter in seal/adapters.ts, its restore sink, its format vocabulary).
//
// Re-add "artifacts" HERE to re-enable it, and nowhere else. That instruction used to appear three times, in
// three files that did not reference each other: this allow-list, the discovery-source allow-list in
// scheduler-do-account-config.ts, and an ARTIFACTS_GA constant in the console. Flipping the console's alone
// would have offered the operator a source this validator then refuses, which is a source they can select
// and never protect. Both other sites now DERIVE from this list, and the console has a cross-repo check that
// fails if it offers a type this refuses, so the gate opens in one edit or not at all.
export const SELECTABLE_SOURCE_TYPES = ["kv", "r2", "secrets", "d1", "cf-config", "workers", "stream", "images"] as const;

// TOKEN_SOURCE_TYPES are the account-wide source types read with the engine's read-only discovery TOKEN
// rather than an env binding. Kept whole (artifacts included) because it describes how a type is read, which
// the beta gate does not change; the gate is applied by the intersection below.
const TOKEN_SOURCE_TYPES = ["cf-config", "workers", "stream", "images", "artifacts"] as const;

// SELECTABLE_TOKEN_SOURCE_TYPES is TOKEN_SOURCE_TYPES narrowed to what a config may actually select, so the
// Sources screen's enabled-source allow-list cannot drift from what this validator will accept. A type an
// operator can "add" but never select in a downpipe is a dead control.
export const SELECTABLE_TOKEN_SOURCE_TYPES: readonly string[] = TOKEN_SOURCE_TYPES.filter((t) => (SELECTABLE_SOURCE_TYPES as readonly string[]).includes(t));

export const DOWNPIPE_ID_MAX_LEN = 128;
export const DOWNPIPE_NAME_MAX_LEN = 256;
export const DOWNPIPE_ID_PATTERN = new RegExp(`^[A-Za-z0-9._-]{1,${DOWNPIPE_ID_MAX_LEN}}$`);

// validateIdentity checks the four required scalar fields (id / name / cadenceSeconds / enabled) at the
// authority boundary. Behaviour moved VERBATIM out of validateConfig; the order and reasons are unchanged.
function validateIdentity(c: DownpipeConfig): void {
  if (typeof c.id !== "string" || !DOWNPIPE_ID_PATTERN.test(c.id)) {
    throw new Error(`downpipe id must be 1 to ${DOWNPIPE_ID_MAX_LEN} chars of [A-Za-z0-9._-]`);
  }
  // An all-dots id (".", "..", "...") passes the charset but is a path-reserved token: reject it so a
  // downpipe id can never be a relative-path component, however the id is later consumed.
  if (/^\.+$/.test(c.id)) {
    throw new Error("downpipe id must not be entirely dots");
  }
  if (typeof c.name !== "string" || c.name.length < 1 || c.name.length > DOWNPIPE_NAME_MAX_LEN) {
    throw new Error(`downpipe name must be 1 to ${DOWNPIPE_NAME_MAX_LEN} characters`);
  }
  if (!Number.isInteger(c.cadenceSeconds) || c.cadenceSeconds < 60) {
    throw new Error("cadenceSeconds must be an integer of at least 60");
  }
  if (typeof c.enabled !== "boolean") {
    throw new Error("enabled must be a boolean");
  }
}

// validateDestinations checks the optional destinationId and destinationIds (3-2-1 fan-out) shapes.
// Behaviour moved VERBATIM out of validateConfig; only the shape is bound here, liveness is checked later.
function validateDestinations(c: DownpipeConfig): void {
  // destinationId is optional (ABSENT = the default destination); when present it is an opaque
  // id from the destinations collection. Bound the shape here (same charset as a downpipe id);
  // whether it references a LIVE destination is checked in addDownpipe (it has the collection),
  // and the run path fails loudly on a dangling id rather than writing to the wrong bucket.
  if (c.destinationId !== undefined && (typeof c.destinationId !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(c.destinationId))) {
    throw new Error("destinationId must be 1 to 128 chars of [A-Za-z0-9._-]");
  }
  // destinationIds is the fan-out list (3-2-1): each entry is an opaque destination id, same shape as
  // destinationId. Optional (ABSENT = use destinationId / the default). addDownpipe checks each is live.
  if (c.destinationIds !== undefined) {
    if (!Array.isArray(c.destinationIds) || c.destinationIds.length < 1) {
      throw new Error("destinationIds must be a non-empty array when present");
    }
    if (c.destinationIds.length > MAX_DESTINATIONS_PER_DOWNPIPE) {
      throw new Error(`destinationIds must not exceed ${MAX_DESTINATIONS_PER_DOWNPIPE} entries`);
    }
    for (const id of c.destinationIds) {
      if (typeof id !== "string" || !/^[A-Za-z0-9._-]{1,128}$/.test(id)) {
        throw new Error("each destinationId must be 1 to 128 chars of [A-Za-z0-9._-]");
      }
    }
  }
}

// validateRestoreTestCadence bounds the optional restoreTestCadenceSeconds. Behaviour moved VERBATIM
// out of validateConfig; 0 (off) and the >= floor branch are unchanged.
function validateRestoreTestCadence(c: DownpipeConfig): void {
  // restoreTestCadenceSeconds (contract section 5) is optional; addDownpipe defaults it before this
  // check, so by the time validateConfig runs it is present, but bound it defensively for any direct
  // caller. 0 means "off" (a valid opt-down); any other value must be an integer at or above the floor.
  if (c.restoreTestCadenceSeconds !== undefined) {
    const v = c.restoreTestCadenceSeconds;
    if (!Number.isInteger(v) || v < 0) {
      throw new Error("restoreTestCadenceSeconds must be a non-negative integer (0 = off)");
    }
    if (v > 0 && v < RESTORE_TEST_MIN_CADENCE_SECONDS) {
      throw new Error(`restoreTestCadenceSeconds must be 0 (off) or at least ${RESTORE_TEST_MIN_CADENCE_SECONDS}`);
    }
  }
}

// validateRetention bounds the optional retention window. Behaviour moved VERBATIM out of validateConfig;
// the at-least-one rule, the per-field backstops and the enforce-boolean check are unchanged.
function validateRetention(c: DownpipeConfig): void {
  // retention (ASVS V14.2.7) is optional; ABSENT keeps everything (no prune), the current
  // behaviour, so a pre-retention persisted config is unchanged. When present it must be an
  // object with at least one of keepRuns/keepDays (an empty window would describe no policy),
  // each a positive integer within its backstop, and enforce, when present, a boolean. enforce
  // is the deletion gate: it is validated as a boolean here but its DEFAULT (absent) is dry-run,
  // enforced at the apply site, never here (validateConfig only bounds the shape).
  if (c.retention !== undefined) {
    const r = c.retention;
    if (typeof r !== "object" || r === null || Array.isArray(r)) {
      throw new Error("retention must be an object { keepRuns?, keepDays?, enforce? }");
    }
    if (r.keepRuns === undefined && r.keepDays === undefined) {
      throw new Error("retention requires at least one of keepRuns or keepDays");
    }
    if (r.keepRuns !== undefined) {
      if (!Number.isInteger(r.keepRuns) || r.keepRuns < 1 || r.keepRuns > RETENTION_MAX_KEEP_RUNS) {
        throw new Error(`retention.keepRuns must be an integer from 1 to ${RETENTION_MAX_KEEP_RUNS}`);
      }
    }
    if (r.keepDays !== undefined) {
      if (!Number.isInteger(r.keepDays) || r.keepDays < 1 || r.keepDays > RETENTION_MAX_KEEP_DAYS) {
        throw new Error(`retention.keepDays must be an integer from 1 to ${RETENTION_MAX_KEEP_DAYS}`);
      }
    }
    if (r.enforce !== undefined && typeof r.enforce !== "boolean") {
      throw new Error("retention.enforce must be a boolean");
    }
  }
}

// validateSchedule bounds the optional schedule (cron / timezone / blackout windows). Behaviour moved
// VERBATIM out of validateConfig; the cron reason is still surfaced verbatim and the window bounds are unchanged.
function validateSchedule(c: DownpipeConfig): void {
  // schedule (cron / time-of-day / timezone / blackout) is OPTIONAL; ABSENT means the cadenceSeconds
  // interval cadence, unchanged. When present it must be an object whose cron (if any) parses, whose
  // timeZone (if any) is a known IANA zone, and whose blackoutWindows (if any) are sane. A malformed
  // schedule is REJECTED here with the underlying reason, so a bad schedule never reaches dispatch.
  // Note: cadenceSeconds is still validated and required above, so a cron-scheduled downpipe also
  // carries a valid cadence (the fallback path), and a config with neither cron nor a valid cadence
  // is still invalid exactly as before.
  if (c.schedule !== undefined) {
    const sch = c.schedule;
    if (typeof sch !== "object" || sch === null || Array.isArray(sch)) {
      throw new Error("schedule must be an object { cron?, timeZone?, blackoutWindows? }");
    }
    if (sch.timeZone !== undefined) {
      if (typeof sch.timeZone !== "string" || sch.timeZone.trim() === "") {
        throw new Error("schedule.timeZone must be a non-empty IANA time zone string");
      }
      if (!isValidTimeZone(sch.timeZone)) {
        throw new Error(`schedule.timeZone "${sch.timeZone}" is not a known IANA time zone`);
      }
    }
    if (sch.cron !== undefined) {
      if (typeof sch.cron !== "string") throw new Error("schedule.cron must be a string");
      // validateCron throws a field-named reason on a malformed expression; surface it verbatim so the
      // operator sees exactly which field was wrong, prefixed for context.
      try {
        validateCron(sch.cron);
      } catch (e) {
        throw new Error(`schedule.cron is invalid: ${(e as Error).message}`);
      }
    }
    if (sch.blackoutWindows !== undefined) {
      if (!Array.isArray(sch.blackoutWindows)) {
        throw new Error("schedule.blackoutWindows must be an array");
      }
      if (sch.blackoutWindows.length > SCHEDULE_MAX_BLACKOUT_WINDOWS) {
        throw new Error(`schedule.blackoutWindows must not exceed ${SCHEDULE_MAX_BLACKOUT_WINDOWS} windows`);
      }
      for (const w of sch.blackoutWindows) {
        if (typeof w !== "object" || w === null || Array.isArray(w)) {
          throw new Error("each blackout window must be an object { days?, startMinute, endMinute }");
        }
        if (!Number.isInteger(w.startMinute) || w.startMinute < 0 || w.startMinute > MINUTES_PER_DAY) {
          throw new Error(`blackout window startMinute must be an integer 0-${MINUTES_PER_DAY} (minutes since local midnight)`);
        }
        if (!Number.isInteger(w.endMinute) || w.endMinute < 0 || w.endMinute > MINUTES_PER_DAY) {
          throw new Error(`blackout window endMinute must be an integer 0-${MINUTES_PER_DAY} (minutes since local midnight)`);
        }
        // A window is the HALF-OPEN interval [startMinute, endMinute), so an equal start and end covers NO
        // minutes at all: it is INERT and has never once applied, while the operator believes they have declared
        // a change freeze (G322). Refuse it at the write path so the degenerate case becomes a counted refusal
        // the operator sees immediately, rather than a freeze that silently does nothing for months.
        if (w.startMinute === w.endMinute) {
          throw new Error("blackout window startMinute and endMinute must differ (an equal start and end covers no time, so the window would never apply)");
        }
        if (w.days !== undefined) {
          if (!Array.isArray(w.days)) throw new Error("blackout window days must be an array of weekday numbers");
          for (const d of w.days) {
            if (!Number.isInteger(d) || d < 0 || d > 6) {
              throw new Error("blackout window days must be integers 0-6 (0 = Sunday)");
            }
          }
        }
      }
    }
  }
}

// DiscoveryScopeConfig is the minimal shape accountInDiscoveryScope needs from a discovery config. Kept
// STRUCTURAL rather than imported from scheduler-do-records.ts/router-sources-discovery.ts so this leaf
// takes on no new dependency; the DO's own DiscoveryConfig record and the router's DiscoveryConfigView
// mirror both already carry these two fields under these names, so either satisfies this unchanged.
export interface DiscoveryScopeConfig {
  accountsSeen: Array<{ id: string }>;
  selected: string[];
}

// accountInDiscoveryScope is the cross-account confused-deputy guard (ASVS V4): a token-authenticated
// source (cf-config/workers/stream/images/artifacts) reads the Cloudflare REST API with the single
// account-wide discovery token, so its accountId must be one the Owner's own discovery config actually
// covers -- otherwise any downpipe.write-only caller could point a source at ANY account that shared
// token can reach and use rediscover/trigger to probe or seal it (never checked before this; the cfId()
// checks below only bound the hex SHAPE, never the scope). `cfg === null` is the honest env/IaC-only
// deployment (a bare DISCOVERY_API_TOKEN with no console-set config, resolveDiscoveryToken's documented
// fallback): there is no Owner-curated list to check against, so this is a no-op there, matching every
// other discovery reader's null-config fallback. Once a config exists, accountId must be in accountsSeen
// (a real account the token verified); once the Owner has narrowed the browsed set (selected non-empty),
// it must be in `selected` too -- the SAME "known account" boundary setDiscoveryAccounts already enforces
// when the OWNER picks which accounts to browse (scheduler-do-account-config.ts), re-applied here at the
// point a downpipe's source actually NAMES one.
export function accountInDiscoveryScope(accountId: string, cfg: DiscoveryScopeConfig | null): boolean {
  if (cfg === null) return true;
  if (!cfg.accountsSeen.some((a) => a.id === accountId)) return false;
  if (cfg.selected.length > 0 && !cfg.selected.includes(accountId)) return false;
  return true;
}

// validateSource checks the source type, its binding/id requirements per type, and the optional
// includeContent / include-exclude / cfConfigMode fields. Behaviour moved VERBATIM out of validateConfig;
// the per-type branches, the reserved-binding guard and the field bounds are unchanged.
function validateSource(c: DownpipeConfig): void {
  const s = c.source;
  // The allow-list and the refusal message both read SELECTABLE_SOURCE_TYPES, so the message can never name
  // a set the check does not enforce (see the constant for where the artifacts beta gate lives).
  if (!s || !(SELECTABLE_SOURCE_TYPES as readonly string[]).includes(s.type)) {
    throw new Error(`source.type must be ${SELECTABLE_SOURCE_TYPES.join("/")}`);
  }
  // A source binding must never name one of the engine's own reserved bindings, or a
  // crafted downpipe could read the signer key or destination credentials and seal them
  // into a backup (a confused deputy). Enforced here at the authority boundary and again
  // defensively in buildAdapter.
  const bindingOK = (b: unknown) => typeof b === "string" && /^[A-Za-z0-9_]{1,64}$/.test(b) && !RESERVED_BINDINGS.has(b);
  // resId validates an OPTIONAL native resource id (KV namespace id / D1 database id / Secrets Store
  // store id) recorded for re-attach + match-back. It is permissive on purpose (hex ids AND dash-bearing
  // UUIDs), and only ever checked WHEN PRESENT, so a pre-existing binding-only config never newly fails.
  const resId = (v: unknown) => typeof v === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(v);
  if (s.type === "secrets") {
    if (!Array.isArray(s.secrets) || s.secrets.length === 0) {
      throw new Error("a secrets source needs a non-empty secrets list");
    }
    // Bound the secrets list so the per-secret seal loop AND the coverage match loop over it stay
    // bounded; an oversized list is rejected, not truncated, so the operator knows it did not land.
    if (s.secrets.length > MAX_SECRETS_PER_SOURCE) {
      throw new Error(`a secrets source must not exceed ${MAX_SECRETS_PER_SOURCE} secrets`);
    }
    for (const sec of s.secrets) {
      if (typeof sec.name !== "string" || sec.name.length < 1 || sec.name.length > 256 || !bindingOK(sec.binding)) {
        throw new Error("each secret needs a 1 to 256 char name and a 1 to 64 char [A-Za-z0-9_] binding");
      }
      // storeId is optional (recorded for re-attach); validate its shape only when present.
      if (sec.storeId !== undefined && !resId(sec.storeId)) throw new Error("each secret's storeId must be a Secrets Store store id");
    }
  } else if (s.type === "cf-config") {
    // cf-config reads the Cloudflare REST API with the engine's read-only discovery token, not a
    // Workers binding, so it has no source.binding; it needs an account id (a zone id only widens scope).
    const cfId = (v: unknown) => typeof v === "string" && /^[a-f0-9]{1,64}$/i.test(v);
    if (s.accountId === undefined) {
      throw new Error("a cf-config source needs an accountId (a zoneId alone cannot be crawled)");
    }
    if (s.zoneId !== undefined && !cfId(s.zoneId)) throw new Error("cf-config zoneId must be a Cloudflare zone id (hex)");
    if (!cfId(s.accountId)) throw new Error("cf-config accountId must be a Cloudflare account id (hex)");
  } else if (s.type === "workers") {
    // workers reads the Cloudflare REST API with the engine's read-only discovery token (the same
    // token as cf-config), not a Workers binding, so it has no source.binding. It is account-scoped:
    // it lists and backs up the account's Worker scripts, so it needs an account id (no zone).
    const cfId = (v: unknown) => typeof v === "string" && /^[a-f0-9]{1,64}$/i.test(v);
    if (s.accountId === undefined) throw new Error("a workers source needs an accountId");
    if (!cfId(s.accountId)) throw new Error("workers accountId must be a Cloudflare account id (hex)");
  } else if (s.type === "stream") {
    // stream reads the Cloudflare REST API with the engine's read-only discovery token (the same
    // token as cf-config/workers), not a binding. Account-scoped: it lists the account's Stream
    // videos, so it needs an account id (no zone).
    const cfId = (v: unknown) => typeof v === "string" && /^[a-f0-9]{1,64}$/i.test(v);
    if (s.accountId === undefined) throw new Error("a stream source needs an accountId");
    if (!cfId(s.accountId)) throw new Error("stream accountId must be a Cloudflare account id (hex)");
  } else if (s.type === "images") {
    // images reads the Cloudflare REST API with the engine's read-only discovery token (the same token
    // as cf-config/workers/stream), not a binding. Account-scoped: it lists the account's Images, so it
    // needs an account id (no zone).
    const cfId = (v: unknown) => typeof v === "string" && /^[a-f0-9]{1,64}$/i.test(v);
    if (s.accountId === undefined) throw new Error("an images source needs an accountId");
    if (!cfId(s.accountId)) throw new Error("images accountId must be a Cloudflare account id (hex)");
  } else if (s.type === "artifacts") {
    // artifacts (Artifact Registry) reads the Cloudflare REST API with the read-only discovery token,
    // not a binding. Account-scoped: it lists namespaces + their repos, so it needs an account id (no zone).
    const cfId = (v: unknown) => typeof v === "string" && /^[a-f0-9]{1,64}$/i.test(v);
    if (s.accountId === undefined) throw new Error("an artifacts source needs an accountId");
    if (!cfId(s.accountId)) throw new Error("artifacts accountId must be a Cloudflare account id (hex)");
  } else if (!bindingOK(s.binding)) {
    throw new Error("source.binding must be 1 to 64 chars of [A-Za-z0-9_]");
  }
  // databaseId is optional (recorded for d1 re-attach + match-back); validate its shape only when present.
  if (s.databaseId !== undefined && !resId(s.databaseId)) throw new Error("source.databaseId must be a Cloudflare database id");
  // namespaceId (kv) and bucketName (r2) are recorded the same way (re-attach + match-back), so validate
  // their shape when present too, rather than storing an unchecked override.
  if (s.namespaceId !== undefined && !resId(s.namespaceId)) throw new Error("source.namespaceId must be a Cloudflare KV namespace id");
  if (s.bucketName !== undefined && !resId(s.bucketName)) throw new Error("source.bucketName must be a Cloudflare R2 bucket name");
  // includeContent (also capture the resource BYTES, not just the metadata inventory) is only meaningful
  // for the media sources that have bytes to capture; if present it must be a boolean, and rejected on a
  // type that has no separate content (so a stray flag never silently does nothing).
  if (s.includeContent !== undefined) {
    if (typeof s.includeContent !== "boolean") throw new Error("source.includeContent must be a boolean");
    if (s.type !== "stream" && s.type !== "images" && s.type !== "artifacts") {
      throw new Error("source.includeContent is only valid for stream/images/artifacts");
    }
  }
  if (!Array.isArray(s.include) || !Array.isArray(s.exclude)) {
    throw new Error("source.include and source.exclude must be arrays");
  }
  // The array check bounds the container and says nothing about the contents, and an array of empty
  // strings is an array. A single "" in exclude matches every record name (inScope is a literal
  // startsWith test), so the downpipe backs up NOTHING and every run reports success. The console filters
  // empties on its way in, which means this is only reachable by API, which is precisely the path
  // customer automation uses. Refused rather than filtered, with a message that says what the empty
  // prefix would have meant. See selectorPrefixFault for the full reasoning.
  const prefixFault = selectorPrefixFault(s.include, s.exclude);
  if (prefixFault !== null) throw new Error(`source.${prefixFault}`);
  // cfConfigMode (cf-config capture mode) is optional and, when present, must be the literal "auto" or
  // "manual" (absent = auto). Any other value is rejected at save rather than silently coerced.
  if (s.cfConfigMode !== undefined && s.cfConfigMode !== "auto" && s.cfConfigMode !== "manual") {
    throw new Error('source.cfConfigMode must be "auto" or "manual"');
  }
}

// validateConfig bounds and checks a downpipe config at the authority boundary. It runs the per-section
// validators in the SAME order as the original monolith, so the first failing section throws the same
// reason as before; behaviour and the public signature are unchanged.
export function validateConfig(c: DownpipeConfig): void {
  validateIdentity(c);
  validateDestinations(c);
  validateRestoreTestCadence(c);
  validateRetention(c);
  validateSchedule(c);
  validateSource(c);
}
