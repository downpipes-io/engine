// validateConfig authority-boundary unit suite (config-validate.ts).
// validateConfig is imported directly (not through the HTTP route) so each rejection branch is driven
// without the route's restoreTestCadenceSeconds default or its post-validate destination-liveness check
// masking it. The two bound constants come from the same leaf the validator uses, so the cap cases
// assert the real limits.
import { ok } from "./validate-scheduler-shared.ts";
import type { DownpipeConfig } from "./validate-scheduler-shared.ts";
import { validateConfig } from "../src/sched/config-validate.ts";
import { MINUTES_PER_DAY, SCHEDULE_MAX_BLACKOUT_WINDOWS } from "../src/sched/schedule-window.ts";

export function run(): void {
  // validateConfig is the single authority-boundary guard the apply path (addDownpipe) runs before a
  // config can land in a Durable Object storage key. The schedule cases drive it through the HTTP
  // route, but the route DEFAULTS restoreTestCadenceSeconds and runs a destination-liveness check after
  // validateConfig, both of which would mask or pre-empt some rejection branches. To drive every guard
  // arm precisely, this suite calls validateConfig directly with hand-built configs (the same discipline
  // as the other unit suites, in-memory and offline). Each case asserts the SPECIFIC reason the boundary
  // refuses bad input, or that a well-formed variant is accepted, so a regression that loosened a bound
  // would fail here. Types are stripped under node, so deliberately-malformed values use casts exactly
  // as the route cases above do.
  {
    // baseVC returns a minimal VALID config; each case overrides one field to the value under test, so
    // the rejection (or acceptance) is attributable to that one field and nothing else.
    const baseVC = (over: Partial<DownpipeConfig> = {}): DownpipeConfig => ({
      id: "vc-base",
      name: "vc base",
      cadenceSeconds: 3600,
      enabled: true,
      source: { type: "kv", binding: "KV_test", include: [], exclude: [] } as DownpipeConfig["source"],
      ...over,
    });
    // throws asserts validateConfig REJECTS cfg and the thrown reason matches re (so we know it failed
    // for the field under test, not some unrelated guard). vok asserts it ACCEPTS cfg (no throw).
    const throws = (label: string, cfg: DownpipeConfig, re: RegExp): void => {
      let msg = "";
      try { validateConfig(cfg); } catch (e) { msg = (e as Error).message; }
      ok(label, msg !== "" && re.test(msg));
    };
    const vok = (label: string, cfg: DownpipeConfig): void => {
      let threw = false;
      try { validateConfig(cfg); } catch { threw = true; }
      ok(label, !threw);
    };

    // The baseline itself must be accepted, else every "rejected for field X" case below would be
    // ambiguous (it could be the baseline failing). This anchors the suite.
    vok("vc: a minimal well-formed config is accepted", baseVC());

    // ---- id (L83-84) ----
    throws("vc: a non-string id is rejected", baseVC({ id: 123 as unknown as string }), /downpipe id/);
    throws("vc: an id with a disallowed char (slash) is rejected", baseVC({ id: "bad/id" }), /downpipe id/);
    throws("vc: an over-128-char id is rejected", baseVC({ id: "a".repeat(129) }), /downpipe id/);
    vok("vc: a 128-char id of the allowed charset is accepted (upper bound)", baseVC({ id: "a".repeat(128) }));

    // ---- name (L86-87) ----
    throws("vc: a non-string name is rejected", baseVC({ name: 5 as unknown as string }), /downpipe name/);
    throws("vc: an empty name is rejected", baseVC({ name: "" }), /downpipe name/);
    throws("vc: an over-256-char name is rejected", baseVC({ name: "n".repeat(257) }), /downpipe name/);

    // ---- cadenceSeconds (L89) ----
    throws("vc: a non-integer cadence is rejected", baseVC({ cadenceSeconds: 60.5 }), /cadenceSeconds/);

    // ---- enabled (L92-93) ----
    throws("vc: a non-boolean enabled is rejected", baseVC({ enabled: "yes" as unknown as boolean }), /enabled must be a boolean/);

    // ---- destinationId (L99-100) ----
    throws("vc: a non-string destinationId is rejected", baseVC({ destinationId: 7 as unknown as string }), /destinationId/);
    throws("vc: a destinationId with a disallowed char is rejected", baseVC({ destinationId: "dest id" }), /destinationId/);
    vok("vc: a well-formed destinationId is accepted", baseVC({ destinationId: "dest-A.1" }));

    // ---- destinationIds (L104-113) ----
    throws("vc: a non-array destinationIds is rejected", baseVC({ destinationIds: "dest-A" as unknown as string[] }), /destinationIds must be a non-empty array/);
    throws("vc: an empty destinationIds array is rejected", baseVC({ destinationIds: [] }), /destinationIds must be a non-empty array/);
    throws("vc: a destinationIds entry that is not a string is rejected", baseVC({ destinationIds: [1 as unknown as string] }), /each destinationId/);
    throws("vc: a destinationIds entry with a disallowed char is rejected", baseVC({ destinationIds: ["ok-1", "bad id"] }), /each destinationId/);
    vok("vc: a well-formed destinationIds list is accepted", baseVC({ destinationIds: ["dest-A", "dest-B"] }));

    // ---- restoreTestCadenceSeconds (L117-124): direct call so the route default does not mask it ----
    throws("vc: a negative restoreTestCadenceSeconds is rejected", baseVC({ restoreTestCadenceSeconds: -1 }), /restoreTestCadenceSeconds must be a non-negative integer/);
    throws("vc: a non-integer restoreTestCadenceSeconds is rejected", baseVC({ restoreTestCadenceSeconds: 90.5 }), /restoreTestCadenceSeconds must be a non-negative integer/);
    throws("vc: a positive restoreTestCadenceSeconds below the 60s floor is rejected", baseVC({ restoreTestCadenceSeconds: 30 }), /at least 60/);
    vok("vc: restoreTestCadenceSeconds of 0 (off) is accepted", baseVC({ restoreTestCadenceSeconds: 0 }));
    vok("vc: restoreTestCadenceSeconds exactly at the 60s floor is accepted", baseVC({ restoreTestCadenceSeconds: 60 }));

    // ---- retention (L132-153) ----
    // The retention type is indexed as NonNullable so the deliberately-malformed negative-test values below
    // (a number, null, an array, an empty object) do not also carry the optional field's undefined, which
    // exactOptionalPropertyTypes would reject on Partial<DownpipeConfig>. validateConfig is what rejects each.
    throws("vc: a non-object retention is rejected", baseVC({ retention: 5 as unknown as NonNullable<DownpipeConfig["retention"]> }), /retention must be an object/);
    throws("vc: a null retention is rejected", baseVC({ retention: null as unknown as NonNullable<DownpipeConfig["retention"]> }), /retention must be an object/);
    throws("vc: an array retention is rejected", baseVC({ retention: [] as unknown as NonNullable<DownpipeConfig["retention"]> }), /retention must be an object/);
    throws("vc: a retention with neither keepRuns nor keepDays is rejected", baseVC({ retention: {} as NonNullable<DownpipeConfig["retention"]> }), /at least one of keepRuns or keepDays/);
    throws("vc: retention.keepRuns of 0 is rejected (would supersede the whole downpipe)", baseVC({ retention: { keepRuns: 0 } }), /retention.keepRuns/);
    throws("vc: a non-integer retention.keepRuns is rejected", baseVC({ retention: { keepRuns: 1.5 } }), /retention.keepRuns/);
    throws("vc: a retention.keepRuns above the 10000 backstop is rejected", baseVC({ retention: { keepRuns: 10001 } }), /retention.keepRuns/);
    throws("vc: retention.keepDays of 0 is rejected", baseVC({ retention: { keepDays: 0 } }), /retention.keepDays/);
    throws("vc: a retention.keepDays above the century backstop is rejected", baseVC({ retention: { keepDays: 36501 } }), /retention.keepDays/);
    throws("vc: a non-boolean retention.enforce is rejected", baseVC({ retention: { keepRuns: 5, enforce: "yes" as unknown as boolean } }), /retention.enforce must be a boolean/);
    vok("vc: a retention with keepRuns at the upper backstop and a boolean enforce is accepted", baseVC({ retention: { keepRuns: 10000, enforce: true } }));
    vok("vc: a retention with only keepDays is accepted", baseVC({ retention: { keepDays: 30 } }));

    // ---- schedule object shape + timeZone + cron (L161-183) ----
    throws("vc: a null schedule is rejected", baseVC({ schedule: null as unknown as NonNullable<DownpipeConfig["schedule"]> }), /schedule must be an object/);
    throws("vc: a non-string schedule.timeZone is rejected", baseVC({ schedule: { timeZone: 5 as unknown as string } }), /schedule.timeZone must be a non-empty/);
    throws("vc: a blank schedule.timeZone is rejected", baseVC({ schedule: { timeZone: "   " } }), /schedule.timeZone must be a non-empty/);
    throws("vc: an unknown IANA schedule.timeZone is rejected", baseVC({ schedule: { timeZone: "Mars/Phobos" } }), /not a known IANA time zone/);
    throws("vc: a non-string schedule.cron is rejected", baseVC({ schedule: { cron: 5 as unknown as string } }), /schedule.cron must be a string/);
    throws("vc: a malformed schedule.cron is rejected with the underlying reason", baseVC({ schedule: { cron: "99 * * * *" } }), /schedule.cron is invalid/);
    vok("vc: a valid cron with a known time zone is accepted", baseVC({ schedule: { cron: "30 2 * * *", timeZone: "UTC" } }));

    // ---- schedule.blackoutWindows (L184-209) ----
    throws("vc: a non-array blackoutWindows is rejected", baseVC({ schedule: { blackoutWindows: {} as unknown as [] } }), /blackoutWindows must be an array/);
    {
      const tooMany = Array.from({ length: SCHEDULE_MAX_BLACKOUT_WINDOWS + 1 }, () => ({ startMinute: 0, endMinute: 60 }));
      throws("vc: a blackoutWindows list over the cap is rejected", baseVC({ schedule: { blackoutWindows: tooMany } }), /must not exceed/);
    }
    throws("vc: a non-object blackout window is rejected", baseVC({ schedule: { blackoutWindows: [5 as unknown as { startMinute: number; endMinute: number }] } }), /each blackout window must be an object/);
    throws("vc: a null blackout window is rejected", baseVC({ schedule: { blackoutWindows: [null as unknown as { startMinute: number; endMinute: number }] } }), /each blackout window must be an object/);
    throws("vc: a blackout window with a non-integer startMinute is rejected", baseVC({ schedule: { blackoutWindows: [{ startMinute: 1.5, endMinute: 60 }] } }), /startMinute/);
    throws("vc: a blackout window startMinute below zero is rejected", baseVC({ schedule: { blackoutWindows: [{ startMinute: -1, endMinute: 60 }] } }), /startMinute/);
    throws("vc: a blackout window endMinute over a day is rejected", baseVC({ schedule: { blackoutWindows: [{ startMinute: 0, endMinute: MINUTES_PER_DAY + 1 }] } }), /endMinute/);
    throws("vc: a non-array blackout window days is rejected", baseVC({ schedule: { blackoutWindows: [{ startMinute: 0, endMinute: 60, days: 1 as unknown as number[] }] } }), /days must be an array/);
    throws("vc: a blackout window day above 6 is rejected", baseVC({ schedule: { blackoutWindows: [{ startMinute: 0, endMinute: 60, days: [7] }] } }), /days must be integers 0-6/);
    vok("vc: a well-formed blackout window with days is accepted", baseVC({ schedule: { blackoutWindows: [{ startMinute: 0, endMinute: 60, days: [0, 6] }] } }));

    // ---- source.type (L212-215) ----
    throws("vc: a missing source is rejected", baseVC({ source: undefined as unknown as DownpipeConfig["source"] }), /source.type must be/);
    throws("vc: an unknown source.type is rejected", baseVC({ source: { type: "ftp" } as unknown as DownpipeConfig["source"] }), /source.type must be/);

    // ---- secrets source (L221-234) ----
    throws("vc: a secrets source with a non-array secrets list is rejected", baseVC({ source: { type: "secrets", secrets: "x", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /non-empty secrets list/);
    throws("vc: a secrets source with an empty secrets list is rejected", baseVC({ source: { type: "secrets", secrets: [], include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /non-empty secrets list/);
    throws("vc: a secret with an empty name is rejected", baseVC({ source: { type: "secrets", secrets: [{ name: "", binding: "SEC_A" }], include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /each secret needs/);
    throws("vc: a secret whose binding names a reserved env binding is rejected", baseVC({ source: { type: "secrets", secrets: [{ name: "k", binding: "SIGNER_PRIVATE" }], include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /each secret needs/);
    throws("vc: a secret with a binding outside the allowed charset is rejected", baseVC({ source: { type: "secrets", secrets: [{ name: "k", binding: "bad-binding" }], include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /each secret needs/);
    vok("vc: a well-formed secrets source is accepted", baseVC({ source: { type: "secrets", secrets: [{ name: "API_KEY", binding: "SEC_API" }], include: [], exclude: [] } as unknown as DownpipeConfig["source"] }));
    // storeId (optional, recorded for re-attach reconstruction): a well-formed id is accepted, a malformed one rejected.
    vok("vc: a secret with a valid storeId is accepted", baseVC({ source: { type: "secrets", secrets: [{ name: "API_KEY", binding: "SEC_API", storeId: "store_abc-123" }], include: [], exclude: [] } as unknown as DownpipeConfig["source"] }));
    throws("vc: a secret with a malformed storeId is rejected", baseVC({ source: { type: "secrets", secrets: [{ name: "API_KEY", binding: "SEC_API", storeId: "bad store!" }], include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /storeId must be a Secrets Store store id/);

    // ---- cf-config source (L235-243): needs a hex accountId; a zoneId only widens scope ----
    throws("vc: a cf-config source with no accountId is rejected", baseVC({ source: { type: "cf-config", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /needs an accountId/);
    throws("vc: a cf-config source with a non-hex zoneId is rejected", baseVC({ source: { type: "cf-config", accountId: "0abc12", zoneId: "not-hex-zone", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /zoneId must be a Cloudflare zone id/);
    throws("vc: a cf-config source with a non-hex accountId is rejected", baseVC({ source: { type: "cf-config", accountId: "ZZZ", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /accountId must be a Cloudflare account id/);
    vok("vc: a cf-config source with a hex accountId (and optional zoneId) is accepted", baseVC({ source: { type: "cf-config", accountId: "0abc12", zoneId: "abc123def456", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }));

    // ---- workers / stream / images sources (L244-270): each needs a hex accountId ----
    for (const t of ["workers", "stream", "images"] as const) {
      throws(`vc: a ${t} source with no accountId is rejected`, baseVC({ source: { type: t, include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /needs an accountId/);
      throws(`vc: a ${t} source with a non-hex accountId is rejected`, baseVC({ source: { type: t, accountId: "nothex!", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /accountId must be a Cloudflare account id/);
      vok(`vc: a ${t} source with a hex accountId is accepted`, baseVC({ source: { type: t, accountId: "0abc12", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }));
    }

    // ---- artifacts source is gated (closed beta): validateConfig rejects it at the source-type allowlist
    // (config-validate.ts:311), before the per-type check, so a config carrying it is refused. Re-enable by
    // re-adding "artifacts" to that allowlist and restoring the accountId cases above.
    throws("vc: a gated artifacts source is rejected as an unsupported type", baseVC({ source: { type: "artifacts", accountId: "0abc12", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /source\.type must be/);

    // ---- binding sources kv/r2/d1 (L271-272) ----
    throws("vc: a kv source whose binding names a reserved env binding is rejected", baseVC({ source: { type: "kv", binding: "DEST_R2", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /source.binding must be/);
    throws("vc: an r2 source with a missing binding is rejected", baseVC({ source: { type: "r2", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /source.binding must be/);
    vok("vc: a d1 source with a valid binding is accepted", baseVC({ source: { type: "d1", binding: "DB_test", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }));
    // databaseId (optional, recorded for re-attach + match-back): a well-formed UUID is accepted, a malformed one rejected.
    vok("vc: a d1 source with a valid databaseId is accepted", baseVC({ source: { type: "d1", binding: "DB_test", databaseId: "11111111-2222-3333-4444-555555555555", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }));
    throws("vc: a d1 source with a malformed databaseId is rejected", baseVC({ source: { type: "d1", binding: "DB_test", databaseId: "bad id!", include: [], exclude: [] } as unknown as DownpipeConfig["source"] }), /databaseId must be a Cloudflare database id/);

    // ---- includeContent (L277-282) ----
    throws("vc: a non-boolean includeContent is rejected", baseVC({ source: { type: "stream", accountId: "0abc12", include: [], exclude: [], includeContent: "yes" } as unknown as DownpipeConfig["source"] }), /includeContent must be a boolean/);
    throws("vc: includeContent on a kv source (no bytes to capture) is rejected", baseVC({ source: { type: "kv", binding: "KV_test", include: [], exclude: [], includeContent: true } as unknown as DownpipeConfig["source"] }), /includeContent is only valid for/);
    vok("vc: includeContent on a stream source is accepted", baseVC({ source: { type: "stream", accountId: "0abc12", include: [], exclude: [], includeContent: true } as unknown as DownpipeConfig["source"] }));

    // ---- include / exclude must be arrays (L283-285) ----
    throws("vc: a non-array source.include is rejected", baseVC({ source: { type: "kv", binding: "KV_test", include: "all", exclude: [] } as unknown as DownpipeConfig["source"] }), /include and source.exclude must be arrays/);
    throws("vc: a non-array source.exclude is rejected", baseVC({ source: { type: "kv", binding: "KV_test", include: [], exclude: {} } as unknown as DownpipeConfig["source"] }), /include and source.exclude must be arrays/);

    // ---- cfConfigMode (L288-290) ----
    throws("vc: an unrecognised cfConfigMode is rejected", baseVC({ source: { type: "cf-config", accountId: "0abc12", include: [], exclude: [], cfConfigMode: "draft" } as unknown as DownpipeConfig["source"] }), /cfConfigMode must be/);
    vok("vc: cfConfigMode \"manual\" is accepted", baseVC({ source: { type: "cf-config", accountId: "0abc12", include: [], exclude: [], cfConfigMode: "manual" } as unknown as DownpipeConfig["source"] }));
    vok("vc: cfConfigMode \"auto\" is accepted", baseVC({ source: { type: "cf-config", accountId: "0abc12", include: [], exclude: [], cfConfigMode: "auto" } as unknown as DownpipeConfig["source"] }));
  }
}
