// pickDownpipeConfig: the closed field allowlist for a downpipe save (ASVS V15.3.3, mass assignment).
//
// WHY THIS EXISTS. The upsert arm used to spread the raw request body into the stored config, and
// validateConfig bounds only the fields it knows, so an authorised downpipe.write caller could insert any
// key (including misleading ones such as configRev or createdAt) into the persisted record, from where it
// rode into GET /downpipes and every re-post of the stored config. This function is the one place the body
// is narrowed to the fields the action intends, and single, bulk and approved-change replay all pass
// through it.
//
// TWO PROPERTIES. (1) The key lists are TYPE-ANCHORED with `satisfies Record<keyof T, true>`, so a field
// added to DownpipeConfig (or a nested interface) without extending its list fails `tsc`, and a key listed
// here that the interface no longer has fails the same way. (2) An unknown key is REFUSED, not dropped:
// config-validate.ts states that a save is refused rather than filtered, and a silently dropped field would
// let an operator believe a setting took effect. The error names the path so the console can show it.
//
// This function narrows KEYS only. Types and ranges stay with validateConfig, which runs after it.
import type { BlackoutWindow, DownpipeConfig, DownpipeSchedule, RetentionPolicy, SecretBindingSpec, SourceSpec } from "./types.ts";

const CONFIG_KEYS = { id: true, name: true, cadenceSeconds: true, enabled: true, source: true, destinationId: true, destinationIds: true, restoreTestCadenceSeconds: true, retention: true, schedule: true } as const satisfies Record<keyof DownpipeConfig, true>;
const SOURCE_KEYS = { type: true, binding: true, namespaceId: true, bucketName: true, databaseId: true, zoneId: true, accountId: true, secrets: true, cfConfigMode: true, includeContent: true, include: true, exclude: true } as const satisfies Record<keyof SourceSpec, true>;
const SECRET_KEYS = { name: true, binding: true, storeId: true } as const satisfies Record<keyof SecretBindingSpec, true>;
const RETENTION_KEYS = { keepRuns: true, keepDays: true, enforce: true } as const satisfies Record<keyof RetentionPolicy, true>;
const SCHEDULE_KEYS = { cron: true, timeZone: true, blackoutWindows: true } as const satisfies Record<keyof DownpipeSchedule, true>;
const WINDOW_KEYS = { days: true, startMinute: true, endMinute: true } as const satisfies Record<keyof BlackoutWindow, true>;

// Prototype-shaped keys are refused on every object regardless of the list: they are never a config field
// and a permissive JSON parser would otherwise let one through as an own property.
const FORBIDDEN_KEYS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// checkKeys refuses the first key of `obj` that is not in `allowed`, naming it by dotted path. A non-object
// is left for validateConfig to refuse with its own message.
function checkKeys(obj: unknown, allowed: Record<string, true>, path: string): void {
  if (!isPlainObject(obj)) return;
  for (const key of Object.keys(obj)) {
    if (FORBIDDEN_KEYS.has(key) || !Object.hasOwn(allowed, key)) {
      throw new Error(`unknown field ${path === "" ? key : `${path}.${key}`}: a downpipe save accepts only its documented fields, and this one is refused rather than dropped`);
    }
  }
}

function checkEach(list: unknown, allowed: Record<string, true>, path: string): void {
  if (!Array.isArray(list)) return;
  list.forEach((item, i) => {
    checkKeys(item, allowed, `${path}[${i}]`);
  });
}

/** pickDownpipeConfig refuses any key outside the downpipe's documented fields, at every nesting level. */
export function pickDownpipeConfig(raw: unknown): DownpipeConfig {
  checkKeys(raw, CONFIG_KEYS, "");
  if (!isPlainObject(raw)) return raw as DownpipeConfig;
  checkKeys(raw.source, SOURCE_KEYS, "source");
  if (isPlainObject(raw.source)) checkEach(raw.source.secrets, SECRET_KEYS, "source.secrets");
  checkKeys(raw.retention, RETENTION_KEYS, "retention");
  checkKeys(raw.schedule, SCHEDULE_KEYS, "schedule");
  if (isPlainObject(raw.schedule)) checkEach(raw.schedule.blackoutWindows, WINDOW_KEYS, "schedule.blackoutWindows");
  return raw as unknown as DownpipeConfig;
}
