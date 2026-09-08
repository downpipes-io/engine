// config-anomalies.ts -- the closed-vocabulary record of destination configuration an operator SET and the
// engine SILENTLY DISCARDED (G185).
//
// THE PROBLEM: every destination-config read is fail-safe by DROPPING. fetchDestConfig validates the stored
// worm / assumeRole / addressing / storageClass and, on anything malformed, simply omits it; the env path
// (parseWormPolicy / validateStorageClass / validateAddressing / destPacerFromEnv) does the same for the
// DEST_WORM_* / DEST_STORAGE_CLASS / DEST_ADDRESSING / DEST_RATE_PER_SEC / DEST_BURST knobs. The drop is the
// RIGHT call (a half-read policy must never arm false protection, a typo'd knob must never stop a backup) but
// it is INVISIBLE: a corrupted assumeRole policy means the engine signs with the long-lived PRINCIPAL and the
// cross-account backup fails AccessDenied forever, and nothing anywhere says the operator's intent was
// discarded. The support pack shows a healthy-looking destination and a mystifying 403.
//
// THE SHAPE: two PURE classifiers over the two config sources, both returning members of one CLOSED
// vocabulary.
//   - classifyStoredDestAnomalies(raw)  the console-set destination as it is STORED. The pack cannot derive
//     this itself: the DO's /destinations read returns the SANITISED row (the malformed field is already
//     gone), and the raw row lives behind the internal full-value route that carries the secret. So the drop
//     must be RECORDED at the read-for-use site (factory.fetchDestConfig -> a closed admin counter).
//   - classifyEnvDestAnomalies(env)     the deploy-time DEST_* knobs. This one needs NO write at all: env is
//     readable at pack-build time, so the pack DERIVES it (the same way destResolution already derives
//     rateKnobInvalid). A derived signal cannot drift from the drop it describes and cannot be lost.
//
// NO-CUSTODY REDACTION (binding): a classifier READS the malformed value only to SELECT a member of
// DEST_CONFIG_ANOMALIES, and returns THAT ENUM. The value itself -- which may be an endpoint, a bucket, a
// role ARN, an externalId or a credential -- is never returned, stored, counted or forwarded. The output
// alphabet of both functions is exactly DEST_CONFIG_ANOMALIES, and nothing else can leave this module.

import { validateAddressing, validateAssumeRolePolicy, validateStorageClass, validateWormPolicyValue } from "./factory-validators.ts";

/**
 * DEST_CONFIG_ANOMALIES is the CLOSED vocabulary of destination-config intents the engine discarded. Each
 * member names the FIELD or KNOB, never its value:
 *
 *   worm-policy-dropped            a STORED WORM policy failed validation and was dropped: the destination
 *                                  claims immutability in the console and writes are NOT locked.
 *   assume-role-policy-dropped     a STORED STS AssumeRole policy was dropped: the engine now signs with the
 *                                  long-lived principal, so every cross-account write is AccessDenied.
 *   storage-class-dropped          a STORED storage class was dropped: writes land in the bucket default tier
 *                                  and the cost lever the operator set does nothing.
 *   addressing-dropped             a STORED addressing style was dropped: the engine re-derives auto, which
 *                                  can be the wrong style for a non-AWS store.
 *   missing-field-*                the STORED config is incomplete: the read throws and NO backup can run.
 *   rate-knob-invalid              DEST_RATE_PER_SEC is set but unreadable: the pacer silently uses the
 *                                  default rate.
 *   burst-knob-invalid             DEST_BURST is set but unreadable: same, for the burst.
 *   worm-policy-partial            only ONE of DEST_WORM_MODE / DEST_WORM_RETENTION_DAYS is set: WORM was
 *                                  intended and is armed nowhere.
 *   worm-mode-invalid              DEST_WORM_MODE is neither governance nor compliance.
 *   worm-retention-days-invalid    DEST_WORM_RETENTION_DAYS is not a positive integer.
 *   storage-class-unsupported      DEST_STORAGE_CLASS names a class outside the immediately-readable
 *                                  allow-list (a GLACIER tier would break verify-at-seal and restore).
 *   addressing-invalid             DEST_ADDRESSING is neither auto, path nor vhost.
 */
export const DEST_CONFIG_ANOMALIES = [
  // --- the STORED (console-set) destination: recorded at the read-for-use site ---
  "worm-policy-dropped",
  "assume-role-policy-dropped",
  "storage-class-dropped",
  "addressing-dropped",
  "missing-field-endpoint",
  "missing-field-bucket",
  "missing-field-region",
  "missing-field-access-key-id",
  "missing-field-secret",
  // --- the ENV (deploy-time) knobs: derived at pack-build time ---
  "rate-knob-invalid",
  "burst-knob-invalid",
  "worm-policy-partial",
  "worm-mode-invalid",
  "worm-retention-days-invalid",
  "storage-class-unsupported",
  "addressing-invalid",
] as const;
/**
 * One member of DEST_CONFIG_ANOMALIES: a destination-config intent the operator set and the engine then
 * discarded. It is the entire output alphabet of both classifiers in this module, so a malformed endpoint,
 * bucket, role ARN, externalId or credential can never leave here as a value. The stored half maps to an
 * admin counter through STORED_ANOMALY_COUNTERS; the env half has no counter, because the pack derives it.
 */
export type DestConfigAnomaly = (typeof DEST_CONFIG_ANOMALIES)[number];

/**
 * STORED_ANOMALY_COUNTERS maps each STORED-config anomaly to the closed admin-counter name it is recorded
 * under (ADMIN_COUNTER_NAMES in admin/diag-records.ts). The five missing-field members share ONE counter:
 * an incomplete stored config throws before any write can run, so the actionable fact is THAT it is
 * incomplete, and naming WHICH field is left to the pack's derived view rather than five near-identical
 * counters. The mapping is total over the stored half of the vocabulary.
 */
export const STORED_ANOMALY_COUNTERS: Readonly<Record<string, string>> = {
  "worm-policy-dropped": "dest-config-worm-policy-dropped",
  "assume-role-policy-dropped": "dest-config-assume-role-policy-dropped",
  "storage-class-dropped": "dest-config-storage-class-dropped",
  "addressing-dropped": "dest-config-addressing-dropped",
  "missing-field-endpoint": "dest-config-incomplete",
  "missing-field-bucket": "dest-config-incomplete",
  "missing-field-region": "dest-config-incomplete",
  "missing-field-access-key-id": "dest-config-incomplete",
  "missing-field-secret": "dest-config-incomplete",
};

/**
 * RawStoredDest is the UNVALIDATED shape the scheduler DO's full-value /dest-config route returns. Every
 * field is unknown on purpose: this module's whole job is to say which of them the validators will discard.
 *
 * Every field is also OPTIONAL, because absence is a shape the stored row really takes and the two halves of
 * it mean different things: an absent worm / assumeRole / addressing / storageClass is not configured and is
 * no anomaly, while an absent endpoint / bucket / region / accessKeyId / secret is the incomplete-config
 * case, which is a different member from a dropped intent.
 */
export interface RawStoredDest {
  endpoint?: unknown;
  bucket?: unknown;
  region?: unknown;
  accessKeyId?: unknown;
  secretAccessKey?: unknown;
  worm?: unknown;
  assumeRole?: unknown;
  addressing?: unknown;
  storageClass?: unknown;
}

// nonEmptyString is the "field is present at all" test the incomplete-config guard in fetchDestConfig uses.
function nonEmptyString(v: unknown): boolean {
  return typeof v === "string" && v !== "";
}

/**
 * classifyStoredDestAnomalies names every field of a STORED destination config that the engine's validators
 * will silently discard (or that is missing outright). PURE: it reads the values ONLY to decide which closed
 * enum members apply, and returns those members. No value, key, ARN, endpoint or secret is ever returned.
 *
 * A field that is ABSENT is not an anomaly (absent is the honest "not configured"); a field that is PRESENT
 * but does not survive its validator IS one -- that is precisely the operator intent being thrown away.
 *
 * @param raw - the untrusted stored destination row.
 * @param secretPresent - whether the stored secret is present in EITHER of its two at-rest shapes (a plain
 *   string or a wrapped envelope); the caller decides this because the envelope shape is an admin concern.
 * @returns the closed anomaly members, in vocabulary order.
 */
export function classifyStoredDestAnomalies(raw: RawStoredDest, secretPresent: boolean): DestConfigAnomaly[] {
  const out: DestConfigAnomaly[] = [];
  if (raw.worm !== undefined && raw.worm !== null && validateWormPolicyValue(raw.worm) === null) out.push("worm-policy-dropped");
  if (raw.assumeRole !== undefined && raw.assumeRole !== null && validateAssumeRolePolicy(raw.assumeRole) === null) out.push("assume-role-policy-dropped");
  if (raw.storageClass !== undefined && raw.storageClass !== null && validateStorageClass(raw.storageClass) === undefined) out.push("storage-class-dropped");
  if (raw.addressing !== undefined && raw.addressing !== null && validateAddressing(raw.addressing) === undefined) out.push("addressing-dropped");
  if (!nonEmptyString(raw.endpoint)) out.push("missing-field-endpoint");
  if (!nonEmptyString(raw.bucket)) out.push("missing-field-bucket");
  if (!nonEmptyString(raw.region)) out.push("missing-field-region");
  if (!nonEmptyString(raw.accessKeyId)) out.push("missing-field-access-key-id");
  if (!secretPresent) out.push("missing-field-secret");
  return out;
}

/**
 * EnvDestKnobs is the deploy-time destination knob surface. Typed as unknown-valued because a Worker env var
 * is a string in production but a validator (and a misconfigured deploy) can present anything.
 *
 * A Worker Env satisfies it structurally, which is what lets the pack pass its own env straight to
 * classifyEnvDestAnomalies with no adapter and no chance of the two reading different knobs.
 */
export interface EnvDestKnobs {
  DEST_RATE_PER_SEC?: unknown;
  DEST_BURST?: unknown;
  DEST_STORAGE_CLASS?: unknown;
  DEST_ADDRESSING?: unknown;
  DEST_WORM_MODE?: unknown;
  DEST_WORM_RETENTION_DAYS?: unknown;
}

// setTrimmed reduces an env knob to its trimmed string when it is set to something non-empty, else undefined
// (the honest "not configured"). It never returns the value onward: only this module's classifier sees it.
function setTrimmed(v: unknown): string | undefined {
  if (typeof v !== "string") return undefined;
  const t = v.trim();
  return t === "" ? undefined : t;
}

// positiveNumber mirrors destPacerFromEnv's own acceptance test (a finite number > 0), so the classifier's
// verdict is the same verdict the pacer acted on -- a knob this says is invalid IS a knob that fell back.
function positiveNumber(raw: string): boolean {
  const n = Number(raw);
  return Number.isFinite(n) && n > 0;
}

/**
 * classifyEnvDestAnomalies names every deploy-time DEST_* knob that is SET but does not survive its
 * validator, and so falls back silently: the pacer's rate/burst (destPacerFromEnv), the storage class and
 * addressing style (validateStorageClass / validateAddressing), and the WORM pair (parseWormPolicy, whose
 * partial or invalid state arms nothing).
 *
 * PURE and DERIVABLE: the pack can call this at build time from env, so this signal needs no write, cannot be
 * dropped by an unavailable DO, and cannot drift from the fallback it describes.
 *
 * @param env - the destination knob surface (a Worker env, or any object carrying the same names).
 * @returns the closed anomaly members, in vocabulary order.
 */
export function classifyEnvDestAnomalies(env: EnvDestKnobs): DestConfigAnomaly[] {
  const out: DestConfigAnomaly[] = [];
  const rate = setTrimmed(env.DEST_RATE_PER_SEC);
  if (rate !== undefined && !positiveNumber(rate)) out.push("rate-knob-invalid");
  const burst = setTrimmed(env.DEST_BURST);
  if (burst !== undefined && !positiveNumber(burst)) out.push("burst-knob-invalid");
  const mode = setTrimmed(env.DEST_WORM_MODE);
  const days = setTrimmed(env.DEST_WORM_RETENTION_DAYS);
  // WORM is a PAIR: one knob without the other is an intent armed nowhere, and is reported as its own
  // anomaly rather than as two field faults (the operator set what they set; the fault is the missing half).
  if ((mode === undefined) !== (days === undefined)) out.push("worm-policy-partial");
  if (mode !== undefined && mode.toLowerCase() !== "governance" && mode.toLowerCase() !== "compliance") out.push("worm-mode-invalid");
  if (days !== undefined) {
    const n = Number(days);
    if (!Number.isInteger(n) || n <= 0) out.push("worm-retention-days-invalid");
  }
  const sc = setTrimmed(env.DEST_STORAGE_CLASS);
  if (sc !== undefined && validateStorageClass(sc) === undefined) out.push("storage-class-unsupported");
  const addr = setTrimmed(env.DEST_ADDRESSING);
  if (addr !== undefined && validateAddressing(addr) === undefined) out.push("addressing-invalid");
  return out;
}

/**
 * anomalyBumps folds STORED anomalies into the {closed counter name: count} tally the DO's
 * POST /diag/admin-counters route folds into its bounded aggregate. An anomaly with no counter (the env half,
 * which the pack derives instead) contributes nothing, so the tally's key space is a strict subset of
 * ADMIN_COUNTER_NAMES and the DO's applyAdminCounters drops anything else regardless (defence in depth).
 *
 * @param anomalies - the closed anomaly members.
 * @returns the tally, empty when there is nothing to report.
 */
export function anomalyBumps(anomalies: readonly DestConfigAnomaly[]): Record<string, number> {
  const bumps: Record<string, number> = {};
  for (const a of anomalies) {
    const name = STORED_ANOMALY_COUNTERS[a];
    if (name === undefined) continue;
    bumps[name] = (bumps[name] ?? 0) + 1;
  }
  return bumps;
}
