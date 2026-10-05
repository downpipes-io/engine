import { isWrappedSecret, resolveConfigSecret, type WrappedSecret } from "../admin/config-secret.ts";
import { recordUnwrapFault } from "../admin/diag-admin.ts";
import { unwrapFaultCauseOf } from "../admin/diag-records.ts";
import { recordDiagWrite } from "../admin/diag-writer.ts";
import type { Env } from "../env.d.ts";
import type { Meter } from "../meter.ts";
import { AzureBlobDestination } from "./azure-blob.ts";
import { azureEntraCloudFor, AzureEntraTokenSource } from "./azure-entra.ts";
import { looksLikeAzureSasToken } from "./azure-sas.ts";
import { azureAccountFromHost, type DestProvider, providerForEndpoint, UNUSABLE_ENDPOINT_REASON, unusableEndpoint } from "./provider.ts";
import { DestBuildError, destBuildFaultOf } from "./build-health.ts";
import { DEPLOY_DEST_ID } from "./dest-resolution.ts";
export { DestResolutionError, destResolutionRefusalOf, type DestResolutionRefusal } from "./dest-resolution.ts";
import { anomalyBumps, classifyStoredDestAnomalies } from "./config-anomalies.ts";
import { flushDestIo, noteDestIoWriteLost, pendingDestIo } from "./dest-io.ts";
import { type AssumeRolePolicy, type AzureEntraDirectory, normaliseWormMode, validateAddressing, validateAssumeRolePolicy, validateAzureEntraDirectory, validateStorageClass, validateWormPolicyValue } from "./factory-validators.ts";
import { destPacerFromEnv } from "./pace.ts";
import { R2Destination } from "./r2.ts";
import { type Addressing, S3Destination } from "./s3.ts";
import { assumeRole, isValidStsRegion } from "./sts.ts";
import type { Destination, WormPolicy } from "./types.ts";

// The four config validators and the storage-class allow-list MOVED to the leaf factory-validators.ts (so
// config-anomalies.ts can decide what this factory will DISCARD using the very functions that discard it,
// with no import cycle). They are re-exported here VERBATIM, so every existing importer of
// "./factory.ts" -- the admin router, the scheduler DO's dest-config mixin, the validators -- is unchanged.
export { addressingRejection, assumeRolePolicyRejection, type AssumeRolePolicy, type AzureEntraDirectory, azureEntraDirectoryRejection, validateAddressing, validateAssumeRolePolicy, validateAzureEntraDirectory, validateStorageClass, validateWormPolicyValue, wormPolicyRejection } from "./factory-validators.ts";

/**
 * The console-set destination: the S3-shaped credentials an Owner stores from the Destinations
 * screen at runtime (held in the scheduler DO, no CLI, no redeploy). It is always S3-shaped because
 * a runtime config cannot bind a new R2 bucket (bindings are deploy-time); R2 is reached through
 * its S3-compatible endpoint. When both this and the deploy-time env config exist, this wins, so an
 * Owner can repoint the archive without a deploy. It may carry an optional per-destination WORM
 * policy.
 */
export interface RuntimeDestConfig {
  endpoint: string;
  bucket: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  // worm is the OPTIONAL per-destination WORM/Object-Lock policy a console-set destination may carry
  // (mode + retention days). When present and valid it arms store-enforced immutability for writes to
  // THAT destination; absent = OFF (unchanged). A console-set policy wins over the env DEST_WORM_*
  // vars, exactly as the rest of the console-set destination config wins over env. Stored alongside the
  // S3 credentials in the scheduler DO; carries no secret.
  worm?: WormPolicy;
  // sessionToken is the OPTIONAL AWS STS session token for TEMPORARY credentials. It is NOT read from
  // storage (a stored temp credential would expire); it is populated IN MEMORY by resolveRuntimeDest when
  // an assumeRole policy mints short-lived credentials, alongside the temporary accessKeyId/secretAccessKey.
  // Credential-class: never persisted, never logged, never surfaced in a status view.
  sessionToken?: string;
  // assumeRole is the OPTIONAL STS AssumeRole policy. When present, accessKeyId/secretAccessKey are the
  // long-lived PRINCIPAL authorised only to assume the role, and resolveRuntimeDest mints short-lived
  // credentials per invocation (so they never expire mid-run). The role ARN is not secret; the externalId
  // is credential-class (the cross-account confused-deputy guard). region (above) is the STS region.
  assumeRole?: AssumeRolePolicy;
  // addressing is the OPTIONAL request-addressing style ("auto" | "path" | "vhost"). Absent/"auto" picks
  // virtual-hosted for AWS S3 and path-style elsewhere; an explicit value forces one. Non-secret.
  addressing?: Addressing;
  // storageClass is the OPTIONAL S3 storage class set on every write (a cost lever for cold backups). Only
  // the immediately-readable tiers are accepted (see validateStorageClass); absent = the bucket default.
  // Non-secret.
  storageClass?: string;
  // azureEntra is the OPTIONAL Microsoft Entra service principal for an AZURE BLOB destination: the
  // directory (tenant) id and the application (client) id, both non-secret. Its PRESENCE is what selects
  // Entra authentication over a Shared Key, and the third value the principal needs, the client secret, is
  // secretAccessKey above -- on an Entra destination that field holds the client secret exactly as it
  // holds the storage account key on a Shared Key one, so there is still one credential slot per
  // destination and every surface that already handles a destination secret handles this one unchanged.
  // Ignored on any endpoint that is not Azure Blob; the write boundary refuses it there rather than storing a credential nothing would read.
  azureEntra?: AzureEntraDirectory;
  checksumRequired?: true; // the probe learned the bucket refuses a write with no checksum; seeds the S3 destination
}

/**
 * Resolves a destination config for USE: when it carries an assumeRole policy, mints short-lived STS
 * credentials (with the stored long-lived principal) and returns a config whose accessKeyId/secretAccessKey
 * are the TEMPORARY credentials plus a sessionToken, with assumeRole cleared. Otherwise returns the config
 * unchanged. It is FAIL-CLOSED: an STS failure throws (the run/probe fails loudly and retries) and NEVER
 * falls back to writing with the long-lived principal. The returned temp-credential config is in-memory
 * only; it is never persisted or logged. Called inside buildDestination, so EVERY destination build mints
 * fresh credentials per invocation, and only the unresolved principal+policy is ever pinned/stored.
 *
 * @param config - the unresolved RuntimeDestConfig (principal + assumeRole), or null for the env path.
 * @returns the resolved config (temp credentials), or the input unchanged when there is no assumeRole.
 * @throws Error when the region is invalid or STS fails (fail-closed; never a long-lived-key fallback).
 */
export async function resolveRuntimeDest(config: RuntimeDestConfig | null): Promise<RuntimeDestConfig | null> {
  if (!config || config.assumeRole === undefined) return config;
  const policy = config.assumeRole;
  if (!isValidStsRegion(config.region)) {
    // Typed so the standing destBuildHealth names the knob (the region NAME, never its value).
    throw new DestBuildError("sts-region-invalid", `the destination region "${config.region}" is not a valid AWS region for STS AssumeRole; set it to the role's region`, { varName: "region" });
  }
  const temp = await assumeRole(
    { roleArn: policy.roleArn, region: config.region, ...(policy.externalId !== undefined ? { externalId: policy.externalId } : {}), ...(policy.durationSeconds !== undefined ? { durationSeconds: policy.durationSeconds } : {}) },
    { accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey },
  );
  // Return a config carrying the TEMPORARY credentials; clear assumeRole so a (defensive) re-resolution is
  // a no-op, and never carry the principal secret further than here.
  const { assumeRole: _dropped, ...rest } = config;
  return { ...rest, accessKeyId: temp.accessKeyId, secretAccessKey: temp.secretAccessKey, sessionToken: temp.sessionToken };
}

/**
 * azureEntraTokenSourceFor builds the Microsoft Entra token source for an Azure destination that carries a
 * service principal, or returns undefined for one that authenticates with a Shared Key.
 *
 * IT IS FAIL-LOUD ON A CLOUD IT CANNOT SERVE. dest/azure-entra.ts holds the login authority and storage
 * scope for the commercial cloud only, because those are the only two values that have been driven against
 * a real account; the US Government and China clouds are refused by name rather than guessed. The refusal is a typed
 * DestBuildError, so the standing destination-build health reports it as a configuration fault the
 * operator can act on, not as a credential that stopped working.
 *
 * @param cfg - the resolved destination config.
 * @returns the token source, or undefined when this destination does not use Entra.
 * @throws DestBuildError when the endpoint is in an Azure cloud whose Entra values are not established.
 */
function azureEntraTokenSourceFor(cfg: RuntimeDestConfig): AzureEntraTokenSource | undefined {
  if (cfg.azureEntra === undefined) return undefined;
  const resolution = azureEntraCloudFor(cfg.endpoint);
  if (!resolution.ok) throw new DestBuildError("config-incomplete", resolution.reason);
  return new AzureEntraTokenSource({ tenantId: cfg.azureEntra.tenantId, clientId: cfg.azureEntra.clientId, clientSecret: cfg.secretAccessKey }, resolution.cloud);
}

/**
 * The fail-safe result of reading a WORM policy from configuration. It distinguishes three states so
 * the writer and the posture agree on the same verdict:
 *   { configured:false }                              -> no WORM intended (the default): writes are unchanged.
 *   { configured:true, misconfigured:false, policy }  -> a valid armed policy: WORM headers are written.
 *   { configured:true, misconfigured:true }           -> WORM was intended but is invalid (e.g. only one of
 *        mode/days set, a bad mode, a non-positive window). Fail-safe: the writer is built without WORM
 *        (never writes unprotected while claiming protection) and the posture reports a misconfiguration
 *        warning rather than a green WORM claim.
 */
export type WormPolicyParse =
  | { configured: false }
  | { configured: true; misconfigured: false; policy: WormPolicy }
  | { configured: true; misconfigured: true };

/**
 * Reads the env DEST_WORM_* knobs into a fail-safe WormPolicyParse. Both DEST_WORM_MODE and
 * DEST_WORM_RETENTION_DAYS must be set together and valid to arm WORM; any partial or invalid state
 * is reported as configured-but-misconfigured (so the posture warns) and arms nothing, and neither
 * set is the honest "off". This is the single place env WORM config is interpreted, so the writer
 * and the posture read the exact same verdict.
 *
 * @param env - the Worker environment carrying the DEST_WORM_* vars.
 * @returns the fail-safe parse verdict.
 */
export function parseWormPolicy(env: Env): WormPolicyParse {
  const modeRaw = env.DEST_WORM_MODE?.trim();
  const daysRaw = env.DEST_WORM_RETENTION_DAYS?.trim();
  const anySet = (modeRaw !== undefined && modeRaw !== "") || (daysRaw !== undefined && daysRaw !== "");
  if (!anySet) return { configured: false };
  // From here a WORM policy is INTENDED (at least one knob set), so an invalid/partial value is a
  // misconfiguration to surface, never a silent fall-through to no-protection.
  const mode = normaliseWormMode(modeRaw);
  const days = daysRaw !== undefined && daysRaw !== "" ? Number(daysRaw) : NaN;
  if (mode === null || !Number.isInteger(days) || days <= 0) return { configured: true, misconfigured: true };
  return { configured: true, misconfigured: false, policy: { mode, retentionDays: days } };
}

// DoStoredDestConfig is the raw, UNVALIDATED shape the scheduler DO returns from /dest-config. Every
// field is optional and weakly typed on purpose: fetchDestConfig validates each one before use, so this
// interface only names the wire shape (the boundary), it does not assert any field is well-formed.
interface DoStoredDestConfig {
  endpoint?: string;
  bucket?: string;
  region?: string;
  accessKeyId?: string;
  secretAccessKey?: string | WrappedSecret;
  worm?: unknown;
  assumeRole?: unknown;
  addressing?: unknown;
  storageClass?: unknown;
  azureEntra?: unknown;
  source?: unknown; checksumRequired?: unknown; id?: unknown; pricing?: unknown;
}

/**
 * Reads the console-set destination from the scheduler DO (the internal full-value route; a DO
 * fetch never leaves the account). It returns null when no console destination is set (the env
 * fallback applies); a malformed stored WORM policy is dropped rather than passed through.
 *
 * The validation half (storedDestConfigForUse) is the READ-FOR-USE chokepoint every run, drill, restore,
 * canary, retention and replication pass funnels through (by way of resolveDestination), which is why it is
 * also where two kinds of evidence are recorded: the stored intents
 * this read is about to DISCARD (a corrupted assumeRole or WORM policy is dropped fail-safe, and the drop
 * is the invisible part, not the wrong part), and the closed cause of a credential that would not unwrap.
 * Both records are best-effort and never change what the read returns.
 *
 * @param scheduler - the scheduler Durable Object stub to fetch the config from.
 * @param destinationId - an optional destination id for per-downpipe routing; absent or null
 *   resolves the default.
 * @param wrapKey - the resolved CONFIG_WRAP_KEY, needed only when the stored secret is an at-rest
 *   envelope rather than the legacy plaintext string. Omitting it against an enveloped secret throws
 *   rather than signing with the envelope.
 * @returns the validated RuntimeDestConfig, or null when no console destination is set.
 * @throws DestBuildError when the DO responds non-ok (tagged config-do-unreadable, carrying the DO
 *   status, so "the destination is broken" and "the config plane is" stay distinguishable) or the stored
 *   config is missing a required field (config-incomplete, naming which one). Failing loudly here
 *   prevents a run being written to the wrong bucket.
 */
export async function fetchDestConfig(scheduler: DurableObjectStub, destinationId?: string | null, wrapKey?: Uint8Array): Promise<RuntimeDestConfig | null> {
  // An optional destinationId resolves a SPECIFIC destination (per-downpipe routing); absent or null
  // resolves the DEFAULT. wrapKey is the resolved CONFIG_WRAP_KEY (loadConfigWrapKey(env.CONFIG_WRAP_KEY)).
  //
  // THIS RETURNS ONE null FOR TWO DIFFERENT FACTS: "no console destination: use the env destination" and "no
  // record for that id". Code outside this module therefore never calls it: every consumer goes through
  // resolveDestination below, which keeps the two apart (test/validate-dest-resolution-single-path.ts
  // enforces that). It stays exported for the offline validators that read a stored credential back.
  const raw = await readStoredDestRecord(scheduler, destinationId);
  if (!raw || raw.source === "deploy") return null;
  return storedDestConfigForUse(scheduler, raw, wrapKey);
}

// readStoredDestRecord is the one DO read of a stored destination row: by id, or the default with no id. It
// returns the RAW, unvalidated row (null when the DO holds none). Only this module reads the row.
async function readStoredDestRecord(scheduler: DurableObjectStub, destinationId?: string | null): Promise<DoStoredDestConfig | null> {
  const url = destinationId ? `https://scheduler.internal/dest-config?id=${encodeURIComponent(destinationId)}` : "https://scheduler.internal/dest-config";
  const resp = await scheduler.fetch(url, { method: "GET" });
  // The destination may be perfectly healthy -- we could not READ its config. The clamped DO status is the
  // one fact that separates "the destination is broken" from "the config plane is". Never the response body.
  if (!resp.ok) throw new DestBuildError("config-do-unreadable", `destination configuration unreadable (DO responded ${resp.status})`, { doStatus: resp.status });
  const { config } = (await resp.json()) as { config?: DoStoredDestConfig | null };
  return config ?? null;
}

// storedDestConfigForUse validates a console-stored row (never a source:"deploy" one) into the RuntimeDestConfig
// a Destination is built from, recording the intents it discards and opening an enveloped credential.
async function storedDestConfigForUse(scheduler: DurableObjectStub, config: DoStoredDestConfig, wrapKey?: Uint8Array): Promise<RuntimeDestConfig> {
  const { endpoint, bucket, region, accessKeyId } = config;
  // The secret is stored as a plaintext string (legacy floor) or an AES-256-GCM envelope (when
  // CONFIG_WRAP_KEY is set); both are "present", only the empty string is missing.
  const storedSecret = config.secretAccessKey;
  const secretPresent = typeof storedSecret === "string" ? storedSecret !== "" : isWrappedSecret(storedSecret);
  // NAME what this read is about to silently DISCARD, before it discards it. Every validator below is
  // fail-safe by DROPPING (a corrupted assumeRole policy is dropped and the engine then signs with the
  // long-lived PRINCIPAL, so every cross-account write is AccessDenied forever; a dropped WORM policy leaves
  // the console claiming immutability the writer is not applying). The drop is right; its INVISIBILITY is the
  // bug. The pack cannot re-derive it, either: the DO's /destinations read returns the already-sanitised row.
  // So it is recorded HERE, at the read-for-use site, as closed counter names -- never the malformed value.
  await recordStoredDestAnomalies(scheduler, config, secretPresent);
  if (!endpoint || !bucket || !region || !accessKeyId || !secretPresent) {
    // Names WHICH stored field is missing, from the CLOSED field vocabulary (a product token, never a
    // value). The message is unchanged, so every downstream classification behaves exactly as before.
    const missing = !endpoint ? "endpoint" : !bucket ? "bucket" : !region ? "region" : !accessKeyId ? "accessKeyId" : "secretAccessKey";
    throw new DestBuildError("config-incomplete", "the stored destination configuration is incomplete", { varName: missing });
  }
  // Decrypt at the moment of use. resolveConfigSecret returns the plaintext for both shapes and throws
  // loudly if an envelope is present but the key is absent, so a request is never signed with the
  // opaque envelope nor silently routed with a wrong credential.
  // This is the READ-FOR-USE chokepoint every run, drill, restore, canary, retention and replication
  // pass funnels through, so it is where the wrap-key fault TIMELINE is recorded. resolveConfigSecret TAGS its
  // throw with the closed cause (a rotated key vs a damaged record vs an unbound env var vs a malformed key --
  // four different remediations that would otherwise read as one lazily-failing destination error days later).
  // The throw is RE-THROWN unchanged: the read fails exactly the same way, it simply stops failing silently.
  let secretAccessKey: string;
  try {
    secretAccessKey = await resolveConfigSecret(wrapKey, storedSecret as string | WrappedSecret);
  } catch (e) {
    const cause = unwrapFaultCauseOf(e);
    if (cause !== null) await recordUnwrapFault(scheduler, cause);
    throw e;
  }
  // worm is OPTIONAL on a stored destination (a per-destination WORM policy). It is VALIDATED here so a
  // malformed stored value never reaches the writer as a partial policy; only a fully-valid policy is
  // attached. buildDestination re-validates before arming, so even a value that slips through arms nothing.
  // A malformed stored policy is therefore simply dropped (fail-safe: no false protection); the immutability
  // posture then leans on the live capability probe rather than a claimed-but-unapplied policy.
  const worm = validateWormPolicyValue(config.worm);
  // assumeRole is the OPTIONAL stored STS policy (role ARN + optional externalId/duration). It is returned
  // UNRESOLVED here (the principal accessKeyId/secretAccessKey above are the assume-role principal);
  // buildDestination mints the temporary credentials per invocation via resolveRuntimeDest. A malformed
  // policy is dropped (fail-safe), exactly like worm.
  const assume = validateAssumeRolePolicy(config.assumeRole);
  const addr = validateAddressing(config.addressing);
  const sc = validateStorageClass(config.storageClass);
  // azureEntra is the OPTIONAL stored service principal (tenant id + client id, neither secret). It is
  // validated here and DROPPED when malformed, fail-safe exactly like worm and assumeRole. The drop is
  // safe in the loud direction: without it the Azure client reads secretAccessKey as a storage account
  // key, which fails to authenticate rather than authenticating as something nobody configured.
  const entra = validateAzureEntraDirectory(config.azureEntra);
  return { endpoint, bucket, region, accessKeyId, secretAccessKey, ...(worm !== null ? { worm } : {}), ...(assume !== null ? { assumeRole: assume } : {}), ...(addr !== undefined ? { addressing: addr } : {}), ...(sc !== undefined ? { storageClass: sc } : {}), ...(entra !== null ? { azureEntra: entra } : {}), ...(config.checksumRequired === true ? { checksumRequired: true as const } : {}) };
}

/**
 * recordStoredDestAnomalies counts the STORED destination-config intents this read is discarding, under
 * the closed admin-counter names, in the DO's bounded aggregate. Best-effort and NEVER throwing: a diagnostic
 * write must not stop a backup, and recordDiagWrite already counts a DROPPED write of its own, so a pack can
 * never read "no anomalies" when the truth is "the recorder could not reach the DO".
 *
 * The raw config is read ONLY to select closed enum members (classifyStoredDestAnomalies); the malformed
 * value -- which may be an endpoint, a bucket, a role ARN, an externalId or a credential -- never leaves this
 * call. A clean config posts nothing at all.
 *
 * @param scheduler - the scheduler DO stub.
 * @param config - the raw stored destination row.
 * @param secretPresent - whether the stored secret is present in either at-rest shape.
 */
async function recordStoredDestAnomalies(scheduler: DurableObjectStub, config: DoStoredDestConfig, secretPresent: boolean): Promise<void> {
  try {
    const bumps = anomalyBumps(classifyStoredDestAnomalies(config, secretPresent));
    if (Object.keys(bumps).length === 0) return;
    await recordDiagWrite(scheduler, "admin-counter", () =>
      scheduler.fetch("https://scheduler.internal/diag/admin-counters", {
        method: "POST",
        body: JSON.stringify({ bumps }),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: observing a discarded config must never break the read that discarded it */
  }
}

// ---------------------------------------------------------------------------------------------------------
// DESTINATION-ID RESOLUTION: the ONE place a destination id becomes something a Destination is built from.
//
// A downpipe names its destinations by id (destinationIds). Three kinds of id exist: a console-stored
// destination, the synthetic deploy-time destination (DEPLOY_DEST_ID, source:"deploy", seeded when the first
// console destination joins a deploy-time binding), and an id with no record (a removed destination). The
// first two are both configured destinations; only the third is not. Every consumer that resolves an id --
// the seal choice, the fan-out failover, replication (target and origin), the canary, restore and drill reads,
// retention pruning, the orphan reconcile, the control-plane export and destination verify -- calls
// resolveDestination, so a consumer cannot read the deploy-time destination as "not configured".
// test/validate-dest-resolution-single-path.ts fails the build if any src file resolves an id another way.
// ---------------------------------------------------------------------------------------------------------

/** The branch the resolver took. A closed vocabulary: the support pack carries it per configured id. */
export const DEST_RESOLUTION_BRANCHES = ["console-stored", "deploy-env-binding", "env-no-collection", "missing", "deploy-binding-missing"] as const;
/** One member of DEST_RESOLUTION_BRANCHES: the branch a single resolveDestination call took. */
export type DestResolutionBranch = (typeof DEST_RESOLUTION_BRANCHES)[number];
/**
 * A resolved destination id. ok:true carries the override buildDestination takes (null means the env-backed
 * destination). ok:false carries the closed reason the id cannot be served:
 *   not-configured          the id names no stored destination (a removed destination under a live downpipe)
 *   deploy-binding-missing  the id is DEPLOY_DEST_ID but this deployment declares no env destination at all
 *                           (no DEST_R2 binding and no DEST_* variables), so there is nothing for it to name
 * storedId is the id of the stored row the resolver used (the named id, or the DEFAULT's own id when none was
 * named), so a default-routed run can record the destination it actually sealed to. Absent when no stored
 * row was read: an env-only estate (env-no-collection) has no destination id to record.
 */
export type DestResolution =
  | { ok: true; branch: "console-stored"; config: RuntimeDestConfig; storedId?: string }
  | { ok: true; branch: "deploy-env-binding"; config: null; storedId?: string }
  | { ok: true; branch: "env-no-collection"; config: null }
  | { ok: false; branch: "missing"; reason: "not-configured" }
  | { ok: false; branch: "deploy-binding-missing"; reason: "deploy-binding-missing" };


/**
 * envDestinationDeclared reports whether this deployment declares an env-backed destination at all: the DEST_R2
 * binding, or any DEST_* S3 variable. It answers "is there something for the deploy-time id to name", not "will
 * it build": a declared but broken env destination still fails in buildDestination with its own typed cause
 * (a missing variable, an ambiguous kind), which is the more specific answer.
 *
 * @param env - the Worker environment.
 * @returns true when an env destination is declared.
 */
export function envDestinationDeclared(env: Env): boolean {
  if (env.DEST_R2 !== undefined && env.DEST_R2 !== null) return true;
  return [env.DEST_ENDPOINT, env.DEST_BUCKET, env.DEST_REGION, env.DEST_ACCESS_KEY_ID, env.DEST_SECRET_ACCESS_KEY].some((v) => typeof v === "string" && v.trim() !== "");
}

/**
 * resolveDestination resolves a destination id (or the default, with no id) into what buildDestination takes.
 *
 * - An id naming a console-stored destination: ok, branch console-stored, its validated config.
 * - DEPLOY_DEST_ID (or a default that IS the deploy-time record): ok, branch deploy-env-binding, config null,
 *   which buildDestination turns into the env-backed destination (the DEST_R2 binding or the DEST_* vars).
 *   DEPLOY_DEST_ID resolves this way with or without its stored stand-in row, so not-configured never names it.
 * - No id and no stored destinations at all: ok, branch env-no-collection, config null (a deployment that
 *   has only ever had its deploy-time destination).
 * - Any other id with no record: ok:false, not-configured.
 * - DEPLOY_DEST_ID NAMED explicitly while no env destination is declared: ok:false, deploy-binding-missing.
 *   The default is never refused here: with no id, buildDestination names the missing env variable itself.
 *
 * It throws only what the read itself throws: the DO could not be read (config-do-unreadable), a stored
 * config is incomplete (config-incomplete), or its credential would not unwrap. Those are faults of the
 * config plane, not answers about the id, and every caller already handles them as such.
 *
 * @param env - the Worker environment (read only to decide deploy-binding-missing).
 * @param scheduler - the scheduler DO stub.
 * @param destinationId - the id to resolve; absent, null or "" resolves the default.
 * @param wrapKey - the resolved CONFIG_WRAP_KEY, for an enveloped stored credential.
 * @returns the resolution.
 */
export async function resolveDestination(env: Env, scheduler: DurableObjectStub, destinationId: string | null | undefined, wrapKey?: Uint8Array): Promise<DestResolution> {
  // Each branch literal says `satisfies DestResolutionBranch`: the union arm alone types it as one literal, and
  // the dead-vocabulary gate cannot tell whose vocabulary a one-literal slot belongs to.
  const id = typeof destinationId === "string" && destinationId !== "" ? destinationId : null;
  const raw = await readStoredDestRecord(scheduler, id);
  if (raw === null) {
    // DEPLOY_DEST_ID names the env destination whether or not its stand-in row is stored. The row can be gone
    // while downpipes still name the id: clearing the default through the singular POST /destination route
    // removes it with no pin check. Without this arm that estate read "deploy" as not-configured while DEST_R2
    // was bound, which is the engine 0.3.5 fault class this resolver exists to end.
    if (id === DEPLOY_DEST_ID) return envDestinationDeclared(env) ? { ok: true, branch: "deploy-env-binding" satisfies DestResolutionBranch, config: null } : { ok: false, branch: "deploy-binding-missing" satisfies DestResolutionBranch, reason: "deploy-binding-missing" };
    if (id !== null) return { ok: false, branch: "missing" satisfies DestResolutionBranch, reason: "not-configured" };
    return { ok: true, branch: "env-no-collection" satisfies DestResolutionBranch, config: null };
  }
  const storedId = typeof raw.id === "string" && raw.id !== "" ? raw.id : (id ?? undefined);
  const withId = storedId !== undefined ? { storedId } : {};
  if (raw.source === "deploy" || id === DEPLOY_DEST_ID) {
    if (id !== null && !envDestinationDeclared(env)) return { ok: false, branch: "deploy-binding-missing" satisfies DestResolutionBranch, reason: "deploy-binding-missing" };
    return { ok: true, branch: "deploy-env-binding" satisfies DestResolutionBranch, config: null, ...withId };
  }
  return { ok: true, branch: "console-stored" satisfies DestResolutionBranch, config: await storedDestConfigForUse(scheduler, raw, wrapKey), ...withId };
}


/**
 * resolveDefaultDestConfig resolves the account DEFAULT destination (no id) into buildDestination's override:
 * the default console-stored destination's config, or null for the env-backed destination (the deploy-time
 * record as the default, or no stored destinations at all). The default is never refused (see
 * resolveDestination), so this is total apart from the config-plane faults the read throws.
 *
 * @param env - the Worker environment.
 * @param scheduler - the scheduler DO stub.
 * @param wrapKey - the resolved CONFIG_WRAP_KEY.
 * @returns the override for buildDestination.
 */
export async function resolveDefaultDestConfig(env: Env, scheduler: DurableObjectStub, wrapKey?: Uint8Array): Promise<RuntimeDestConfig | null> {
  const res = await resolveDestination(env, scheduler, null, wrapKey);
  return res.ok ? res.config : null;
}

/**
 * flushPendingDestIo reports this isolate's pending destination-DEGRADATION tally to the DO. The dest
 * layer has no end-of-run hook of its own, so the tally noted during one slice is carried by the NEXT
 * buildDestination in this isolate -- the diag-writer.ts piggy-back protocol, verbatim (the cron seal loop
 * builds a destination per run, so any account with a live schedule flushes continuously). A no-op when
 * nothing is pending, so a healthy destination costs no subrequest. NEVER throws.
 *
 * @param env - the Worker environment (its SCHEDULER binding is the sink).
 */
async function flushPendingDestIo(env: Env): Promise<void> {
  if (Object.keys(pendingDestIo()).length === 0) return;
  try {
    const ns = env.SCHEDULER as DurableObjectNamespace | undefined;
    // A context with no scheduler binding (a validator's fake env, a double) cannot flush. Count the LOSS
    // rather than dropping it silently: absence of evidence must never read as absence of degradation.
    if (ns === undefined || typeof ns.idFromName !== "function") {
      noteDestIoWriteLost();
      return;
    }
    await flushDestIo(ns.get(ns.idFromName("account-scheduler")));
  } catch {
    /* best-effort: a diagnostic flush must never break the backup it is observing */
  }
}

// buildDestination chooses the archive destination from configuration so the run pipeline
// and the restore drill write through whichever store the customer configured, rather than
// hard-wiring S3. The choice is total and fail-loud: an explicit DEST_KIND ("r2" or "s3")
// always wins, an unrecognised DEST_KIND is rejected so a typo cannot silently fall back to
// S3, and with no DEST_KIND the ambiguous case where BOTH an R2 binding and S3 credentials
// are present is refused rather than silently preferring one. R2 is the same-account binding
// path (no credentials on the wire); S3 is the portable path to any S3-compatible bucket,
// Google Cloud Storage's S3-interoperable endpoint included. DEST_KIND stays a two-member
// WIRE selector: an AZURE BLOB endpoint is dispatched to AzureBlobDestination, its own client
// with its own signer, by providerForEndpoint on the resolved endpoint rather than by a third
// DEST_KIND value. All three implement the same Destination contract, so the pipeline is agnostic.
// The optional meter reports every destination subrequest into the sliced seal's budget;
// callers that do not slice (the drill, the restore path) omit it.
// The optional override is the CONSOLE-SET RuntimeDestConfig (fetched from the scheduler DO
// by the caller): when present it wins over every env fact, including DEST_KIND, the
// console-set destination IS the explicit choice, set later and more deliberately than the
// deploy-time vars, and precedence must be total so the selected store never depends on
// which env vars happen to linger.
/**
 * Chooses the archive destination from configuration so the pipeline and drill write through
 * whichever store the customer configured. The choice is total and fail-loud: a console-set
 * override wins over every env fact; otherwise an explicit DEST_KIND wins, an unrecognised
 * DEST_KIND is rejected, and with no DEST_KIND the ambiguous both-R2-and-S3 case is refused. WORM
 * is armed only from a valid policy.
 *
 * @param env - the Worker environment carrying the DEST_* and DEST_WORM_* vars and the DEST_R2
 *   binding.
 * @param meter - an optional meter that records each destination subrequest into a slice budget.
 * @param override - the optional console-set RuntimeDestConfig; when present it wins over env.
 * @param destinationId - the resolved destination id, when the caller has one: it labels the instance so the
 *   degradation it records can be attributed to that id (dest-io.ts).
 * @returns the selected Destination: AzureBlobDestination when the resolved endpoint is an Azure
 *   Blob host, otherwise S3Destination or R2Destination.
 * @throws Error when DEST_KIND is set to anything but "r2" or "s3", the destination is ambiguous,
 *   a required S3 var is missing, the S3 endpoint is non-https, an explicit vhost addressing's bucket
 *   contains a character that would break out of the request host, the Azure storage account does not
 *   match the endpoint host, the env endpoint is an ADLS Gen2 dfs host, or the R2 binding is missing.
 */
export async function buildDestination(env: Env, meter?: Meter, override?: RuntimeDestConfig | null, destinationId?: string): Promise<Destination> {
  // The WHOLE construction is OBSERVED, so "every backup has been failing to even BUILD its
  // destination since Tuesday, because DEST_ENDPOINT is gone" becomes a standing fact in the pack instead of a
  // coarse per-run error class. The observation NEVER changes the build: the inner throw is rethrown verbatim,
  // and the recorder is best-effort and never throws.
  try {
    const dest = await buildDestinationInner(env, meter, override);
    // A caller that resolved a destination id labels the instance, so the timeouts it records are attributed
    // to that id in the pack (dest-io.ts). The label is the customer's own destination id; it changes nothing
    // about the build or the writes.
    if (destinationId !== undefined && destinationId !== "") dest.labelIo?.(destinationId);
    await recordDestBuildOk(env);
    return dest;
  } catch (e) {
    await recordDestBuildFailure(env, e);
    throw e;
  }
}

// buildDestinationInner is the construction itself: byte-for-byte the prior buildDestination body.
async function buildDestinationInner(env: Env, meter?: Meter, override?: RuntimeDestConfig | null): Promise<Destination> {
  // Resolve an STS AssumeRole policy (if any) to FRESH temporary credentials before building, so every
  // invocation mints its own short-lived creds (they never expire mid-run, even across the park window)
  // and only the unresolved principal+policy is ever pinned/stored. Fail-closed: an STS failure throws
  // here rather than ever writing with the long-lived principal. A non-STS override is returned unchanged.
  const resolved = await resolveRuntimeDest(override ?? null);
  // Piggy-back the previous destination instance's DEGRADATION tally onto this build: the dest layer
  // has no end-of-run hook, and this is the one call every run, drill, replicate and restore passes through.
  await flushPendingDestIo(env);
  if (resolved) {
    // WORM precedence for a console-set destination: its OWN policy wins; only when it carries none do
    // we fall back to the env policy. Either source is armed ONLY when valid (validateWormPolicyValue /
    // parseWormPolicy), so a misconfigured policy arms nothing here, the writer never claims protection
    // it is not applying; the posture surfaces the misconfiguration separately.
    const overrideWorm = resolved.worm !== undefined ? validateWormPolicyValue(resolved.worm) ?? undefined : undefined;
    const envParse = parseWormPolicy(env);
    const worm = overrideWorm ?? (envParse.configured && !envParse.misconfigured ? envParse.policy : undefined);
    // AZURE IS A DIFFERENT CLIENT, not a differently-configured S3 one. R2 and Google Cloud Storage both
    // reach this same S3Destination because both speak the S3 XML API with SigV4; Azure Blob does not, so
    // it is dispatched here to its own client with its own Shared Key signer.
    //
    // The credential pair is REUSED rather than given new fields: an Azure destination stores the storage
    // ACCOUNT in accessKeyId and one of its access KEYS in secretAccessKey. That keeps the stored config
    // shape, the envelope-encryption of the secret, and the whole console credential path byte-identical,
    // and the account is cross-checked against the endpoint host below so a mismatch fails loud at
    // construction rather than as a 403 nothing explains.
    if (providerForEndpoint(resolved.endpoint) === "azure") {
      // THE CREDENTIAL KIND is chosen here and applied inside the client's own authorise() seam. An
      // azureEntra directory on the config means the stored secretAccessKey is a service principal's
      // CLIENT SECRET rather than a storage account key, so the account key handed to the client is ""
      // and the token source carries the credential instead. The cloud's login authority and storage
      // scope are DERIVED from the endpoint host, never stored, so a US Government endpoint can never be
      // pointed at the commercial login authority by a stale field.
      const entra = azureEntraTokenSourceFor(resolved);
      return buildAzureDestination(env, meter, resolved, worm, entra);
    }
    // An adaptive destination pacer (T1-A) is built from the env knobs and shared by every S3 destination
    // (the run path AND the 3-2-1 replicate path, which both build through here, so the replica bulk-copy
    // loop is paced too). It is per-invocation/per-destination scope, exactly like CfPacer.
    return new S3Destination(resolved.endpoint, resolved.bucket, resolved.region, resolved.accessKeyId, resolved.secretAccessKey, {
      ...(meter !== undefined ? { meter } : {}),
      ...(worm !== undefined ? { worm } : {}),
      pacer: destPacerFromEnv(env),
      // sessionToken is present only when resolveRuntimeDest minted temporary STS credentials into this
      // config; a long-lived-key destination leaves it undefined (byte-identical to before).
      ...(resolved.sessionToken !== undefined ? { sessionToken: resolved.sessionToken } : {}),
      ...(resolved.addressing !== undefined ? { addressing: resolved.addressing } : {}),
      ...(resolved.storageClass !== undefined ? { storageClass: resolved.storageClass } : {}), ...(resolved.checksumRequired === true ? { checksumRequired: true } : {}),
    });
  }
  const r2 = env.DEST_R2 as R2Bucket | undefined;
  if (resolveUseR2(env, r2)) {
    if (!r2) throw new DestBuildError("r2-binding-missing", "missing required configuration: DEST_R2", { varName: "DEST_R2" });
    return new R2Destination(r2, meter);
  }
  return buildEnvDestination(env, meter);
}

/** The four fields an Azure Blob destination is built from, whichever path supplied them. */
interface AzureDestFields {
  endpoint: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
}

/**
 * buildAzureDestination builds the Azure Blob client for a destination whose endpoint is a blob host. The
 * console-set branch and the env branch both call it, so an Azure host reaches the Azure client and its own
 * signer from either source. Before engine 0.3.7 only the console-set branch did this: an env DEST_ENDPOINT
 * on a blob host went to the S3 client, where SigV4 answers 403 on the first call, while the status surface
 * already labelled that destination as Azure.
 *
 * @param env - the Worker environment, read for the pacer knobs.
 * @param meter - the optional slice-budget meter.
 * @param f - the endpoint, the container, the storage account (blank means the account in the host) and
 *   the secret (an account key or a SAS).
 * @param worm - the resolved, valid immutability policy, or undefined.
 * @param entra - the Entra token source, or undefined when the secret is a key or a SAS.
 * @returns the Azure Blob destination.
 * @throws DestBuildError when a Shared Key account does not match the endpoint host, or when the Azure
 *   client refuses the endpoint or the credential at construction.
 */
function buildAzureDestination(env: Env, meter: Meter | undefined, f: AzureDestFields, worm: WormPolicy | undefined, entra: AzureEntraTokenSource | undefined): Destination {
  const fromHost = azureAccountFromHost(f.endpoint);
  const account = f.accessKeyId.trim() === "" ? fromHost : f.accessKeyId.trim();
  // THE STORED SECRET CARRIES EITHER an account access key or a shared access signature, and which one
  // it is is read off its SHAPE rather than from a second stored field. That keeps the config schema,
  // the envelope-encryption of the secret and the whole console credential path unchanged, and the
  // discriminator is structural rather than a substring search precisely so a key can never be mistaken
  // for a token: an account key is 88 characters of base64 with no "&" in it at all, and a SAS is a
  // query string that always has several parameters and always has `sig`. See looksLikeAzureSasToken.
  const sasToken = looksLikeAzureSasToken(f.secretAccessKey) ? f.secretAccessKey.trim() : undefined;
  // The account-versus-host cross-check is a SHARED KEY invariant and does not apply to a SAS. A Shared
  // Key signature is computed against one account name, so a mismatch there is a 403 that names
  // nothing, which is why it fails loud here. A SAS carries no account name for us to disagree with:
  // it is signed for whatever resource it was minted against, and the live probe is what establishes
  // whether that is this container.
  if (sasToken === undefined && fromHost !== "" && account !== fromHost) {
    throw new DestBuildError(
      "config-incomplete",
      // WRITTEN TO FIT THE SURFACE THAT CARRIES IT. classifyProbeError (admin/router-posture.ts:198)
      // clips a probe reason to 200 characters and then appends "Check the bucket name, the endpoint
      // and that the credentials allow object read and write on that bucket". A longer message would
      // end mid-word and send the operator to audit a credential that was never wrong, so this stays
      // short enough to survive the cap whole rather than widening a cap that exists for a reason.
      // Both account names are bounded (Azure allows at most 24 characters), so the worst case stays
      // well inside it.
      `the Azure storage account ${JSON.stringify(account)} is not the account in the endpoint host, ${JSON.stringify(fromHost)}. A Shared Key signature is scoped to one account, so these must match.`,
    );
  }
  // The meter rides through exactly as it does for the S3 client. It is not optional plumbing: the sliced
  // seal and the 3-2-1 replication pass both build their destination WITH the slice budget as the
  // meter, and a destination that ignores it spends the invocation's subrequests without the pass ever
  // learning it should yield.
  //
  // The PACER rides through for the same reason it does for S3, and from the same env knobs: an Azure
  // account has its own request-rate, ingress and egress targets and answers 503 ServerBusy when they
  // are exceeded, so a destination built without one is driven at full rate into a store that is
  // already asking for less. DEST_RATE_PER_SEC and DEST_BURST govern both arms, because they describe
  // how hard this engine drives A destination and not which protocol it speaks.
  // WORM rides through on the same terms it does for the S3 client: the policy the caller resolved
  // (the console-set one, else the env one, either way only when valid) maps onto Azure's own per-blob
  // immutability headers, because the Azure client has nowhere else to put it.
  //
  // All three kinds meet here because all three are the SAME destination with a different way of
  // proving who is asking. Precedence is Entra, then SAS, then the account key, and it is written as
  // one expression so no two of them can be armed at once.
  return new AzureBlobDestination(f.endpoint, f.bucket, account, entra === undefined ? f.secretAccessKey : "", {
    ...(meter !== undefined ? { meter } : {}),
    pacer: destPacerFromEnv(env),
    ...(entra !== undefined ? { entra } : {}),
    ...(sasToken !== undefined ? { sasToken } : {}),
    ...(worm !== undefined ? { worm } : {}),
  });
}

// resolveUseR2 disambiguates the env-only destination kind: an explicit DEST_KIND ("r2"/"s3") wins (an
// unrecognised value is rejected); with no DEST_KIND the both-R2-and-S3 case is refused as ambiguous,
// otherwise the presence of the DEST_R2 binding decides. Returns true to use R2, false to use env S3.
function resolveUseR2(env: Env, r2: R2Bucket | undefined): boolean {
  const kind = env.DEST_KIND?.trim();
  if (kind !== undefined && kind !== "r2" && kind !== "s3") {
    throw new DestBuildError("kind-unrecognised", `DEST_KIND must be "r2" or "s3" when set (got ${JSON.stringify(env.DEST_KIND)})`, { varName: "DEST_KIND" });
  }
  const s3Configured = Boolean(
    env.DEST_ENDPOINT || env.DEST_BUCKET || env.DEST_REGION || env.DEST_ACCESS_KEY_ID || env.DEST_SECRET_ACCESS_KEY,
  );
  if (kind === "r2") return true;
  if (kind === "s3") return false;
  if (r2 !== undefined && s3Configured) {
    throw new DestBuildError("kind-ambiguous", 'ambiguous destination: both DEST_R2 and S3 credentials are configured; set DEST_KIND to "r2" or "s3"', { varName: "DEST_KIND" });
  }
  return r2 !== undefined;
}

// buildEnvDestination builds the destination from the DEST_* env vars (the non-override, non-R2 path).
// The S3 store constructor rejects a non-https DEST_ENDPOINT (V12.3.1: no fallback to unencrypted transport),
// so a misconfigured http:// endpoint fails loud rather than transmitting the SigV4 credential and archive
// bytes in cleartext. There is no exception here: the http://localhost / 127.0.0.1 / [::1]
// allowance in requireHttpsEndpoint is a test seam this builder does not pass, so
// a DEST_ENDPOINT of http://localhost:9000 fails at construction instead of building a destination that
// signs the SigV4 credential onto a cleartext request.
//
// WORM is armed ONLY from a valid env policy (parseWormPolicy); a misconfigured or absent policy
// arms nothing (undefined), so a non-WORM deployment is byte-unchanged and a misconfigured one fails safe to
// no-protection-plus-posture-warning rather than a false claim.
//
// THE ENDPOINT PICKS THE CLIENT here exactly as it does on the console-set path. From engine 0.3.7 an Azure
// blob host goes to buildAzureDestination, and an ADLS Gen2 dfs host is refused with the same reason the
// write boundary gives. Before that, both went to the S3 client and answered 403 on the first call, while
// admin/status.ts resolveDestKind already reported the blob host as Azure. The Azure arm reads the same
// vars the console-set arm reads from the stored config: DEST_ACCESS_KEY_ID is the storage account (blank
// means the account in the host) and DEST_SECRET_ACCESS_KEY is an account key or a SAS. DEST_REGION is not
// required, because no Azure module reads a region. DEST_ADDRESSING and DEST_STORAGE_CLASS are not passed:
// the Azure client has no place for either (provider.ts AZURE_REFUSED_FIELDS), and the console-set arm
// drops them in the same way. The env path carries no Entra directory, so Entra stays console-set only.
function buildEnvDestination(env: Env, meter?: Meter): Destination {
  const envParse = parseWormPolicy(env);
  const worm = envParse.configured && !envParse.misconfigured ? envParse.policy : undefined;
  const endpoint = requireEnv(env.DEST_ENDPOINT, "DEST_ENDPOINT");
  const unusable = unusableEndpoint(endpoint);
  if (unusable !== null) throw new DestBuildError("endpoint-unusable", UNUSABLE_ENDPOINT_REASON[unusable], { varName: "DEST_ENDPOINT" });
  if (providerForEndpoint(endpoint) === "azure") {
    return buildAzureDestination(env, meter, {
      endpoint,
      bucket: requireEnv(env.DEST_BUCKET, "DEST_BUCKET"),
      accessKeyId: env.DEST_ACCESS_KEY_ID ?? "",
      secretAccessKey: requireEnv(env.DEST_SECRET_ACCESS_KEY, "DEST_SECRET_ACCESS_KEY"),
    }, worm, undefined);
  }
  const envAddressing = validateAddressing(env.DEST_ADDRESSING);
  const envStorageClass = validateStorageClass(env.DEST_STORAGE_CLASS);
  return new S3Destination(
    endpoint,
    requireEnv(env.DEST_BUCKET, "DEST_BUCKET"),
    requireEnv(env.DEST_REGION, "DEST_REGION"),
    requireEnv(env.DEST_ACCESS_KEY_ID, "DEST_ACCESS_KEY_ID"),
    requireEnv(env.DEST_SECRET_ACCESS_KEY, "DEST_SECRET_ACCESS_KEY"),
    { ...(meter !== undefined ? { meter } : {}), ...(worm !== undefined ? { worm } : {}), pacer: destPacerFromEnv(env), ...(envAddressing !== undefined ? { addressing: envAddressing } : {}), ...(envStorageClass !== undefined ? { storageClass: envStorageClass } : {}) },
  );
}

// requireEnv is the env gate for the DEST_* vars. An absent var is a TYPED build fault carrying the
// var NAME from the engine's OWN closed vocabulary (never its value), so a redeploy that wipes the destination
// vars, after which every backup fails at construction, is attributable from the pack alone.
function requireEnv(v: string | undefined, name: string): string {
  if (!v) throw new DestBuildError("env-missing", `missing required configuration: ${name}`, { varName: name });
  return v;
}

// ---------------------------------------------------------------------------------------------------------
// The STANDING destination-build health recorder.
//
// COST DISCIPLINE. A FAILURE is always recorded (it is rare, and it is the whole point). A SUCCESS is recorded
// only ONCE per isolate, or after this isolate has seen a failure -- so the healthy steady state costs at most
// one extra DO subrequest per isolate lifetime, while a RECOVERY still clears failingSinceAt promptly (the very
// next successful build in the isolate that observed the failure reports it, and a fresh isolate reports its
// first success anyway). Both writes route through recordDiagWrite, so a DROPPED build-health write is itself
// counted in droppedWrites["dest-build-health"] rather than reading back as "no faults".
//
// NO-CUSTODY: the only bytes on the wire are {ok} or {cause, varName, stsFailureClass, doStatus} -- all closed
// vocabulary members and a clamped int. The construction error's MESSAGE (which can embed the endpoint, the
// bucket or the region) is never sent, and destBuildFaultOf classifies by TYPE, never by text.
// ---------------------------------------------------------------------------------------------------------

// destBuildOkReported is the isolate-local "we have already told the DO this destination builds" flag.
let destBuildOkReported = false;

// schedulerStub resolves the account scheduler DO from env, or null in a context that has no binding (a
// validator's fake env, a test double). Mirrors flushPendingDestIo's own resolution.
function schedulerStub(env: Env): DurableObjectStub | null {
  const ns = env.SCHEDULER as DurableObjectNamespace | undefined;
  if (ns === undefined || typeof ns.idFromName !== "function") return null;
  return ns.get(ns.idFromName("account-scheduler"));
}

// postDestBuild is the one wire shape. Best-effort and never throwing: observing a build must never break it.
async function postDestBuild(env: Env, body: Record<string, unknown>): Promise<void> {
  try {
    const scheduler = schedulerStub(env);
    if (scheduler === null) return;
    await recordDiagWrite(scheduler, "dest-build-health", () =>
      scheduler.fetch("https://scheduler.internal/diag/dest-build", {
        method: "POST",
        body: JSON.stringify(body),
        headers: { "content-type": "application/json" },
      }),
    );
  } catch {
    /* best-effort: a diagnostic write must never break the build it is observing */
  }
}

/**
 * recordDestBuildOk reports a SUCCESSFUL destination build, which is what CLEARS the standing failing state
 * (failingSinceAt + the consecutive count). Bounded by the isolate-local flag so a healthy fleet does not pay a
 * DO subrequest per run.
 *
 * @param env - the Worker environment (its SCHEDULER binding is the sink).
 */
async function recordDestBuildOk(env: Env): Promise<void> {
  if (destBuildOkReported) return;
  destBuildOkReported = true;
  await postDestBuild(env, { ok: true });
}

/**
 * recordDestBuildFailure reports a FAILED destination build with its closed cause. The error is classified by
 * TYPE (destBuildFaultOf reads the DestBuildError tag the throw sites set); an untagged throw records the
 * residual "other" cause rather than guessing from its message -- which is exactly the free-text leak this
 * vocabulary exists to prevent.
 *
 * @param env - the Worker environment.
 * @param e - the thrown construction error (its message is never sent).
 */
async function recordDestBuildFailure(env: Env, e: unknown): Promise<void> {
  destBuildOkReported = false; // the next success in this isolate must report the recovery
  await postDestBuild(env, { ok: false, ...destBuildFaultOf(e) });
}

/** Which fields a stored destination row carries: presence only, never a value. */
export interface StoredDestFieldsSet {
  endpoint: boolean;
  bucket: boolean;
  region: boolean;
  accessKeyId: boolean;
  secret: boolean;
  worm: boolean;
  assumeRole: boolean;
  azureEntra: boolean;
  addressing: boolean;
  storageClass: boolean;
  pricing: boolean;
}

/**
 * inspectStoredDestination describes ONE stored destination row for the support pack without letting a value
 * out: its source (the synthetic deploy-time row or a console row), the provider a console row's endpoint
 * would build, and which fields are set. It reads the row through the same DO read resolveDestination uses,
 * and returns booleans and closed enums only; the endpoint, bucket, region and credential stay here.
 *
 * @param scheduler - the scheduler DO stub.
 * @param destinationId - the stored id to describe.
 * @returns the description, or null when the DO holds no row for the id.
 */
export async function inspectStoredDestination(scheduler: DurableObjectStub, destinationId: string): Promise<{ source: "deploy" | "console"; provider: DestProvider | null; fieldsSet: StoredDestFieldsSet } | null> {
  const raw = await readStoredDestRecord(scheduler, destinationId);
  if (raw === null) return null;
  const has = (v: unknown): boolean => (typeof v === "string" ? v.trim() !== "" : v !== undefined && v !== null);
  const deploy = raw.source === "deploy";
  const secret = raw.secretAccessKey;
  return {
    source: deploy ? "deploy" : "console",
    provider: !deploy && typeof raw.endpoint === "string" && raw.endpoint !== "" ? providerForEndpoint(raw.endpoint) : null,
    fieldsSet: {
      endpoint: has(raw.endpoint),
      bucket: has(raw.bucket),
      region: has(raw.region),
      accessKeyId: has(raw.accessKeyId),
      secret: typeof secret === "string" ? secret !== "" : isWrappedSecret(secret),
      worm: has(raw.worm),
      assumeRole: has(raw.assumeRole),
      azureEntra: has(raw.azureEntra),
      addressing: has(raw.addressing),
      storageClass: has(raw.storageClass),
      pricing: has(raw.pricing),
    },
  };
}
