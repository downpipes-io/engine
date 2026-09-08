// factory-validators.ts -- the LEAF bounding functions for destination configuration.
//
// These four validators were extracted VERBATIM from factory.ts (behaviour unchanged, symbols unchanged;
// factory.ts re-exports every one of them, so every existing importer keeps its import path). The extraction
// exists for ONE reason: config-anomalies.ts must decide which stored/env config fields the engine will
// SILENTLY DISCARD, and it must decide it with EXACTLY the functions that do the discarding -- a second,
// parallel copy of the rules would drift, and a drifted diagnosis is worse than none. factory.ts imports
// config-anomalies.ts (to record the drop at the read-for-use site), so the validators cannot live there
// without an import cycle. They live here, in a leaf both can import.
//
// Nothing here is diagnostic: this module is the same fail-safe bounding it always was. A value that does not
// survive its validator is dropped, and the caller behaves as if it were never set.

import type { Addressing } from "./s3.ts";
import type { WormMode, WormPolicy } from "./types.ts";

/**
 * Bounds an untrusted addressing value to "auto" | "path" | "vhost", or undefined when absent/invalid (so
 * the default auto behaviour applies). Non-secret, like the rest of the destination location config.
 *
 * @param v - the candidate value.
 * @returns the validated Addressing, or undefined.
 */
export function validateAddressing(v: unknown): Addressing | undefined {
  return v === "auto" || v === "path" || v === "vhost" ? v : undefined;
}

/**
 * addressingRejected answers whether a SUBMITTED addressing value is one the engine must refuse rather than
 * drop. It is the shared predicate behind every submit-time addressing refusal, so the destination surface
 * and the audit-export surface cannot drift about what "unusable" means.
 *
 * An absent or null value is not a rejection (no addressing was asked for) and neither is a blank string
 * (the console clears the field to mean the auto default). Anything else that validateAddressing cannot use
 * IS a rejection: the value is drawn from a closed three-member enum, so a value outside it is a mistake
 * rather than a preference, and dropping it silently addressed every object in a way the operator did not
 * choose.
 *
 * @param v - the submitted addressing value (untrusted, any shape).
 * @returns true when the submit boundary must refuse it.
 */
export function addressingRejected(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "string" && v.trim() === "") return false;
  return validateAddressing(v) === undefined;
}

/**
 * addressingRejection is the SUBMIT-TIME twin of validateAddressing, in the same family as
 * assumeRolePolicyRejection and wormPolicyRejection: it answers WHY a submitted addressing style is
 * unusable, so the write boundary can refuse with an actionable reason instead of storing a destination
 * addressed differently from the way the operator chose.
 *
 * The read path stays fail-safe (validateAddressing drops what it cannot use, because a STORED config must
 * never half-apply, and config-anomalies.ts reports that drop as addressing-dropped). This is the one moment
 * the operator is still at the keyboard.
 *
 * @param v - the submitted addressing value (untrusted, any shape).
 * @returns an operator-facing reason, or null when there is nothing to refuse.
 */
export function addressingRejection(v: unknown): string | null {
  if (!addressingRejected(v)) return null;
  return 'the destination addressing style must be "auto", "path" or "vhost"; leave it unset for the auto default';
}

/**
 * STORAGE_CLASSES is the allow-list of S3 storage classes downpipes will write to: the IMMEDIATELY-READABLE
 * tiers only. GLACIER, GLACIER_IR, DEEP_ARCHIVE and anything else are deliberately excluded, because an
 * object that is not immediately readable would break verify-at-seal (the engine reads the archive back at
 * seal time) and would need an async RestoreObject thaw before any restore. STANDARD_IA and
 * INTELLIGENT_TIERING are the cost levers for cold backups; both are immediately readable, no thaw.
 *
 * It bounds what the engine will ASK for, and nothing more: a bucket LIFECYCLE rule can still transition a
 * written object to a cold tier afterwards, which a later read surfaces as the distinct thaw-needed fault.
 * validateStorageClass gates the write path against it and the support pack re-reads it to judge a stored
 * class, so it is the one list both sides answer from; widening it widens both.
 */
export const STORAGE_CLASSES = ["STANDARD", "STANDARD_IA", "INTELLIGENT_TIERING", "ONEZONE_IA"] as const;

/**
 * Bounds an untrusted storage-class value to a supported, immediately-readable S3 storage class, or
 * undefined when absent or unsupported (so the write uses the bucket default). A GLACIER/DEEP_ARCHIVE value
 * resolves to undefined here; the router rejects it explicitly so the operator is told why rather than
 * having it silently dropped.
 *
 * @param v - the candidate value.
 * @returns the supported storage class, or undefined.
 */
export function validateStorageClass(v: unknown): string | undefined {
  return typeof v === "string" && (STORAGE_CLASSES as readonly string[]).includes(v) ? v : undefined;
}

/** An STS AssumeRole policy: the role to assume, an optional external id (credential-class) and an
 * optional session duration. The principal key + the region live on the RuntimeDestConfig alongside it. */
export interface AssumeRolePolicy {
  roleArn: string;
  externalId?: string;
  durationSeconds?: number;
}

/**
 * Bounds an untrusted AssumeRole policy value (stored or submitted): roleArn must be a non-empty
 * arn:aws:iam role ARN, externalId an optional short string, durationSeconds an optional positive integer.
 * Returns the validated policy or null. A malformed policy is dropped (fail-safe), exactly like a WORM
 * policy, so a half-set policy never reaches the resolver.
 *
 * @param v - the candidate value (untrusted, any shape).
 * @returns the validated AssumeRolePolicy, or null when invalid.
 */
export function validateAssumeRolePolicy(v: unknown): AssumeRolePolicy | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const roleArn = typeof o.roleArn === "string" ? o.roleArn.trim() : "";
  if (!/^arn:aws[a-z-]*:iam::\d{12}:role\/.+/.test(roleArn)) return null;
  const out: AssumeRolePolicy = { roleArn };
  if (typeof o.externalId === "string" && o.externalId.trim() !== "") out.externalId = o.externalId.trim();
  if (typeof o.durationSeconds === "number" && Number.isInteger(o.durationSeconds) && o.durationSeconds > 0) out.durationSeconds = o.durationSeconds;
  return out;
}

/**
 * STS_DURATION_MIN is AWS's own floor on an AssumeRole session (15 minutes). sts.ts already CLAMPS a stored
 * value into this window at request time, so a value below it was never honoured; declaring the window here
 * lets the SUBMIT boundary refuse it instead of accepting a number the engine will quietly replace. It is
 * declared here rather than in sts.ts because this module is the leaf both config-anomalies.ts and the
 * router read their rules from, and sts.ts imports it (the reverse would cycle).
 */
export const STS_DURATION_MIN = 900;

/**
 * STS_DURATION_MAX is AWS's own ceiling on an AssumeRole session (12 hours). See STS_DURATION_MIN for why
 * the window lives here and what enforces it at each end.
 */
export const STS_DURATION_MAX = 43200;

/**
 * assumeRolePolicyRejection is the SUBMIT-TIME twin of validateAssumeRolePolicy: it answers WHY a submitted
 * AssumeRole policy is unusable, so the write boundary can refuse with an actionable reason instead of
 * dropping the policy and storing a destination that quietly uses the principal keys directly.
 *
 * The read path stays fail-safe (validateAssumeRolePolicy drops what it cannot use, because a stored config
 * must never half-apply). This function is for the one moment the operator can still act. It returns null
 * when the value is absent (no policy asked for) or usable exactly as validateAssumeRolePolicy would build
 * it, so the two can never disagree about what "usable" means.
 *
 * @param v - the submitted assumeRole value (untrusted, any shape).
 * @returns an operator-facing reason, or null when there is nothing to refuse.
 */
export function assumeRolePolicyRejection(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  if (validateAssumeRolePolicy(v) === null) {
    return 'the STS AssumeRole policy needs a role ARN of the form arn:aws:iam::<12-digit account>:role/<role name>; leave the Role ARN blank to use the destination keys directly';
  }
  const o = v as Record<string, unknown>;
  const d = o.durationSeconds;
  if (d === undefined || d === null) return null;
  if (typeof d !== "number" || !Number.isInteger(d) || d < STS_DURATION_MIN || d > STS_DURATION_MAX) {
    return `the STS session duration must be a whole number of seconds from ${STS_DURATION_MIN} to ${STS_DURATION_MAX} (AWS's own limits); leave it blank for the 3600-second default`;
  }
  return null;
}

/**
 * wormPolicyRejection is the SUBMIT-TIME twin of validateWormPolicyValue, and it exists because an
 * immutability policy is the one setting where a silent drop is worse than a refusal: without it, an
 * operator asking for compliance-mode WORM could have the destination stored and verified with NO
 * Object-Lock at all, and nothing downstream could tell that apart from a destination nobody ever asked
 * to lock.
 *
 * The read path stays fail-safe (an unusable STORED policy arms nothing, which is right: a partial lock is
 * worse than none). This is the write boundary, where the operator is still at the keyboard.
 *
 * @param v - the submitted worm value (untrusted, any shape).
 * @returns an operator-facing reason, or null when there is nothing to refuse.
 */
export function wormPolicyRejection(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  if (validateWormPolicyValue(v) !== null) return null;
  return "the immutability policy needs a mode of governance or compliance AND a retention window of a whole number of days greater than zero; a policy that is not both is refused rather than saved without immutability";
}

/**
 * Bounds a WORM policy that arrives as a stored or console-set value (the RuntimeDestConfig.worm
 * field): it must be { mode: governance|compliance, retentionDays: positive integer } or it is
 * rejected. An invalid stored policy is treated as misconfigured (arm nothing) just like the env
 * path.
 *
 * @param v - the candidate value (untrusted, possibly any shape).
 * @returns the validated WormPolicy, or null when the value is not a valid policy.
 */
export function validateWormPolicyValue(v: unknown): WormPolicy | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const mode = normaliseWormMode(typeof o.mode === "string" ? o.mode : undefined);
  const days = o.retentionDays;
  if (mode === null || typeof days !== "number" || !Number.isInteger(days) || days <= 0) return null;
  return { mode, retentionDays: days };
}

/**
 * normaliseWormMode maps a raw string to a WormMode, case-insensitively, or null when it is neither.
 *
 * @param raw - the candidate mode string.
 * @returns the WormMode, or null.
 */
export function normaliseWormMode(raw: string | undefined): WormMode | null {
  const m = raw?.trim().toLowerCase();
  return m === "governance" || m === "compliance" ? m : null;
}

/**
 * AzureEntraDirectory names WHICH service principal an Azure Blob destination authenticates as: the
 * directory it lives in and the application it is. Neither value is secret.
 *
 * THE SECRET IS NOT IN HERE, AND THAT IS THE DESIGN. An Entra service principal is three values, and a
 * stored destination already carries exactly one credential slot. The third value, the client secret, IS
 * that slot: on an Entra destination `secretAccessKey` holds the client secret, exactly as it holds the
 * storage account key on a Shared Key destination. So there is still one secret per destination, in the
 * field every surface that handles a destination secret already knows about, which means the at-rest
 * envelope (admin/config-secret.ts), the control-plane export's wrapped-or-reestablish projection, the
 * approval-summary redaction and the plaintext-at-rest census all keep working with no second code path
 * and no second thing to remember. The alternative, a third credential field with its own envelope, would
 * have had to be taught to every one of those surfaces, and a surface that was missed is a credential
 * that leaks or a credential that is silently dropped on import.
 *
 * The presence of this object is also the DISCRIMINATOR: an Azure destination that carries it
 * authenticates with Entra and signs nothing, and one that does not authenticates with a Shared Key.
 * There is no separate mode field, so there is no way for a mode and a credential to disagree.
 */
export interface AzureEntraDirectory {
  tenantId: string;
  clientId: string;
}

/** A Microsoft Entra directory or application identifier in GUID form. Anchored, so a value with
 *  anything either side of it is not a GUID. */
const ENTRA_GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A tenant may also be named by its verified domain (contoso.onmicrosoft.com, or a custom domain). The
 *  pattern is deliberately strict about what a label may contain, because this value is placed in the
 *  PATH of the token request URL: a value that could carry a slash or a dot-segment could point the
 *  token request at a different endpoint on the same authority. */
const ENTRA_TENANT_DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

/** The multi-tenant authority aliases. They are REFUSED for a destination, not merely unsupported: the
 *  client-credentials grant needs a specific directory, and Microsoft rejects these aliases for it. A
 *  destination stored with one would fail at every token request rather than at the one moment the
 *  operator could still fix the tenant id. */
const ENTRA_MULTI_TENANT_ALIASES: ReadonlySet<string> = new Set(["common", "organizations", "consumers"]);

/**
 * Bounds an untrusted Entra directory value (stored or submitted): tenantId must be a GUID or a domain
 * name and must not be a multi-tenant alias, clientId must be a GUID. Returns the validated pair or null.
 * A malformed value is DROPPED on the read path (fail-safe, exactly like assumeRole and worm), which for
 * an Azure destination means it falls back to reading secretAccessKey as a storage account key: that
 * fails to authenticate, loudly, rather than authenticating as something nobody configured.
 *
 * @param v - the candidate value (untrusted, any shape).
 * @returns the validated AzureEntraDirectory, or null when invalid.
 */
export function validateAzureEntraDirectory(v: unknown): AzureEntraDirectory | null {
  if (typeof v !== "object" || v === null) return null;
  const o = v as Record<string, unknown>;
  const tenantId = typeof o.tenantId === "string" ? o.tenantId.trim() : "";
  const clientId = typeof o.clientId === "string" ? o.clientId.trim() : "";
  if (!ENTRA_GUID.test(clientId)) return null;
  if (ENTRA_MULTI_TENANT_ALIASES.has(tenantId.toLowerCase())) return null;
  if (!ENTRA_GUID.test(tenantId) && !ENTRA_TENANT_DOMAIN.test(tenantId)) return null;
  return { tenantId, clientId };
}

/**
 * azureEntraDirectoryRejection is the SUBMIT-TIME twin of validateAzureEntraDirectory, in the same family
 * as assumeRolePolicyRejection and wormPolicyRejection: it answers WHY a submitted service principal is
 * unusable, so the write boundary refuses with a reason instead of dropping it and storing a destination
 * that quietly tries to use the client secret as a storage account key.
 *
 * The multi-tenant aliases get their own sentence, because "common" is the value an operator copies out
 * of a sign-in tutorial and it is the one wrong tenant id that looks deliberate.
 *
 * @param v - the submitted azureEntra value (untrusted, any shape).
 * @returns an operator-facing reason, or null when there is nothing to refuse.
 */
export function azureEntraDirectoryRejection(v: unknown): string | null {
  if (v === undefined || v === null) return null;
  if (validateAzureEntraDirectory(v) !== null) return null;
  const o = typeof v === "object" ? (v as Record<string, unknown>) : {};
  const tenantId = typeof o.tenantId === "string" ? o.tenantId.trim() : "";
  if (ENTRA_MULTI_TENANT_ALIASES.has(tenantId.toLowerCase())) {
    return `a destination has to name ONE directory, so the tenant cannot be "${tenantId}": a service principal signs in to a specific tenant. Use the Directory (tenant) ID from the app registration's overview page.`;
  }
  return "the Microsoft Entra service principal needs a Directory (tenant) ID (a GUID, or a verified domain such as contoso.onmicrosoft.com) and an Application (client) ID (a GUID). Both are on the app registration's overview page in the Azure portal.";
}
