// The per-provider immutability vocabulary: what each store CALLS write-once retention, and what an
// operator whose destination does not enforce it can actually DO about it.
//
// WHY THIS FILE EXISTS. Until one Amazon-shaped sentence was served to all four supported
// providers, on the destination-add refusal, the immutability posture check, the signed immutability
// report and the support pack: "re-create the destination bucket with Object-Lock enabled". It is right
// for Amazon S3. It is wrong for the other three, and on Cloudflare R2 it was worse than wrong, because
// the remedy published beside it was "reach the bucket by its S3 endpoint", which R2 refuses outright.
//
// MEASURED against a real R2 bucket over https://<account>.r2.cloudflarestorage.com, signed
// with this repo's own SigV4 signer:
//
//   GET /<bucket>/?object-lock=                 -> 404 ObjectLockConfigurationNotFoundError
//   PUT with x-amz-object-lock-mode: COMPLIANCE -> 501 NotImplemented, "Header
//                                                  'x-amz-object-lock-mode' with value 'COMPLIANCE'
//                                                  not implemented"
//
// So R2 does not merely hide Object-Lock behind its native binding: it refuses the header on the S3 arm
// too, by name. An operator who followed the old remedy got a 501 on every write and an archive holding
// nothing. R2 IS THE ONE PROVIDER WITH NO REMEDY, and saying so plainly is the honest answer; a remedy
// that cannot be followed is worse than a plain refusal.
//
// The other three each have a real one, and each is a different mechanism rather than a different
// spelling of the same one:
//   Amazon S3 (and any other S3-compatible store that implements it) - Object-Lock, at bucket-create time.
//   Google Cloud Storage - a bucket created with per-object retention, which its S3-interoperable
//     endpoint reports as ObjectLockEnabled and which the probe already reads correctly (see
//     GCS_REFUSED_FIELDS in provider.ts for that measurement).
//   Azure Blob Storage - version-level immutability on the container or the storage account, plus blob
//     versioning on the account. Not Object-Lock at all.
//
// ONE SOURCE, three surfaces. These strings are the whole reason this leaf is separate: the posture
// check, the signed report and the add-time refusal each read from this ONE table, so they can never
// disagree about the same fact.

import type { DestProvider } from "./provider.ts";

/**
 * AZURE_VERSION_LEVEL_IMMUTABILITY_REMEDY is the Azure setting an operator has to change, stated as an
 * action. azure-worm.ts composes the write-failure hint from it, so the sentence a failed Azure write
 * carries and the sentence the posture check offers cannot drift apart.
 */
export const AZURE_VERSION_LEVEL_IMMUTABILITY_REMEDY =
  "A container accepts a per-blob immutability policy only when VERSION-LEVEL IMMUTABILITY is enabled on it, which is a setting on the Azure storage account or container and not a downpipes one: enable it in Azure (an existing container has to be migrated, it cannot simply be switched on) and make sure blob versioning is on for the account, or remove the immutability policy from this destination.";

/**
 * IMMUTABILITY_REMEDY is what to DO about a destination whose store does not enforce write-once
 * retention, one sentence per provider, each one an action an operator of THAT store can take. The R2
 * member deliberately offers no way to keep R2: there is none.
 */
export const IMMUTABILITY_REMEDY: Readonly<Record<DestProvider, string>> = {
  s3: "Re-create the destination bucket with Object-Lock ENABLED (it can only be set when the bucket is created, never afterwards) and point this destination at the new bucket, or set the WORM mode back to off to keep using this bucket without immutability.",
  gcs: "Re-create the destination bucket in Google Cloud with per-object retention turned on, which is only available when the bucket is created and is what its S3-interoperable endpoint reports as Object-Lock ENABLED, then point this destination at the new bucket, or set the WORM mode back to off to keep using this bucket without immutability.",
  azure: `Azure's mechanism is version-level immutability rather than S3 Object-Lock, so there is no Object-Lock setting on the container to look for. ${AZURE_VERSION_LEVEL_IMMUTABILITY_REMEDY}`,
  r2: "Cloudflare R2 enforces no immutability this engine can arm, on any bucket and by any route: its native binding exposes no lock at all, and its S3 endpoint answers a PUT carrying x-amz-object-lock-mode with 501 NotImplemented, so re-creating the bucket or reaching it over the S3 endpoint changes nothing. Point this destination at a store that does enforce it (Amazon S3, Google Cloud Storage with per-object retention, or Azure Blob Storage with version-level immutability), or set the WORM mode back to off to keep using R2 without store-enforced immutability.",
};

/**
 * IMMUTABILITY_MECHANISM names the thing each store actually implements, for a sentence that ASSERTS
 * rather than instructs. It is what a signed attestation has to say: naming S3 Object-Lock on an Azure
 * destination is a precision defect in an artefact a customer hands an auditor.
 */
export const IMMUTABILITY_MECHANISM: Readonly<Record<DestProvider, string>> = {
  s3: "S3 Object-Lock",
  gcs: "Object Lock (Google Cloud Storage per-object retention)",
  azure: "version-level immutability",
  // "write-once retention" rather than a product name, because R2 has none to give: the label has to read
  // correctly on both sides of the sentence, "the bucket enforces X" and "a bucket that does not enforce X".
  r2: "write-once retention",
};

/**
 * IMMUTABILITY_STORE_NOUN is what each provider calls the container the archives land in. Azure has
 * containers, not buckets, and a signed attestation that calls one a bucket is describing a thing the
 * operator cannot find in their own portal.
 */
export const IMMUTABILITY_STORE_NOUN: Readonly<Record<DestProvider, string>> = { s3: "bucket", gcs: "bucket", r2: "bucket", azure: "container" };

/**
 * immutabilityRemedy is IMMUTABILITY_REMEDY made total over an UNKNOWN provider, which is a state every
 * caller has: the posture slice omits it when no destination could be resolved, and the report carries a
 * null destination kind. An unknown provider falls back to the S3 sentence, which is the existing
 * behaviour for every caller and is the widest true statement available when the store is not known.
 *
 * @param provider - the destination's provider, or null/undefined when it could not be resolved.
 * @returns the remedy sentence for that provider.
 */
export function immutabilityRemedy(provider: DestProvider | null | undefined): string {
  return provider == null ? IMMUTABILITY_REMEDY.s3 : IMMUTABILITY_REMEDY[provider];
}

/**
 * immutabilityMechanism is IMMUTABILITY_MECHANISM made total over an unknown provider, for the same
 * reason and with the same S3 fallback.
 *
 * @param provider - the destination's provider, or null/undefined when it could not be resolved.
 * @returns the name of the write-once mechanism that store implements.
 */
export function immutabilityMechanism(provider: DestProvider | null | undefined): string {
  return provider == null ? IMMUTABILITY_MECHANISM.s3 : IMMUTABILITY_MECHANISM[provider];
}

/**
 * immutabilityStoreNoun is IMMUTABILITY_STORE_NOUN made total over an unknown provider, with the same
 * S3 fallback ("bucket", which is also what three of the four providers call it).
 *
 * @param provider - the destination's provider, or null/undefined when it could not be resolved.
 * @returns "bucket" or, for Azure, "container".
 */
export function immutabilityStoreNoun(provider: DestProvider | null | undefined): string {
  return provider == null ? IMMUTABILITY_STORE_NOUN.s3 : IMMUTABILITY_STORE_NOUN[provider];
}

/**
 * IMMUTABILITY_ENABLE_WHEN states WHEN each store's write-once mechanism can be turned on, which is the
 * fact an auditor reading the signed immutability report needs beside a not-in-force verdict. Amazon's
 * "only at bucket creation" is right for two of them and wrong for the other two.
 */
export const IMMUTABILITY_ENABLE_WHEN: Readonly<Record<DestProvider, string>> = {
  s3: "Object-Lock can only be enabled when a bucket is created.",
  gcs: "Per-object retention can only be turned on when a bucket is created.",
  azure: "Version-level immutability is a setting on the Azure storage account or container, and an existing container has to be migrated to it rather than simply switched on.",
  r2: "Cloudflare R2 enforces no Object-Lock on any bucket, through its native binding or its S3 endpoint, so no bucket of its can be created or reconfigured to hold one.",
};

/**
 * immutabilityEnableWhen is IMMUTABILITY_ENABLE_WHEN made total over an unknown provider, with the same
 * S3 fallback the other three lookups use.
 *
 * @param provider - the destination's provider, or null/undefined when it could not be resolved.
 * @returns the sentence stating when that store's write-once mechanism can be turned on.
 */
export function immutabilityEnableWhen(provider: DestProvider | null | undefined): string {
  return provider == null ? IMMUTABILITY_ENABLE_WHEN.s3 : IMMUTABILITY_ENABLE_WHEN[provider];
}
