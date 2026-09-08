// Which object store is behind a destination endpoint.
//
// WHY THIS EXISTS AS ITS OWN MODULE. The destination kind is DERIVED, never stored: admin/status.ts has
// always read it back off the endpoint host, because a console-set destination records the host and not a
// provider label. That derivation had exactly two answers, R2 or "S3", and every store that is not R2
// collapsed into the second one. That is correct for ROUTING (they are all reached with SigV4 over the S3
// XML API, which is why they work at all) and wrong for everything an operator reads or is refused:
//
//   - A Google Cloud Storage bucket has worked as a downpipes destination for as long as the S3-compatible
// arm has existed. Driven live against a real bucket with this repo's own signer, every
//     call the engine makes succeeded: PUT 200, GET 200 byte-correct, HEAD 404 on a missing key, DELETE 204,
//     and multipart initiate/upload/complete all 200. It was simply never NAMED, so it was labelled S3,
//     priced as Amazon S3 Standard, and offered fields it cannot honour.
//   - Azure Blob Storage is not an S3-compatible endpoint at all and never will be. Pointed at the same arm
//     it answers 403 AuthenticationFailed on the first call, and no credential or setting changes that.
// It is a SUPPORTED destination, and it is supported BECAUSE of that fact rather than
//     in spite of it: it has its own client (dest/azure-blob.ts) and its own Shared Key signer, and this
//     derivation is the thing that routes an Azure host to them instead of to the S3 arm that cannot reach
//     it. Collapsed into the "s3" residual it would still be signed with SigV4 and still answer 403.
//
// Naming the provider is what lets a refusal carry the remedy that is true for THAT store, and what lets a
// store with its own client be dispatched to it. The union is
// deliberately about the WIRE-VISIBLE identity of the endpoint, not about a customer's intent: it is
// derived from the host and nothing else, so it cannot disagree with where the bytes actually go.
//
// WHAT THIS IS NOT. It is not a claim that downpipes has a native client for any of these. GCS is reached
// through its S3-interoperable XML API, authenticated with HMAC keys under the identical SigV4 scheme S3
// uses, so it shares s3.ts verbatim. That is an S3-interop client wearing a GCS label and it is never
// implied to be more.

/** The object store behind a destination endpoint, derived from the endpoint host alone.
 *
 * "s3" is the residual and stays the residual on purpose: any S3-compatible store this module does not
 * recognise by host (Wasabi, Backblaze B2, MinIO, Ceph, a private endpoint fronting AWS) reads as "s3" and
 * is handled exactly as before. A new member is only worth adding when the engine would REFUSE or SAY
 * something different because of it. */
export type DestProvider = "r2" | "s3" | "gcs" | "azure";

/** An endpoint host that is not an object store this engine can write to at all, with the reason. Kept
 * separate from DestProvider because these are not destinations: they are refusals with a name.
 *
 * `azure-blob` USED to be a member and is not any more: Azure Blob Storage became a supported destination
 * with its own client (dest/azure-blob.ts) and its own Shared Key signer. ADLS Gen2 stays
 * refused, because its `dfs` endpoint is a genuinely different wire protocol and not merely a different
 * host for the Blob one. */
export type UnusableEndpoint = "azure-dfs";

// R2_HOST matches Cloudflare R2's S3 endpoint, including the account-scoped form and the regional
// variants that carry an extra label in front of it. The leading-label anchor is what admits those
// without also admitting a look-alike domain.
//
// The word for those regional variants is deliberately not written here. A tier-1 gate asserts that
// the engine mentions it in exactly one file, admin/bindings-sync.ts, because it is a
// property of a SOURCE R2 binding and never of a destination, and a destination module that starts
// using the vocabulary is the first step toward a destination module that starts honouring it.
// Unchanged from the pattern admin/status.ts has always used; moved here so one derivation serves the
// status surface, the refusal surface and the pack rather than three copies drifting apart.
const R2_HOST = /(^|\.)r2\.cloudflarestorage\.com$/i;

// GCS_HOST matches Google Cloud Storage's S3-interoperable XML API endpoint. GCS documents exactly one
// interop host and does not use a per-bucket or per-region host for it, so this is a whole-host match
// rather than a suffix that could admit a look-alike domain.
const GCS_HOST = /^storage\.googleapis\.com$/i;

// AZURE_BLOB_HOST / AZURE_DFS_HOST match Azure Storage's two endpoint families, and the two get OPPOSITE
// answers because they are different wire protocols: a blob host classifies as "azure" and is dispatched to
// the Azure client, a dfs host is refused. They are matched as SUFFIXES of the account label
// ("<account>.blob.core.windows.net"), across every Azure cloud in AZURE_STORAGE_SUFFIXES.
//
// THE MATCHER IS TESTED. THE WIRE IS NOT, for the US Government and China clouds. Both regexes are built from one list,
// and validate-dest-provider.ts drives every suffix in that list plus a look-alike for each, so what this
// module CLASSIFIES is graded. What is not graded is a real request to a government-cloud or China-cloud
// account: nobody here holds a subscription in either, so no PUT, GET or List has ever been made against
// one. The claim being made is therefore narrow and exact: an Azure host in one of those clouds is now
// routed to the Azure client and its Shared Key signer, rather than falling through to the S3 arm where
// SigV4 could never authenticate it. Whether that account then accepts the request is decided by the live
// probe at save time, exactly as it is for a commercial account, and a failure there is reported rather
// than hidden. Routing a store to the only client that could talk to it is strictly better than routing it
// to one that certainly cannot, and it is all that is being claimed.

/**
 * AZURE_STORAGE_SUFFIXES is the closed list of Azure Storage endpoint suffixes, one per Azure cloud. It is
 * the SINGLE source both host matchers are built from, so a cloud added here is admitted for blob and
 * refused for dfs in the same edit and the two cannot drift. It is declared ABOVE the matchers because they
 * read it while they are being built, and a const read before its own initialiser throws.
 *
 *   core.windows.net        the commercial cloud, the only one measured live
 *   core.usgovcloudapi.net  Azure US Government
 *   core.chinacloudapi.cn   Azure China, operated by 21Vianet
 *
 * TWO FAMILIES ARE DELIBERATELY ABSENT. Microsoft Cloud Germany (core.cloudapi.de) was closed in October
 * 2021, so admitting it would name a cloud that no longer exists. The US air-gapped clouds for classified
 * workloads have their own suffixes again, and they are left out because they are not certain enough here
 * to write down: an endpoint suffix that is nearly right is a host that never resolves, and the cost of
 * omitting one is the pre-existing refusal rather than a new fault.
 */
export const AZURE_STORAGE_SUFFIXES: readonly string[] = ["core.windows.net", "core.usgovcloudapi.net", "core.chinacloudapi.cn"];

/** azureHostPattern builds the anchored suffix matcher for one Azure Storage endpoint family across every
 *  cloud in AZURE_STORAGE_SUFFIXES. The leading "\." is what makes it a match on the ACCOUNT LABEL rather
 *  than on a bare string ending: without it "notablob.core.windows.net" would read as an Azure host, and
 *  the "$" is what stops "acct.blob.core.windows.net.evil.example" reading as one. Every dot in a suffix is
 *  escaped, so a suffix cannot smuggle a regex metacharacter into the pattern. */
function azureHostPattern(family: "blob" | "dfs"): RegExp {
  const clouds = AZURE_STORAGE_SUFFIXES.map((s) => s.replace(/\./g, "\\.")).join("|");
  return new RegExp(`\\.${family}\\.(?:${clouds})$`, "i");
}

const AZURE_BLOB_HOST = azureHostPattern("blob");
const AZURE_DFS_HOST = azureHostPattern("dfs");

/** azureAccountFromHost pulls the storage account out of an Azure Blob endpoint host. The account is the
 *  FIRST label, and it is needed in two places that must agree: the Shared Key canonicalised resource is
 *  built from it, and a mismatch between the account in the host and the account in the signature is a
 *  403 that names neither. Deriving it from the host in one place is what keeps them the same. */
export function azureAccountFromHost(hostOrUrl: string | undefined): string {
  const h = bareHost(hostOrUrl);
  if (!AZURE_BLOB_HOST.test(h)) return "";
  return h.split(".")[0] ?? "";
}

/** bareHost strips a scheme and any path from a value that may be a full URL or already a bare host, and
 * lower-cases it. Every matcher here reads its output, so a caller passing "https://host/" and a caller
 * passing "host" cannot get different answers. */
function bareHost(hostOrUrl: string | undefined): string {
  if (typeof hostOrUrl !== "string") return "";
  return hostOrUrl
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
}

/**
 * providerForEndpoint names the store behind an endpoint host. It answers "s3" for anything it does not
 * recognise, which is the pre-existing behaviour for every store but R2 and is why adding GCS changes
 * nothing for a Wasabi or MinIO destination.
 *
 * @param hostOrUrl - the endpoint, as a full URL or a bare host.
 * @returns the derived provider.
 */
export function providerForEndpoint(hostOrUrl: string | undefined): DestProvider {
  const h = bareHost(hostOrUrl);
  if (h === "") return "s3";
  if (R2_HOST.test(h)) return "r2";
  if (GCS_HOST.test(h)) return "gcs";
  if (AZURE_BLOB_HOST.test(h)) return "azure";
  return "s3";
}

/**
 * unusableEndpoint names an endpoint that cannot be a destination at all, so the refusal can say which
 * store it recognised instead of letting the live probe fail with a credential-shaped error. Returns null
 * for every endpoint that is worth probing.
 *
 * ITS ONLY MEMBER IS THE ADLS GEN2 `dfs` ENDPOINT. An Azure BLOB endpoint is NOT unusable and never reaches
 * here: it became a supported destination, so providerForEndpoint classifies it as "azure" and
 * the factory dispatches it to the Azure client. The dfs endpoint stays refused because it speaks a
 * different wire protocol from the Blob one, which is not something a credential or a setting can change.
 *
 * This is a MESSAGE improvement and not a new gate: a dfs endpoint was already refused, because the probe's
 * first call answers 403. What it was not doing was telling the operator why, and "check that the
 * credentials allow object read and write on that bucket" sends them to audit a credential that was never
 * the problem. The remedy it now carries, point at the same account's blob endpoint instead, is one the
 * operator can act on.
 *
 * @param hostOrUrl - the endpoint, as a full URL or a bare host.
 * @returns the unusable-endpoint kind, or null when the endpoint is worth probing.
 */
export function unusableEndpoint(hostOrUrl: string | undefined): UnusableEndpoint | null {
  const h = bareHost(hostOrUrl);
  if (AZURE_DFS_HOST.test(h)) return "azure-dfs";
  return null;
}

/** The operator-facing refusal for an endpoint that is not an S3-compatible store. It names the store, says
 * plainly that downpipes cannot write to it, and does not suggest a workaround that does not exist. */
export const UNUSABLE_ENDPOINT_REASON: Readonly<Record<UnusableEndpoint, string>> = {
  "azure-dfs":
    // The remedy names the SWAP rather than one suffix, because the dfs matcher now covers the US
    // Government and China clouds too: an Azure US Government account's blob endpoint is not at
    // blob.core.windows.net, so a
    // message naming that host would send a government-cloud operator to a host that does not resolve.
    // The commercial form is kept as the worked example, since it is the common case.
    "that endpoint is Azure Data Lake Storage Gen2, whose dfs endpoint is a different protocol from Azure Blob Storage and is not supported. If the storage account holds ordinary block blobs, use its BLOB endpoint instead: the same account in the same cloud, with blob in place of dfs in the host, so acct.dfs.core.windows.net becomes acct.blob.core.windows.net. That endpoint downpipes does support.",
};

/**
 * AZURE_REFUSED_FIELDS is the closed set of destination fields an Azure Blob endpoint cannot honour.
/**
 * AZURE_REFUSED_FIELDS is the closed set of destination fields an Azure Blob endpoint cannot honour.
 *
 * IMMUTABILITY IS NOT IN THIS SET: Azure's two primitives map exactly onto the vocabulary this product
 * uses. governance means a privileged principal CAN lift the retention, which is an UNLOCKED Azure policy;
 * compliance means nobody can shorten or remove it, which is a LOCKED one. Nothing is being guessed,
 * because the mode is a REQUEST HEADER chosen per write rather than a property of the container that has
 * to be inferred. The legal hold, which genuinely has no counterpart here, is simply never set.
 *
 * An Azure container with version-level immutability enabled answers the live capability probe, has its
 * policy accepted, and enforces it; a container without it is refused by the probe's verdict, the same
 * rule every other store is held to.
 *
 *
 * REFUSED, NEVER TRANSLATED. The entries here are genuinely unsupported rather than merely unimplemented:
 * Azure has no AWS storage classes to translate to, no AssumeRole to assume, and one URL form rather than
 * a choice of two.
 *
 * REGION IS DELIBERATELY NOT IN THIS SET, and the reason is a measurement rather than a preference. No
 * Azure module reads it: azure-blob, azure-sharedkey, azure-sas and azure-entra reference `region` zero
 * times between them, and factory.ts builds AzureBlobDestination without it. So it is inert, and the first
 * instinct is to refuse it beside the other three. That would break EVERY Azure destination, because region
 * is never absent to begin with: the console's field is declared with "auto" already in it, the console
 * coerces an empty box to "auto" on submit, and the router does the same again server-side. A refusal keyed
 * on "the field is present" would therefore fire on every single submit, including the ones that carry
 * nothing but the default.
 *
 * `addressing` is safe to refuse precisely because it is NOT defaulted: it is sent only when an operator
 * picks path or vhost, so this refusal cannot fire on a destination that simply left it alone.
 *
 * The console hides both controls for Azure, which is where an inert-but-harmless field belongs. A field
 * nobody can set does not need a refusal as well, and a refusal that fires on a default is worse than the
 * inert field it was meant to tidy away.
 */
export const AZURE_REFUSED_FIELDS: ReadonlyArray<{ field: string; reason: string }> = [
  {
    field: "storageClass",
    reason:
      "Azure Blob Storage uses access tiers (Hot, Cool, Cold, Archive) rather than Amazon's storage-class names, and downpipes does not translate between them. Leave the storage class blank, and set the access tier on the container or the storage account in Azure.",
  },
  {
    field: "assumeRole",
    reason:
      "STS AssumeRole is an Amazon Web Services mechanism with no Azure equivalent, so a role ARN here would never be assumed. Authenticate with the storage account name and one of its access keys, with a shared access signature, or with a Microsoft Entra service principal, instead.",
  },
  {
    field: "addressing",
    reason:
      "Addressing style is an S3 concept: it chooses whether the bucket sits in the request host or the path. Azure Blob has one form, https://<account>.blob.core.windows.net/<container>/<blob>, with the container always in the path, so there is nothing to choose. Leave it on auto.",
  },
];

/**
 * GCS_REFUSED_FIELDS is the closed set of destination fields a Google Cloud Storage endpoint cannot
 * honour, each with the reason a GCS operator can act on.
 *
/**
 * GCS_REFUSED_FIELDS is the closed set of destination fields a Google Cloud Storage endpoint cannot
 * honour, each with the reason a GCS operator can act on.
 *
 * IMMUTABILITY IS NOT IN THIS SET. Against a real bucket:
 *
 *   a bucket created WITH per-object retention answers GET /<bucket>/?object-lock= with 200 and
 *   <ObjectLockEnabled>Enabled</ObjectLockEnabled>, which parseObjectLockConfig reads as { enabled: true };
 *   a PUT carrying x-amz-object-lock-mode: COMPLIANCE returns 200, the object then carries a real
 *   retention (mode "Locked", with the retain-until instant), and a DELETE inside the window is REFUSED
 *   with 403 naming the retention. The lock is genuine, not accepted-and-ignored.
 *
 *   a bucket created WITHOUT it answers 404 ObjectLockConfigurationNotFound, which reads as
 *   { enabled: false }, which wormCannotBeEnforced turns into a refused save.
 *
 * The engine's existing PROBE reaches the right answer in both directions, so no hardcoded rule is layered
 * on top of it: a live capability probe is what decides, here as for every other store.
 *
 * REFUSED, NEVER TRANSLATED. A storage class is the case worth stating, because GCS does document its own
 * classes and a mapping looks available. It is refused anyway: downpipes does no AWS-to-GCS storage-class
 * translation, and a value that silently "works" because two providers happen to share the name STANDARD,
 * while STANDARD_IA is rejected on the wire, is worse than a field that is honestly always refused.
 *
 * WHY EACH ONE IS REFUSED HERE RATHER THAN LEFT TO THE PROBE. Against a real GCS bucket:
 *
 *   - a PUT carrying x-amz-storage-class: STANDARD_IA answers 400 InvalidStorageClass, and the save-time
 *     write probe carries the storage class, so the save was already refused;
 *   - GET /bucket/?object-lock= answers 404 ObjectLockConfigurationNotFound, which objectLockStatus reads
 *     as a definite not-enabled, which wormCannotBeEnforced turns into a refused save.
 *
 * So refusing these fields up front changes no outcome, only the SENTENCE: Google Cloud's own setting is
 * PER-OBJECT RETENTION (only settable at bucket-create time), not Amazon's "Object Lock", so naming it
 * correctly here means the operator is not sent looking for a checkbox Google Cloud's console does not
 * have. The per-provider remedies now live in one place, dest/worm-remedy.ts, for every surface that
 * offers one.
 */
export const GCS_REFUSED_FIELDS: ReadonlyArray<{ field: string; reason: string }> = [
  {
    field: "storageClass",
    reason:
      "Google Cloud Storage does not accept Amazon's storage-class names, and downpipes does not translate between them. Leave the storage class blank to use the bucket's own default class, and set the class you want on the bucket itself in Google Cloud.",
  },
  {
    field: "assumeRole",
    reason:
      "STS AssumeRole is an Amazon Web Services mechanism and Google Cloud Storage has no equivalent, so a role ARN here would never be assumed. Authenticate with an HMAC key pair for the service account instead: in Google Cloud these are created under Cloud Storage settings as interoperability keys.",
  },
];
