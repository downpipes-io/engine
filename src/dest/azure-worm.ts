// Azure Blob immutability, expressed in the WORM vocabulary the rest of this engine already speaks.
//
// THIS MODULE MAPS TWO REAL AZURE PRIMITIVES ONTO THE SAME VOCABULARY THE REST OF THIS ENGINE SPEAKS.
// Azure carries TWO orthogonal primitives (a policy that is separately unlocked or locked, plus an
// independent legal hold) where the form collects ONE mode plus one window, and the mapping is not a
// guess despite that.
//
// THE MAPPING IS NOT A GUESS, because the two vocabularies name the same two guarantees:
//
//   governance -> unlocked   S3 governance means a sufficiently privileged principal CAN lift the
//                            retention. An Azure UNLOCKED policy means exactly that: the retain-until date
//                            can be increased, decreased or removed.
//   compliance -> locked     S3 compliance means nobody can shorten or remove the retention for the
//                            window. An Azure LOCKED policy means exactly that: the date can be extended
//                            and nothing else.
//
// The old refusal read that correspondence backwards. It worried that mapping `compliance` onto "an
// immutability policy" would silently deliver the weaker unlocked guarantee, which would indeed be wrong
// in the dangerous direction. But Azure's mode is a REQUEST HEADER we choose per write, not a property of
// the container we have to infer, so nothing is being guessed: `compliance` sends `locked` and gets the
// strong guarantee, or the store refuses the write.
//
// THE LEGAL HOLD IS DELIBERATELY NOT SET. It is Azure's second primitive and it has no counterpart in
// WormPolicy: a legal hold has no expiry at all and is cleared only by an explicit administrative action,
// so a blob written under one is undeletable FOR EVER until a human removes it. Deriving one from a
// retention-days field would be inventing a promise the customer never made. `x-ms-legal-hold` is
// therefore never sent, and that absence is the honest reading of a form that collects a window.
//
// THE PRECONDITION IS AZURE'S, NOT OURS. A per-blob immutability policy only binds on a container with
// VERSION-LEVEL immutability enabled, which is enabled on the storage account at creation time or on the
// container (at creation, or on an existing container through a migration), and which additionally
// requires blob versioning on the account. A lock-bearing write to a container without it fails. That is
// the same shape as an S3 bucket created without Object-Lock, and it is why the capability probe below
// exists and why the write failure carries a hint naming the Azure setting rather than a bare status.

import { OBJECT_LOCK_REFUSAL_PROP } from "./classify.ts";
import { wormUnknownReasonForStatus } from "./s3-read-ops.ts";
import type { WormMode, WormPolicy, WormStatus } from "./types.ts";
import { AZURE_VERSION_LEVEL_IMMUTABILITY_REMEDY } from "./worm-remedy.ts";

/**
 * AZURE_IMMUTABILITY_MODE maps this engine's retention mode onto the exact token Azure accepts on
 * `x-ms-immutability-policy-mode`. Lower case, because Azure documents the values as `unlocked` and
 * `locked`, where the S3 header takes upper-case GOVERNANCE and COMPLIANCE.
 *
 * Total over WormMode, so this is the single place the internal vocabulary meets the Azure wire spelling,
 * exactly as S3_OBJECT_LOCK_MODE is for the Amazon one.
 */
export const AZURE_IMMUTABILITY_MODE: Record<WormMode, string> = { governance: "unlocked", compliance: "locked" };

/**
 * retainUntilRfc1123 derives the absolute retain-until instant for a blob written NOW, in the RFC 1123
 * form `x-ms-immutability-policy-until-date` requires.
 *
 * THE FORMAT IS THE WHOLE POINT OF THIS FUNCTION EXISTING SEPARATELY from the S3 one. S3 takes an
 * RFC 3339 instant ("") and Azure takes an RFC 1123 one ("Thu, 24 Sep 2026 00:00:00
 * GMT"). Sending either store the other's spelling is a rejected write, so the two are kept apart rather
 * than sharing a formatter with a flag.
 *
 * The window is retentionDays fixed 24-hour spans from the write instant, not calendar days, so a window
 * spanning a daylight-saving change is still exactly retentionDays * 86400 seconds. RFC 1123 has no
 * sub-second component, so the instant is whole seconds by construction. PURE: it reads nothing but its
 * two arguments.
 *
 * @param now - the write instant.
 * @param retentionDays - the window in whole days.
 * @returns the retain-until instant as an RFC 1123 UTC string.
 */
export function retainUntilRfc1123(now: Date, retentionDays: number): string {
  return new Date(now.getTime() + retentionDays * 24 * 60 * 60 * 1000).toUTCString();
}

/**
 * azureImmutabilityHeaders returns the immutability headers for an object-creating write made NOW, or an
 * empty object when no policy is configured (the default, so a non-WORM write is byte-unchanged).
 *
 * ONLY THE TWO POLICY HEADERS ARE SENT. `x-ms-legal-hold` is Azure's independent second primitive, with no
 * expiry and no counterpart in WormPolicy, so it is never derived from a retention window; see this
 * module's header for why that absence is the honest reading rather than a gap.
 *
 * @param worm - the configured policy, or undefined for no immutability.
 * @param now - the write instant, from which the retain-until date is derived.
 * @returns the headers to add to the write, empty when no policy is configured.
 */
export function azureImmutabilityHeaders(worm: WormPolicy | undefined, now: Date): Record<string, string> {
  if (worm === undefined) return {};
  return {
    "x-ms-immutability-policy-until-date": retainUntilRfc1123(now, worm.retentionDays),
    "x-ms-immutability-policy-mode": AZURE_IMMUTABILITY_MODE[worm.mode],
  };
}

/**
 * AZURE_VERSION_LEVEL_IMMUTABILITY_HEADER is the Get Container Properties response header that answers, for
 * ONE container, whether version-level immutability is enabled on it.
 *
// IT IS NOT ON THE PUBLISHED REST REFERENCE PAGE FOR THAT OPERATION, which lists only the older
// `x-ms-has-immutability-policy` (a container-SCOPE policy is set) and `x-ms-has-legal-hold`. It IS in the
// official service specification for the Blob data plane at the API version this client pins on every
// request (AZURE_API_VERSION), described there as "Indicates whether version
 * stand in for it: a container may carry a container-scope immutability policy while refusing every
 * per-blob one, which is precisely the case a probe reading them would get backwards.
 */
export const AZURE_VERSION_LEVEL_IMMUTABILITY_HEADER = "x-ms-immutable-storage-with-versioning-enabled";

/**
 * versionLevelImmutabilityStatus turns ONE Get Container Properties response into a WormStatus.
 *
 * THE ABSENT-HEADER CASE IS THE DELIBERATE DECISION IN THIS FILE, and it is a definite `false` rather than
 * an "unknown". It is worth stating why, because the safe-looking answer is the wrong one here.
 *
 * `wormCannotBeEnforced` (admin/router-destinations.ts) refuses a save on a definite not-enabled and on an
 * "unknown" whose reason is `not-implemented`, and ACCEPTS every other "unknown" as could-not-check. That
 * acceptance is right for a diagnostic gap: refusing a correctly-configured destination because a probe
 * was denied or a packet was lost is the opposite defect. But it is wrong for THIS gap, because of what
 * follows an accepted save: the save-time probe deliberately runs with the policy DISARMED (arming it would
 * leave a locked scratch blob in the customer's container that neither party could remove), so the
 * destination verifies green and then every real backup write carries headers the container will refuse.
 * The customer is told their destination is verified and nothing is ever archived to it.
 *
 * So the two readings are not "strict" against "lenient". They are:
 *   false    -> one refusal at save time, naming an Azure setting the operator can go and change.
 *   unknown  -> a verified destination that stores nothing, discovered whenever someone next looks.
 *
 * The first is recoverable and loud; the second is the exact silent-promise failure the WORM gate exists to
 * prevent. And the common case behind an absent header is not a stripped header at all: it is a container
 * that simply does not have version-level immutability on, which is most containers.
 *
 * NOTE WHAT THIS DOES NOT DO. It does not reinstate the blanket Azure refusal it replaced. A container that
 * IS enabled answers `true` and its policy is accepted and enforced; only a container that has not shown
 * it can enforce is refused, which is the same rule every other store is held to.
 *
 * @param status - the HTTP status Get Container Properties answered with.
 * @param header - the value of AZURE_VERSION_LEVEL_IMMUTABILITY_HEADER, or null when absent.
 * @returns the typed WORM capability verdict.
 */
export function versionLevelImmutabilityStatus(status: number, header: string | null): WormStatus {
  // A credentialed probe answered with a 3xx is a proxy interposing or the wrong host, not a fact about
  // the container. The reason rides on the status class; the redirect target never does.
  if (status >= 300 && status < 400) return { enabled: "unknown", unknownReason: "redirect" };
  if (status !== 200) {
    // The store ANSWERED and refused. Reuses the S3 probe's own classifier rather than growing a second
    // spelling of it: a 401/403 is the credential lacking container read, a 5xx is the store, and a 404
    // (ContainerNotFound here, where the S3 arm's 404 means "no lock configuration") lands on the residual
    // because a container that is not there is not a statement about what a container can enforce.
    return { enabled: "unknown", unknownReason: wormUnknownReasonForStatus(status) };
  }
  // Only the exact string "true" is enforcement. Anything else, including the header being absent, is the
  // definite not-enabled reading argued for above.
  //
  // defaultMode / defaultDays are deliberately NEVER set. Azure's account-level and container-level DEFAULT
  // retention rules live on the management plane, and this client holds a storage-account key or a SAS,
  // which reach the data plane only. Claiming a default we cannot read would be worse than omitting it, and
  // omitting it costs nothing that matters: every archive write this engine makes under a policy carries
  // its own explicit retain-until date and mode, so no archive object depends on the container default.
  return { enabled: header === "true" };
}

/**
 * AZURE_IMMUTABILITY_UNSUPPORTED_HINT is appended to the failure of a write that CARRIED the immutability
 * headers, so the operator is not left reading a bare status.
 *
 * WITHOUT IT the failure is undiagnosable in the wrong direction. The write is refused because of a
 * setting on the AZURE STORAGE ACCOUNT, but everything visible says downpipes: an engine error message, on
 * an engine run, about an engine destination that the product itself reported as verified. The first move
 * is then to audit the credential, which was never the problem, or to raise it as a downpipes defect. The
 * hint names the setting, says plainly that it is Azure's rather than ours, and names the one thing that
 * makes it awkward, that an existing container needs a migration rather than a checkbox.
 *
 * It is a FIXED string with no interpolation of anything the store said, so no byte of the store's
 * response can reach an operator surface through it: the one interpolated part is a build-time constant,
 * AZURE_VERSION_LEVEL_IMMUTABILITY_REMEDY, shared with the posture check and the add-time refusal so the
 * sentence a failed write carries and the sentence a check offers cannot drift apart.
 */
export const AZURE_IMMUTABILITY_UNSUPPORTED_HINT = ` This write carried Azure immutability headers. ${AZURE_VERSION_LEVEL_IMMUTABILITY_REMEDY}`;

// AZURE_IMMUTABILITY_REFUSAL_CODES are Azure's own closed error codes for "the blob's immutability policy or
// legal hold refused this operation". They are the ENFORCEMENT direction: the store is applying a lock we
// or the customer set, which is the retention prune meeting a still-locked archive object. Matched against
// the x-ms-error-code header, which is a member of Azure's documented enum and never free text.
//
// They are recognised UNCONDITIONALLY, unlike the lock-armed hint above, because each one names the lock
// policy on its own: they cannot be produced by anything else.
const AZURE_IMMUTABILITY_REFUSAL_CODES = new Set(["BlobImmutableDueToPolicy", "BlobImmutableDueToLegalHold", "ContainerImmutabilityPolicyLocked", "ContainerHasLegalHold"]);

/**
 * stampAzureImmutabilityRefusal marks an error as an immutability refusal when Azure's own error code says
 * the store's lock policy is what refused it, or when the failed request was itself carrying lock headers.
 *
 * It puts the SAME boolean property the S3 path uses (OBJECT_LOCK_REFUSAL_PROP), so an Azure lock refusal
 * reaches the down-reason classifier on the one rail rather than falling through to a generic permanent
 * fault. The two stores decide it from different evidence, an Azure error-code header against an S3
 * response body, because that is where each store puts it; the VERDICT they produce is one shape.
 *
 * @param e - the error to stamp (returned unchanged when this is not an immutability refusal).
 * @param code - the x-ms-error-code header value, or "" when the response carried none.
 * @param lockArmed - whether the failed request carried the immutability headers.
 * @returns the same error, stamped when the verdict is true.
 */
export function stampAzureImmutabilityRefusal(e: Error, code: string, lockArmed: boolean): Error {
  const refused = AZURE_IMMUTABILITY_REFUSAL_CODES.has(code) || lockArmed;
  return refused ? Object.assign(e, { [OBJECT_LOCK_REFUSAL_PROP]: true }) : e;
}
