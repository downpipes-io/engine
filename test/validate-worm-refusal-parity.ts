// WORM REFUSAL PARITY: one rule, graded over every surface that words the not-enforced reading.
//
// WHY THIS FILE EXISTS. the same input produced two contradictory sentences from two
// builders in the same repository, and each was PINNED BY ITS OWN SUITE:
//
//   buildImmutability({configured, !misconfigured, bucketEnforces:false}).detail
//     "The retention headers are ignored by the store, so archives are NOT protected despite the policy."
//     asserted "unchanged byte for byte" by test/validate-posture-compute.ts
//
//   buildImmutabilityReport(dest, same).destinations[0].property
//     "the store refuses every write carrying the lock headers, so no archive is stored here"
//     with test/validate-reports.ts asserting the SAME reading does not match /ignored|discarded/
//
// One suite required the words the other forbade, about the same fact, in the same landing. Neither could
// see the other, because each graded its own builder. This gate grades BOTH from one place, so the next
// divergence is a red rather than a contradiction that survives two green suites.
//
// THE RULE, and it is a fact about the stores rather than a house preference.
//
//   A bucket that does not enforce S3 Object-Lock does not accept a lock-bearing write and drop the
//   headers. It REFUSES the write. Cloudflare R2 answers 501 NotImplemented; AWS S3 answers
//   ObjectLockConfigurationNotFoundError. Therefore, on the NOT-ENFORCED reading:
//     (a) every surface must say the store refuses the write and that nothing is stored there;
//     (b) no surface may say the headers are ignored, discarded, stripped or accepted;
//     (c) no surface may describe archives on that destination as unprotected, because there are none.
//
// EVIDENCE FOR THE RULE, not asserted from memory. AWS's code is already a member of OBJECT_LOCK_CODE_RE
// (src/dest/s3-worm.ts) and drives the worm-refused classification. R2's answer was measured live in the
// drive that found this defect: PUT _RECOVERY/.write-probe returned status 501 (NotImplemented),
// with a no-WORM destination on the SAME bucket and the SAME credential answering ok, so the refusal is
// attributable to the policy rather than to the bucket or the credential. harness/manifest/dest-resources
// carries the separate live probe showing R2 cannot enable Object-Lock on any bucket at all.
//
// THE SECOND RULE, added and about the REMEDY rather than the reading. Four providers are
// supported and they have FOUR DIFFERENT MECHANISMS, so one sentence cannot serve them:
//
//   Amazon S3 (and other S3-compatible stores) - Object-Lock, settable only at bucket creation.
//   Google Cloud Storage - a bucket created with PER-OBJECT RETENTION, which its S3-interoperable
// endpoint reports as Object-Lock enabled. Measured against a real bucket.
//   Azure Blob Storage - VERSION-LEVEL IMMUTABILITY on the container or storage account. Not Object-Lock,
//     and an existing container has to be migrated rather than switched.
// Cloudflare R2 - NOTHING, by any route. Measured over its S3 endpoint with this repo's own
//     signer: GET /<bucket>/?object-lock= answers 404 ObjectLockConfigurationNotFoundError, and a PUT
//     carrying x-amz-object-lock-mode: COMPLIANCE answers 501 NotImplemented, naming the header. R2 is the
//     one provider with no remedy, and saying so is the only honest answer.
//
// Until that date every surface served Amazon's sentence to all four, and r2.ts additionally claimed that
// R2 DOES support Object-Lock through its S3 API, on the strength of which four surfaces published "reach
// the bucket by its S3 endpoint" as the fix. An operator who followed it got a 501 on every write and an
// archive holding nothing. So the rule is: the remedy a surface offers must name THAT store's mechanism,
// and must never offer Amazon's to a store that does not have it.
//
// WHAT THIS GATE DOES NOT DO. It does not pin either sentence byte for byte; the two owning suites still do
// that, and they should, because a byte pin catches an accidental rewrite that a rule cannot. This grades
// the CLAIM. It also keeps the two neighbouring readings as controls, because the cheap way to make a
// refusal rule pass everywhere is to say "refused" everywhere, and that would be a new overclaim: an
// INVALID policy arms nothing, so its writes are accepted and its archives really are unprotected, and a
// CANNOT-CONFIRM probe has established neither.

import { buildImmutability } from "../src/admin/posture-checks.ts";
import { buildImmutabilityReport } from "../src/admin/reports.ts";
import type { DestProvider } from "../src/dest/provider.ts";
import type { PostureInput } from "../src/admin/posture.ts";
import { healthyInput } from "./validate-posture-shared.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  if (cond) {
    console.log(`  ok   ${label}`);
  } else {
    console.log(`  FAIL ${label}`);
    failures++;
  }
}

/** The vocabulary the rule forbids on the not-enforced reading: the store did none of these. */
const IGNORED_RE = /ignored|discarded|stripped|accepted and dropped/i;
/** The vocabulary the rule requires: the store refused, and nothing is there. */
const REFUSES_RE = /refuses? every write|REFUSES every write|cannot be written to|refused by the store/i;
const NOTHING_STORED_RE = /no archive is stored|holds no archives|nothing is stored|no backup/i;
/** The strong claim. It must never appear on a destination that holds nothing. */
const STRONG_RE = /cannot hard-delete or overwrite an archive|cannot hard-delete an archive within/;

type Worm = NonNullable<PostureInput["worm"]>;
const DEST = { destConfigured: true, destKind: "s3" as const, breakGlassConfigured: true, operationalConfigured: { public: false, private: true } };

/** The posture input, built from the SAME healthy fixture validate-posture-compute.ts uses, with only the
 *  WORM slice varied. Sharing the fixture is deliberate: a bespoke input here could drift into a shape the
 *  real check never sees, which is how a gate ends up grading a fiction. */
function postureCheck(worm: Worm) {
  return buildImmutability({ ...healthyInput(), worm });
}
/** The posture check's customer-visible detail. The console renders it under the label "Observed". */
function postureDetail(worm: Worm): string {
  return postureCheck(worm)?.detail ?? "";
}
/** The signed immutability report's per-destination property line. */
function reportProperty(worm: Parameters<typeof buildImmutabilityReport>[1]): string {
  return buildImmutabilityReport(DEST, worm).destinations[0]?.property ?? "";
}
/** The signed report's attestation paragraph, which is the sentence a customer hands an auditor. */
function reportAttestation(worm: Parameters<typeof buildImmutabilityReport>[1]): string {
  return buildImmutabilityReport(DEST, worm).attestation;
}

// The armed, valid policy on a bucket the probe read as NOT enforcing. This is the state the whole rule is
// about, and it is reachable: buildEnvS3Destination (src/dest/factory.ts) arms DEST_WORM_MODE and
// DEST_WORM_RETENTION_DAYS straight from parseWormPolicy with no probe, and the add-time refusal in
// validateAndProbeDestConfig only runs for a CONSOLE-SET destination, so a deploy-time pair against a
// non-Object-Lock S3 bucket lands here untouched.
const NOT_ENFORCED: Worm = { configured: true, misconfigured: false, mode: "compliance", retentionDays: 365, bucketEnforces: false };

function surfacesAgreeOnTheRefusal(): void {
  console.log("\n-- the not-enforced reading: every surface says the store refused, none says it ignored --");
  const surfaces: Array<[string, string]> = [
    ["posture check detail (console renders this as \"Observed\")", postureDetail(NOT_ENFORCED)],
    ["immutability report, destination property", reportProperty(NOT_ENFORCED)],
    ["immutability report, attestation", reportAttestation(NOT_ENFORCED)],
  ];
  for (const [name, text] of surfaces) {
    ok(`${name}: is not empty`, text.length > 0);
    ok(`${name}: says the store refuses the write`, REFUSES_RE.test(text));
    ok(`${name}: says nothing is stored on that destination`, NOTHING_STORED_RE.test(text));
    ok(`${name}: does NOT say the headers are ignored, discarded or stripped`, !IGNORED_RE.test(text));
    ok(`${name}: does NOT make the strong store-enforced claim`, !STRONG_RE.test(text));
  }
  // (c) explicitly: a destination that holds nothing has no archives to describe as unprotected. This is
  // the exact half-truth the posture detail carried, and a regex on "ignored" alone would not catch a
  // rewrite that dropped the word and kept the false consequence.
  for (const [name, text] of surfaces) {
    ok(`${name}: does NOT describe archives there as merely unprotected`, !/archives are NOT protected|archives are not protected|tamper-evident but they are not write-once-locked/.test(text));
  }
  // The posture check's REMEDIATION rides beside the detail on the same console card. It used to end
  // "immutability is not actually protecting your archives", which contradicts a detail saying there are
  // no archives, on the same card, in the same request.
  const remediation = postureCheck(NOT_ENFORCED)?.remediation ?? "";
  ok("posture remediation: does not claim archives exist but are unprotected", !/not actually protecting your archives/.test(remediation));
  ok("posture remediation: names the refusal as the consequence", /refused by the store/.test(remediation));
  ok("posture remediation: still names the only real fix, a bucket created with Object-Lock", /Object-Lock ENABLED/.test(remediation));
}

function theVerdictIsStillAFailure(): void {
  console.log("\n-- the verdict is unchanged: correcting the sentence must not soften the grade --");
  const check = postureCheck(NOT_ENFORCED);
  ok("not-enforced still FAILS the immutability check", check?.auto === "fail");
  ok("not-enforced report still carries the not-in-force note the reconciler requires", /store-enforced Object-Lock is NOT in force/.test(reportProperty(NOT_ENFORCED)));
}

function theNeighbouringReadingsAreControls(): void {
  console.log("\n-- controls: the two readings next door must NOT acquire the refusal wording --");

  // CANNOT-CONFIRM. The probe got no answer. Asserting a refusal here is the same overclaim in the other
  // direction, and it is the reading a least-privilege credential and every native R2 binding produce.
  for (const [label, worm] of [
    ["explicit unknown", { configured: true, misconfigured: false, bucketEnforces: "unknown" as const }],
    ["absent verdict", { configured: true, misconfigured: false }],
  ] as const) {
    const detail = postureDetail(worm as Worm);
    const property = reportProperty(worm);
    ok(`cannot-confirm (${label}): the posture detail does not claim a refusal`, !REFUSES_RE.test(detail));
    // "S3 Object-Lock", not the bare "Object-Lock" this asserted until. The posture check now
    // reads its noun and its mechanism from dest/worm-remedy.ts like the report does, so the unknown-provider
    // fallback spells the mechanism the same way on both surfaces. The store noun is left open here because
    // the per-provider block below grades it properly; pinning "bucket" in this control is what kept the
    // check saying "bucket" to an Azure customer for as long as it did.
    ok(`cannot-confirm (${label}): the posture detail says enforcement could not be confirmed`, /could not confirm the destination (bucket|container) enforces S3 Object-Lock/.test(detail));
    ok(`cannot-confirm (${label}): the report does not claim a refusal`, !REFUSES_RE.test(property));
    ok(`cannot-confirm (${label}): the report does not make the strong claim`, !STRONG_RE.test(property));
  }

  // INVALID POLICY. Nothing is armed, so no lock header is written, so the store accepts the write. The
  // archives really are there and really are unprotected. This is the one reading where "archives are not
  // protected" is TRUE, and it must keep saying so.
  const invalidUnenforced: Worm = { configured: true, misconfigured: true, bucketEnforces: false };
  const invalidDetail = postureDetail(invalidUnenforced);
  ok("invalid policy on a non-enforcing bucket: the posture detail does NOT borrow the refusal wording", !REFUSES_RE.test(invalidDetail));
  ok("invalid policy on a non-enforcing bucket: the posture detail still says archives are NOT protected", /archives are NOT protected/.test(invalidDetail));
  const invalidProperty = reportProperty(invalidUnenforced);
  ok("invalid policy on a non-enforcing bucket: the report does NOT borrow the refusal wording", !REFUSES_RE.test(invalidProperty));

  // ENFORCED AND ARMED. The strong claim, untouched. Kept here so no future widening of the refusal
  // vocabulary can reach the one state that has earned the strong sentence.
  const enforced: Worm = { configured: true, misconfigured: false, mode: "compliance", retentionDays: 365, bucketEnforces: true };
  ok("enforced + armed: the posture check passes", postureCheck(enforced)?.auto === "pass");
  ok("enforced + armed: the posture detail keeps the strong claim", STRONG_RE.test(postureDetail(enforced)));
  ok("enforced + armed: the posture detail claims no refusal", !REFUSES_RE.test(postureDetail(enforced)));
  ok("enforced + armed: the report keeps the strong claim", STRONG_RE.test(reportProperty(enforced)));
  ok("enforced + armed: the report claims no refusal", !REFUSES_RE.test(reportProperty(enforced)));
}

function theTwoSurfacesDoNotContradictEachOther(): void {
  console.log("\n-- the contradiction itself: no reading may have one surface refusing and another ignoring --");
  // The general form of the defect, over the whole enforcement axis rather than the one input that was
  // found. If any reading ever has one surface asserting a refusal while another asserts the headers were
  // ignored, that is the defect back, whichever reading it lands on.
  const readings: Array<[string, Worm]> = [
    ["armed + not enforcing", NOT_ENFORCED],
    ["armed + cannot confirm", { configured: true, misconfigured: false, mode: "governance", retentionDays: 14, bucketEnforces: "unknown" }],
    ["armed + enforcing", { configured: true, misconfigured: false, mode: "compliance", retentionDays: 365, bucketEnforces: true }],
    ["invalid + not enforcing", { configured: true, misconfigured: true, bucketEnforces: false }],
    ["invalid + enforcing", { configured: true, misconfigured: true, bucketEnforces: true, defaultRetention: false }],
    ["no policy + enforcing", { configured: false, misconfigured: false, bucketEnforces: true, defaultRetention: false }],
    ["no policy + not enforcing", { configured: false, misconfigured: false, bucketEnforces: false }],
  ];
  for (const [label, worm] of readings) {
    const detail = postureDetail(worm);
    const property = reportProperty(worm);
    ok(`${label}: no surface says the headers were ignored`, !IGNORED_RE.test(detail) && !IGNORED_RE.test(property));
    ok(`${label}: the two surfaces agree on whether the store refused`, REFUSES_RE.test(detail) === REFUSES_RE.test(property));
  }
}

/** The Amazon-shaped remedy. It is correct for an S3-compatible store and for nobody else. */
const AMAZON_REMEDY_RE = /Object-Lock ENABLED \(it can only be set when the bucket is created/;
/** Every provider's remedy has to offer the operator a way OUT of the refusal, whatever that way is. Two
 *  spellings, because the Azure sentence is SHARED with the write-failure hint azure-blob.ts appends to a
 *  refused write (AZURE_VERSION_LEVEL_IMMUTABILITY_REMEDY), where "remove the immutability policy from this
 *  destination" is the phrasing that fits. Both say the same thing; what is graded is that one of them is
 *  there, because a remedy with no way out leaves an operator whose only option is a store migration. */
const TURN_IT_OFF_RE = /set the WORM mode back to off|remove the immutability policy from this destination/;

/** The posture remediation for an ARMED policy on a store the probe read as not enforcing, per provider. */
function remedyFor(provider: DestProvider): string {
  return postureCheck({ ...NOT_ENFORCED, provider })?.remediation ?? "";
}

function theRemedyIsTheStoreSOwn(): void {
  console.log("\n-- the remedy names THAT store's mechanism, and never Amazon's on a store without it --");
  // The four are asserted from ONE table rather than four hand-written blocks, so a fifth provider added to
  // DestProvider without a remedy fails to compile here rather than quietly inheriting the S3 sentence.
  const expected: Record<DestProvider, RegExp> = {
    s3: AMAZON_REMEDY_RE,
    gcs: /per-object retention turned on, which is only available when the bucket is created/,
    azure: /VERSION-LEVEL IMMUTABILITY/,
    r2: /501 NotImplemented/,
  };
  for (const provider of Object.keys(expected) as DestProvider[]) {
    const remedy = remedyFor(provider);
    ok(`${provider}: the remedy is not empty`, remedy.length > 0);
    ok(`${provider}: the remedy names this store's own mechanism`, expected[provider].test(remedy));
    ok(`${provider}: the remedy still offers a way out (turn the policy off)`, TURN_IT_OFF_RE.test(remedy));
    ok(`${provider}: the remedy still names the refusal as the consequence`, /refused by the store/.test(remedy));
    // The half that moves. Amazon's sentence on a store without Object-Lock sends the operator to a control
    // their own console does not have, which is the defect in its general form.
    if (provider !== "s3") ok(`${provider}: the remedy does NOT offer Amazon's Object-Lock-at-create-time sentence`, !AMAZON_REMEDY_RE.test(remedy));
  }
  // R2 is the one provider with NO remedy, so its sentence must not send the operator anywhere at all: not
  // to a re-created bucket, and above all not to the S3 endpoint, which is the exact advice that shipped.
  const r2 = remedyFor("r2");
  ok("r2: the remedy does NOT send the operator to the S3 endpoint", !/reach(ing)? the bucket (via|by) its S3 endpoint|use the S3 endpoint|configure it via the S3 endpoint/i.test(r2));
  ok("r2: the remedy does NOT tell the operator to re-create the bucket", !/[Rr]e-create the destination bucket/.test(r2));
  ok("r2: the remedy states plainly that no route works", /any bucket and by any route/.test(r2));
  // The REPORT is graded from the same table, on the mechanism it NAMES rather than the remedy it offers,
  // because a signed attestation asserts and does not instruct. This is the reports.ts half of the defect:
  // every branch said "S3 Object-Lock", including on an Azure container.
  const enforced: Worm = { configured: true, misconfigured: false, mode: "compliance", retentionDays: 365, bucketEnforces: true };
  const named: Record<DestProvider, RegExp> = {
    s3: /the bucket enforces S3 Object-Lock/,
    gcs: /the bucket enforces Object Lock \(Google Cloud Storage per-object retention\)/,
    azure: /the container enforces version-level immutability/,
    r2: /the bucket enforces write-once retention/,
  };
  for (const provider of Object.keys(named) as DestProvider[]) {
    const property = buildImmutabilityReport({ ...DEST, destKind: provider }, enforced).destinations[0]?.property ?? "";
    ok(`${provider}: the signed report names this store's own mechanism`, named[provider].test(property));
    if (provider !== "s3") ok(`${provider}: the signed report does NOT name S3 Object-Lock`, !/S3 Object-Lock/.test(property));
  }
  // The report's NOT-IN-FORCE sentence also states WHEN that store's mechanism can be turned on, and
  // Amazon's "Object-Lock can only be enabled when a bucket is created" was asserted on all four. On Azure
  // it is a container migration, and on R2 there is no moment at all: no bucket of its can hold one.
  const enableWhen: Record<DestProvider, RegExp> = {
    s3: /Object-Lock can only be enabled when a bucket is created\./,
    gcs: /Per-object retention can only be turned on when a bucket is created\./,
    azure: /an existing container has to be migrated to it/,
    r2: /no bucket of its can be created or reconfigured to hold one/,
  };
  for (const provider of Object.keys(enableWhen) as DestProvider[]) {
    const property = buildImmutabilityReport({ ...DEST, destKind: provider }, NOT_ENFORCED).destinations[0]?.property ?? "";
    ok(`${provider}: the not-in-force report says when THIS store's mechanism can be turned on`, enableWhen[provider].test(property));
    if (provider !== "s3") ok(`${provider}: ...and not Amazon's bucket-creation sentence`, !enableWhen.s3.test(property));
  }

  // Azure calls it a container. An attestation that calls it a bucket describes a thing the operator cannot
  // find in their own portal, and the three bucket providers must not acquire the Azure noun either.
  const azureProperty = buildImmutabilityReport({ ...DEST, destKind: "azure" }, enforced).destinations[0]?.property ?? "";
  ok("azure: the signed report calls it a container, not a bucket", /the container enforces/.test(azureProperty) && !/the bucket enforces/.test(azureProperty));
  const s3Property = buildImmutabilityReport({ ...DEST, destKind: "s3" }, enforced).destinations[0]?.property ?? "";
  ok("s3 CONTROL: an S3 destination is still a bucket", /the bucket enforces/.test(s3Property) && !/the container enforces/.test(s3Property));
}

/**
 * THE POSTURE CHECK'S OWN DETAIL, graded per provider exactly as the report's property is above.
 *
 * This block is the reason the file grew a second time. The per-provider work landed in the
 * signed report and in the REMEDY sentence of this check, and stopped there: the check's DETAIL, the line
 * the console renders to a customer under "Observed", still said "the destination bucket enforces S3
 * Object-Lock" on an Azure container. That is the half-landed shape, and what let it sit was this gate
 * itself, whose cannot-confirm control REQUIRED the word "bucket". A gate that pins the unfixed half is
 * worse than no gate, because it reads as coverage.
 *
 * The detail and the property are graded by the same expectations here, so the next divergence between
 * them is a red rather than one surface quietly keeping Amazon's vocabulary.
 */
function thePostureDetailSpeaksEachStoreSOwnVocabulary(): void {
  console.log("\n-- the posture check's detail names THIS store's mechanism and noun --");
  const named: Record<DestProvider, RegExp> = {
    s3: /S3 Object-Lock/,
    gcs: /Google Cloud Storage per-object retention/,
    azure: /version-level immutability/,
    r2: /write-once retention/,
  };
  const enforcedArmed: Worm = { configured: true, misconfigured: false, bucketEnforces: true, mode: "compliance", retentionDays: 30 };
  for (const provider of Object.keys(named) as DestProvider[]) {
    const detail = postureDetail({ ...enforcedArmed, provider });
    ok(`${provider}: the posture detail names this store's own mechanism`, named[provider].test(detail));
    // R2 is exempt from the S3 exclusion only in the sense that it never reaches this branch in the wild
    // (it enforces nothing), but its label must still not be Amazon's.
    if (provider !== "s3") ok(`${provider}: the posture detail does NOT name S3 Object-Lock`, !/S3 Object-Lock/.test(detail));
  }
  // The noun, on the reading a customer is most likely to be shown.
  const azureDetail = postureDetail({ ...enforcedArmed, provider: "azure" });
  ok("azure: the posture detail calls it a container, not a bucket", /the destination container enforces/.test(azureDetail) && !/destination bucket/.test(azureDetail));
  const s3Detail = postureDetail({ ...enforcedArmed, provider: "s3" });
  ok("s3 CONTROL: the posture detail still calls an S3 destination a bucket", /the destination bucket enforces/.test(s3Detail) && !/destination container/.test(s3Detail));

  // The not-enforced reading carries the WHEN-IT-CAN-BE-TURNED-ON sentence, and Amazon's must not be
  // served to the two stores it is wrong for. This is the sentence an operator acts on.
  const notEnforcedAzure = postureDetail({ configured: true, misconfigured: false, bucketEnforces: false, provider: "azure" });
  ok("azure: the not-enforced detail says the container has to be MIGRATED", /an existing container has to be migrated to it/.test(notEnforcedAzure));
  ok("azure: ...and does not offer Amazon's create-time sentence", !/only be enabled when a bucket is created/.test(notEnforcedAzure));
  const notEnforcedGcs = postureDetail({ configured: true, misconfigured: false, bucketEnforces: false, provider: "gcs" });
  ok("gcs: the not-enforced detail names per-object retention at bucket creation", /Per-object retention can only be turned on when a bucket is created\./.test(notEnforcedGcs));
}

function main(): void {
  console.log("WORM REFUSAL PARITY");
  surfacesAgreeOnTheRefusal();
  theRemedyIsTheStoreSOwn();
  theVerdictIsStillAFailure();
  theNeighbouringReadingsAreControls();
  theTwoSurfacesDoNotContradictEachOther();
  thePostureDetailSpeaksEachStoreSOwnVocabulary();
  console.log(failures === 0 ? "\nWORM REFUSAL PARITY PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
