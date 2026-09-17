// Addressing-resolution vectors for the S3 destination: resolveAddressing's three arms, and the
// DOUBLE-BUCKETED endpoint refusal in particular.
//
// Why this file exists. An operator who pastes their provider console's PER-BUCKET URL
// ("https://mybucket.s3.amazonaws.com") into the endpoint box, rather than the bare service endpoint
// ("https://s3.amazonaws.com"), used to get the bucket prepended a SECOND time. The measured behaviour
// before the guard, driven through this same function:
//
//   mybucket.s3.amazonaws.com              + mybucket, auto   ->  mybucket.mybucket.s3.amazonaws.com
//   mybucket.s3.ap-southeast-2.amazonaws.com + mybucket, auto ->  mybucket.mybucket.s3.ap-southeast-2.amazonaws.com
//   mybucket.s3.wasabisys.com              + mybucket, vhost  ->  mybucket.mybucket.s3.wasabisys.com
//
// The AUTO arm is the one that matters, which is not the intuitive way round. Under explicit vhost the
// doubled host simply does not resolve and the destination probe fails, so nothing is stored and the
// operator is only misdiagnosed. Under auto, answering path-style instead would have been WORSE than the
// throw: "https://mybucket.s3.amazonaws.com/mybucket/key" is a request AWS accepts, because the host has
// already selected the bucket and the path is then read as the KEY, so every archive lands under a
// "mybucket/" prefix nobody asked for. Both arms therefore refuse.
//
// The over-fire vectors below carry as much weight as the refusals. A guard on "the host starts with the
// bucket name" alone would refuse legitimate configurations, so the check also requires the REMAINDER to
// be a recognised object-storage service endpoint, and these vectors pin that.

import { resolveAddressing, type Addressing } from "../src/dest/s3-addressing.ts";
import { DestBuildError } from "../src/dest/build-health.ts";
import { ok } from "./validate-s3dest-shared.ts";

// The outcome of one resolveAddressing call, flattened so a throw is a value rather than control flow.
type Outcome = "vhost" | "path" | "throw";

function resolve(host: string, bucket: string, addressing: Addressing | undefined): { outcome: Outcome; cause?: string } {
  try {
    return { outcome: resolveAddressing(host, bucket, addressing) ? "vhost" : "path" };
  } catch (e) {
    // The cause is asserted, not just the fact of a throw: destBuildFaultOf classifies on the TYPED
    // buildCause, so a plain Error here would land in the destBuild health record as the residual "other"
    // and the operator would lose the one-edit remedy. That is the exact defect class the DEAD VOCABULARY
    // note in s3-addressing.ts records for three earlier causes.
    return { outcome: "throw", cause: e instanceof DestBuildError ? e.buildCause : "NOT-A-DestBuildError" };
  }
}

// VECTORS is the whole table, refusals and non-refusals together, so a change that widens the guard shows
// up as a flipped non-refusal rather than as a silently larger refusal set.
const VECTORS: ReadonlyArray<{ host: string; bucket: string; addressing: Addressing | undefined; want: Outcome; why: string }> = [
  // --- the doubled endpoint, refused on both arms ---
  { host: "mybucket.s3.amazonaws.com", bucket: "mybucket", addressing: undefined, want: "throw", why: "an AWS console per-bucket URL under auto is refused, never answered path-style" },
  { host: "mybucket.s3.amazonaws.com", bucket: "mybucket", addressing: "vhost", want: "throw", why: "an AWS console per-bucket URL under explicit vhost is refused" },
  { host: "mybucket.s3.ap-southeast-2.amazonaws.com", bucket: "mybucket", addressing: undefined, want: "throw", why: "a REGIONAL per-bucket URL is refused under auto" },
  { host: "mybucket.s3-ap-southeast-2.amazonaws.com", bucket: "mybucket", addressing: "vhost", want: "throw", why: "the legacy s3-<region> spelling AWS still answers on is refused too" },
  { host: "mybucket.s3.wasabisys.com", bucket: "mybucket", addressing: "vhost", want: "throw", why: "a non-AWS per-bucket URL under explicit vhost is refused" },
  { host: "MyBucket.S3.amazonaws.com", bucket: "mybucket", addressing: "vhost", want: "throw", why: "the host comparison is case-insensitive, so a mixed-case paste is refused too" },

  // --- the documented escape: keep the endpoint, choose path ---
  { host: "mybucket.s3.amazonaws.com", bucket: "mybucket", addressing: "path", want: "path", why: "an explicit path style is honoured even for a per-bucket endpoint: it is the remedy the message offers" },

  // --- must NOT over-fire ---
  { host: "s3.amazonaws.com", bucket: "mybucket", addressing: undefined, want: "vhost", why: "the correct bare AWS endpoint still selects vhost under auto" },
  { host: "s3.ap-southeast-2.amazonaws.com", bucket: "data", addressing: undefined, want: "vhost", why: "a regional bare endpoint still selects vhost under auto" },
  // addressing is EXPLICIT vhost here on purpose. Under auto this host is path-style anyway (it is not
  // .amazonaws.com), so the guard would never be consulted and the vector would pass without testing
  // anything: it survived a mutant that made bucketIsAlreadyLeadingLabel return true unconditionally.
  // Forcing the vhost arm makes the guard run, so the assertion is about the guard rather than about the
  // auto arm's host test.
  { host: "storage.googleapis.com", bucket: "storage", addressing: "vhost", want: "vhost", why: "a bucket named after a bare endpoint's leading label does not fire the guard: stripping it leaves googleapis.com, which is not a service endpoint" },
  { host: "storage.googleapis.com", bucket: "mybucket", addressing: undefined, want: "path", why: "GCS is path-style under auto (non-AWS host)" },
  { host: "acct.r2.cloudflarestorage.com", bucket: "mybucket", addressing: undefined, want: "path", why: "R2 is path-style under auto (non-AWS host)" },
  { host: "s3.wasabisys.com", bucket: "mybucket", addressing: undefined, want: "path", why: "a non-AWS bare endpoint is path-style under auto" },
  { host: "mybucket.example.com", bucket: "mybucket", addressing: "vhost", want: "vhost", why: "a bucket-named host that is NOT an object-storage endpoint is none of the guard's business" },
];

function addressingVectors(): void {
  console.log("resolveAddressing: doubled-endpoint refusal and the arms it must not touch:");
  for (const v of VECTORS) {
    const got = resolve(v.host, v.bucket, v.addressing);
    ok(`${v.why} (${v.host} + ${v.bucket}, addressing=${String(v.addressing)})`, got.outcome === v.want);
    if (v.want === "throw") {
      ok(`  ...and it is refused as the closed cause vhost-bucket-doubled, not the residual "other"`, got.cause === "vhost-bucket-doubled");
    }
  }
}

// The pre-existing unsafe-bucket refusal has to keep its OWN cause. The two refusals are different
// operator remedies (a hostile bucket NAME versus a pasted per-bucket URL) and collapsing them would undo
// the reason the vocabulary is closed at all.
function unsafeBucketKeepsItsOwnCause(): void {
  console.log("the character-break refusal keeps its own distinct cause:");
  const got = resolve("s3.amazonaws.com", "attacker.example/x", "vhost");
  ok("a bucket containing a host-breaking character is still refused", got.outcome === "throw");
  ok("...and still as vhost-bucket-unsafe, distinct from vhost-bucket-doubled", got.cause === "vhost-bucket-unsafe");
}

// The 3-character floor in VHOST_SAFE_BUCKET is PRE-EXISTING and unrelated to the guard, pinned here
// because it is why a bucket literally named "s3" resolves path-style rather than vhost: a two-character
// name is below S3's own minimum, so no such bucket exists to be double-bucketed in the first place.
function shortBucketIsPathStyleUnderAuto(): void {
  console.log("the vhost-safe bucket floor (pre-existing):");
  ok('a two-character bucket name resolves path-style under auto (below the 3-char vhost-safe floor)', resolve("s3.amazonaws.com", "s3", undefined).outcome === "path");
}

export async function run(): Promise<void> {
  addressingVectors();
  unsafeBucketKeepsItsOwnCause();
  shortBucketIsPathStyleUnderAuto();
}
