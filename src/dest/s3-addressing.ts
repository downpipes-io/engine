import { DestBuildError } from "./build-health.ts";

/**
 * requireHttpsEndpoint rejects a destination endpoint that is not https, so a misconfigured
 * http:// endpoint cannot transmit the SigV4 Authorization credential and the archive bytes
 * in cleartext (V12.3.1: no fallback to unencrypted transport). The only exception is a plain
 * http://localhost or http://127.0.0.1 endpoint, which never leaves the host and is the local
 * test loopback (MinIO/LocalStack); everything else must be https. The check is on the scheme
 * and host only, parsed once, so a typo fails loud at construction rather than on the wire.
 *
 * It returns void and communicates ONLY by throwing DestBuildError, tagged endpoint-unparseable or
 * endpoint-not-https. The loopback allowance covers the literal hosts localhost, 127.0.0.1 and [::1],
 * so 127.0.0.2 or a name that merely resolves to loopback is still refused.
 *
 * DEAD VOCABULARY: all three throws below are TYPED (DestBuildError) rather than plain Errors.
 * destBuildFaultOf classifies on the TYPE and never on the message text (deliberately: the message carries the
 * endpoint and the bucket), so a plain Error from here landed in the destBuild health record as the residual
 * cause "other". Three declared DEST_BUILD_CAUSES members -- endpoint-unparseable, vhost-bucket-unsafe and
 * endpoint-not-https -- therefore had no producer: "every backup has been failing to even BUILD its
 * destination since Tuesday" was in the pack, and WHY was not. varName is deliberately NOT set: the same
 * helper serves the env destination (DEST_ENDPOINT) and the console-set one (the stored `endpoint` field), and
 * naming the wrong one would be a false fact. The message and the throw itself are byte-unchanged.
 */
export function requireHttpsEndpoint(endpoint: string): void {
  let u: URL;
  try {
    u = new URL(endpoint);
  } catch {
    throw new DestBuildError("endpoint-unparseable", `DEST_ENDPOINT is not a valid URL: ${JSON.stringify(endpoint)}`);
  }
  if (u.protocol === "https:") return;
  const isLocalLoopback = u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]");
  if (isLocalLoopback) return;
  throw new DestBuildError(
    "endpoint-not-https",
    `DEST_ENDPOINT must use https (got ${JSON.stringify(u.protocol)}); a non-https endpoint would transmit the SigV4 credential and archive bytes in cleartext`,
  );
}

/** The request-addressing style for an S3-compatible endpoint: "path" (https://host/bucket/key),
 * "vhost" (https://bucket.host/key), or "auto" (the default: vhost for AWS S3 with a DNS-safe bucket,
 * path-style everywhere else). */
export type Addressing = "auto" | "path" | "vhost";

// VHOST_SAFE_BUCKET matches a bucket name usable as a DNS SUBDOMAIN for virtual-hosted addressing
// (lower-case letters, digits and hyphens; 3 to 63 characters; NO dots, since a dotted name breaks TLS
// SNI under vhost and AWS itself falls back to path-style for it). Anything else must use path-style.
const VHOST_SAFE_BUCKET = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

// VHOST_UNSAFE_BUCKET_CHARS matches the characters that break out of the request host once concatenated
// raw as `${bucket}.${host}` (S3Destination's vhostBase): "/", "?" and "#" all terminate or restart the
// URL authority when the WHATWG URL parser resolves the concatenated string (a bucket of
// "attacker.example/x" resolves to host "attacker.example", not the configured endpoint), and a literal
// "\" is normalised to "/" by the same parser, so it is an equivalent vector. Deliberately narrower than
// VHOST_SAFE_BUCKET: a DOTTED bucket is a legitimate (if TLS-SNI-risky) explicit-vhost configuration this
// codebase surfaces elsewhere as dottedBucketVhostRisk, not something to reject here.
const VHOST_UNSAFE_BUCKET_CHARS = /[/?#\\]/;

// STORAGE_SERVICE_REMAINDER recognises what is LEFT of an endpoint host after stripping a leading
// "<bucket>." label, when that remainder is itself an object-storage service endpoint: an "s3" label
// (s3.amazonaws.com, s3.ap-southeast-2.amazonaws.com, s3.wasabisys.com), the "s3-<region>" spelling AWS
// still answers on, R2's own host, or GCS's. It is an ALLOW-LIST on purpose. The check below only fires
// when the remainder matches, so a bucket whose name merely happens to be the endpoint's first label
// (bucket "s3" at endpoint "s3.amazonaws.com", whose CORRECT vhost form really is "s3.s3.amazonaws.com")
// is not refused: stripping "s3." there leaves "amazonaws.com", which is not a service endpoint.
const STORAGE_SERVICE_REMAINDER = /^(?:s3[.-]|r2\.cloudflarestorage\.com$|storage\.googleapis\.com$)/i;

/**
 * bucketIsAlreadyLeadingLabel detects the endpoint an operator pastes from their provider's console: the
 * PER-BUCKET URL ("https://mybucket.s3.amazonaws.com") rather than the bare service endpoint
 * ("https://s3.amazonaws.com"). Virtual-hosted addressing then prepends the bucket a SECOND time and the
 * request goes to "mybucket.mybucket.s3.amazonaws.com".
 *
 * Both addressing arms have to refuse it, and the AUTO arm is the one that matters more, which is not the
 * intuitive way round:
 *
 *   - Under EXPLICIT vhost the doubled host does not resolve. The destination probe fails, so nothing is
 *     stored; the operator is simply told the wrong thing (check the bucket, the endpoint, the credentials)
 *     when the fix is one specific edit they could make in seconds.
 *   - Under AUTO the failure is WORSE, and falling back to path-style would not rescue it. Sending
 *     "https://mybucket.s3.amazonaws.com/mybucket/key" path-style is a request AWS ACCEPTS: the host already
 *     selects bucket "mybucket", so the path is read as the KEY, and every archive lands under a "mybucket/"
 *     prefix nobody asked for. A silent write to the wrong key prefix is the one outcome worse than a loud
 *     refusal, so auto refuses too rather than quietly choosing the other style.
 *
 * @param host - the endpoint host (no scheme, no port).
 * @param bucket - the configured bucket name.
 * @returns true when the host already carries this bucket as its leading label AND the remainder is a
 *          recognised object-storage service endpoint.
 */
function bucketIsAlreadyLeadingLabel(host: string, bucket: string): boolean {
  if (bucket === "" || !host.toLowerCase().startsWith(`${bucket.toLowerCase()}.`)) return false;
  return STORAGE_SERVICE_REMAINDER.test(host.slice(bucket.length + 1));
}

// doubledBucketError builds the ONE refusal both arms throw, so the message and the closed cause cannot
// drift between them. It names the mistake and both remedies, because the operator can take either.
function doubledBucketError(host: string, bucket: string): DestBuildError {
  return new DestBuildError(
    "vhost-bucket-doubled",
    `the endpoint host ${JSON.stringify(host)} already starts with the bucket name ${JSON.stringify(bucket)}, so virtual-hosted addressing would send the request to ${JSON.stringify(`${bucket}.${host}`)}. This is usually a provider console's per-bucket URL pasted into the endpoint box. Either use the bare service endpoint (${JSON.stringify(host.slice(bucket.length + 1))}), or keep this endpoint and set the addressing style to path.`,
  );
}

/**
 * resolveAddressing decides whether to use virtual-hosted addressing. An explicit "vhost" is honoured for
 * any bucket EXCEPT one containing a VHOST_UNSAFE_BUCKET_CHARS character, which throws rather than let
 * S3Destination build a host-confused request; an explicit "path" is always honoured. "auto" (the
 * default, also for an absent policy) chooses virtual-hosted for an AWS S3 host with a DNS-safe bucket
 * name (AWS prefers it and path-style to the global endpoint 301-redirects) and path-style everywhere
 * else (R2, B2, Wasabi, MinIO all accept path-style, and a dotted/awkward bucket name is only addressable
 * path-style). So an absent policy is byte-identical to before for every non-AWS endpoint, and only an
 * AWS endpoint with a simple bucket gains the (AWS-correct) vhost form.
 *
 * true means vhost, false means path-style. The unsafe-bucket refusal fires ONLY on the explicit "vhost"
 * arm, because "auto" can only select vhost for a bucket that already passed the stricter DNS-safe
 * pattern. AWS is recognised by the host ending .amazonaws.com, so a CNAME or a private endpoint
 * fronting S3 resolves to path-style under "auto" and needs the explicit setting.
 */
export function resolveAddressing(host: string, bucket: string, addressing: Addressing | undefined): boolean {
  if (addressing === "vhost") {
    // Fail loud HERE, before S3Destination's constructor ever concatenates bucket into vhostBase,
    // mirroring requireHttpsEndpoint's fail-loud-at-construction pattern above: an unsafe bucket must
    // never reach a signed request, let alone one sent to whatever host it redirects to.
    if (VHOST_UNSAFE_BUCKET_CHARS.test(bucket)) {
      throw new DestBuildError("vhost-bucket-unsafe", `bucket ${JSON.stringify(bucket)} cannot use explicit vhost addressing: it contains a character that would break out of the request host`);
    }
    if (bucketIsAlreadyLeadingLabel(host, bucket)) throw doubledBucketError(host, bucket);
    return true;
  }
  if (addressing === "path") return false;
  const autoVhost = host.endsWith(".amazonaws.com") && VHOST_SAFE_BUCKET.test(bucket);
  // Refused rather than silently answered with path-style: see bucketIsAlreadyLeadingLabel's own comment
  // for why the quiet fallback writes every archive under a "<bucket>/" key prefix nobody asked for.
  if (autoVhost && bucketIsAlreadyLeadingLabel(host, bucket)) throw doubledBucketError(host, bucket);
  return autoVhost;
}
