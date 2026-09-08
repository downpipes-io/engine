// AWS STS AssumeRole (T2-A): mint SHORT-LIVED credentials so a destination need not store a long-lived
// IAM access key. The engine holds a principal key whose ONLY permission is sts:AssumeRole on one role,
// and every write happens under temporary credentials (accessKeyId + secretAccessKey + sessionToken) that
// expire on their own. This is strictly better than storing a long-lived write key: a leak of the stored
// principal yields only the bounded ability to assume one role, itself gated by the role's trust policy
// and an optional external id. It does NOT achieve "no long-lived secret at all" (that is OIDC web
// identity, a later step); we do not overclaim.
//
// The call is a SigV4-signed (service "sts") POST to https://sts.<region>.amazonaws.com/, using the same
// signer as the destination writes. Security discipline matches the rest of the dest layer exactly:
//   - region is HOST-BEARING here (unlike everywhere else, where it only enters the signing scope), so it
//     is validated against an allowlist SHAPE and the constructed host is asserted EXACTLY before any
//     credential is signed or sent: a malicious/typo'd region must never be able to point the signed
//     request at an attacker host and exfiltrate the principal credential.
//   - redirect:"manual" + a 3xx-is-an-error guard, so a redirect can never re-send the signed request to
//     a third-party endpoint (V15.3.2), exactly like s3.ts.
//   - a parse failure NEVER echoes the response body: the AssumeRole response carries a LIVE
//     SecretAccessKey and SessionToken in cleartext, so the error is a fixed string with no interpolation.

import { ab, sha256Hex, utf8 } from "../crypto/bytes.ts";
import { classifyStsErrorBody, DestBuildError } from "./build-health.ts";
import { STS_DURATION_MAX, STS_DURATION_MIN } from "./factory-validators.ts";
import { type SigV4Creds, signV4 } from "./sigv4.ts";
import { MAX_DEST_TEXT_BYTES } from "./types.ts";

/** The AssumeRole inputs: the role to assume, an optional external id (the cross-account confused-deputy
 * guard, credential-class), an optional session duration in seconds, and the AWS region (host-bearing). */
export interface AssumeRoleParams {
  roleArn: string;
  externalId?: string;
  durationSeconds?: number;
  region: string;
}

/** The temporary credentials STS returns: a short-lived key pair plus the session token that MUST ride
 * every signed request (x-amz-security-token), and the RFC-3339 expiry. */
export interface TempCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: string;
}

// STS session-duration bounds (AWS: 900s..43200s). Default 3600s; the engine re-mints per slice/invocation
// so even the 900s minimum comfortably outlives one slice (MAX_SLICE_WALL_MS is 120s).
//
// The two bounds are IMPORTED from factory-validators.ts, not restated here, because the submit boundary now
// REFUSES a duration outside them (router-destinations.ts) and a second copy of the window would let the
// refusal and the clamp drift apart -- the exact class of divergence this pair exists to close.
const STS_DURATION_DEFAULT = 3600;

// VALID_STS_REGION is the allowlist SHAPE for an AWS region: two letters, one or more lower-case words,
// and a one or two digit number (us-east-1, ap-southeast-2, us-gov-east-1, cn-northwest-1, il-central-1).
// It deliberately rejects "auto" (the R2 convention, not a real AWS region) and anything carrying a path,
// query, dot or other host metacharacter, so it can never widen the constructed STS host.
const VALID_STS_REGION = /^[a-z]{2}(-[a-z]+)+-\d{1,2}$/;

/**
 * Reports whether a region is a syntactically valid AWS region for STS. The router validates with this
 * BEFORE the value is stored, and assumeRole re-checks as defence in depth, so a host-bearing region is
 * always allowlisted before it is interpolated into the STS host.
 *
 * @param region - the candidate region string.
 * @returns true when the region matches the AWS region shape.
 */
export function isValidStsRegion(region: string): boolean {
  return VALID_STS_REGION.test(region);
}

function clampDuration(d: number | undefined): number {
  if (d === undefined || !Number.isFinite(d)) return STS_DURATION_DEFAULT;
  return Math.max(STS_DURATION_MIN, Math.min(STS_DURATION_MAX, Math.floor(d)));
}

// parseAssumeRoleResponse extracts the temporary credentials from an STS AssumeRole XML response. It NEVER
// interpolates the response body (or any extracted credential value) into an error: the body carries a
// live secret. A missing required field throws a FIXED string, matching the discipline of
// initiateMultipart / parseObjectLockConfig in s3.ts.
// readStsErrorBody reads a FAILED AssumeRole response's (tiny, fixed-shape) XML error document ONCE, bounded,
// so a misconfigured or hostile endpoint cannot exhaust isolate memory on the error path. It is called ONLY on a
// NON-2xx response: a 2xx AssumeRole document carries a LIVE SecretAccessKey and SessionToken, an error document
// does not. The body never leaves this module's error path -- it is consumed only to derive the closed
// StsFailureClass (classifyStsErrorBody, an allow-listed <Code> table). Fail-safe: any hiccup yields "".
async function readStsErrorBody(resp: Response): Promise<string> {
  try {
    const cl = resp.headers.get("content-length");
    if (cl !== null) {
      const advertised = Number(cl);
      if (Number.isFinite(advertised) && advertised > MAX_DEST_TEXT_BYTES) return "";
    }
    const text = await resp.text();
    return text.slice(0, MAX_DEST_TEXT_BYTES);
  } catch {
    return "";
  }
}

function parseAssumeRoleResponse(xml: string): TempCredentials {
  const accessKeyId = /<AccessKeyId>([^<]+)<\/AccessKeyId>/.exec(xml)?.[1];
  const secretAccessKey = /<SecretAccessKey>([^<]+)<\/SecretAccessKey>/.exec(xml)?.[1];
  const sessionToken = /<SessionToken>([^<]+)<\/SessionToken>/.exec(xml)?.[1];
  const expiration = /<Expiration>([^<]+)<\/Expiration>/.exec(xml)?.[1];
  if (!accessKeyId || !secretAccessKey || !sessionToken) {
    // G136: a 200 whose document carried no credentials (a proxy or appliance in the path). Typed with the
    // closed class so the standing destBuildHealth names it; the body is still NEVER echoed (it can carry a
    // live credential), and the message is byte-unchanged.
    throw new DestBuildError("sts-assume-role-failed", "STS AssumeRole: the response could not be parsed (missing temporary credentials)", { stsFailureClass: "response-unparseable" });
  }
  return { accessKeyId, secretAccessKey, sessionToken, expiration: expiration ?? "" };
}

/**
 * Performs an STS AssumeRole, returning temporary credentials. SigV4-signed with the principal key over
 * service "sts". Validates the (host-bearing) region against an allowlist and asserts the constructed host
 * exactly before sending; refuses redirects; never echoes the response body on failure.
 *
 * @param params - the role ARN, optional external id and duration, and the AWS region.
 * @param principal - the long-lived principal credentials authorised to assume the role.
 * @returns the temporary credentials (short-lived key pair + session token + expiry).
 * @throws Error (fixed strings, never echoing a credential) on an invalid region, a non-ok STS status, a
 *   redirect, or an unparseable response.
 */
export async function assumeRole(params: AssumeRoleParams, principal: { accessKeyId: string; secretAccessKey: string }): Promise<TempCredentials> {
  const region = params.region;
  // S-F1: validate the region BEFORE it is ever interpolated into a host.
  if (!isValidStsRegion(region)) {
    // G137: the "auto" region (the R2 convention) under an STS policy. Typed so the standing record names the
    // knob; the message (which interpolates the region the operator set) is unchanged and never recorded.
    throw new DestBuildError("sts-region-invalid", `STS AssumeRole: ${JSON.stringify(region)} is not a valid AWS region (expected e.g. "us-east-1"); set the destination region to the role's region (R2's "auto" is not a valid STS region)`, { varName: "DEST_REGION" });
  }
  const host = `sts.${region}.amazonaws.com`;
  // Defence in depth: parse the URL and assert the host is EXACTLY the intended one and the scheme is
  // https, before any credential is signed or sent (mirrors requireHttpsEndpoint in s3.ts).
  const u = new URL(`https://${host}/`);
  if (u.protocol !== "https:" || u.host !== host) {
    throw new Error("STS AssumeRole: refusing a non-https or unexpected STS host");
  }
  const form = new URLSearchParams();
  form.set("Action", "AssumeRole");
  form.set("Version", "2011-06-15");
  form.set("RoleArn", params.roleArn);
  // RoleSessionName is a FIXED, non-secret, AWS-charset-valid ([\w+=,.@-]{2,64}) string: no run or tenant
  // identifier (NC-2) and nothing attacker-influenced.
  form.set("RoleSessionName", "downpipes");
  form.set("DurationSeconds", String(clampDuration(params.durationSeconds)));
  if (params.externalId !== undefined && params.externalId !== "") form.set("ExternalId", params.externalId);
  const body = utf8(form.toString());
  const amzDate = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const payloadHash = await sha256Hex(body);
  const headers: Record<string, string> = {
    host,
    "content-type": "application/x-www-form-urlencoded",
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payloadHash,
  };
  const creds: SigV4Creds = { accessKeyID: principal.accessKeyId, secretKey: principal.secretAccessKey, region, service: "sts" };
  const auth = await signV4("POST", "/", "", headers, payloadHash, amzDate, creds);
  let resp: Response;
  try {
    resp = await fetch(u, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, Authorization: auth },
      body: ab(body),
      // S-F2: never follow a 3xx and re-send the signed AssumeRole request to a redirect target.
      redirect: "manual",
    });
  } catch (e) {
    // G136: the request never got an answer (DNS, a blocked egress, an intercepting appliance). Recorded as the
    // closed "network" class; the transport message is not run data and is not carried.
    throw new DestBuildError("sts-assume-role-failed", `STS AssumeRole: the request failed before a response (${e instanceof Error ? e.name : "transport"})`, { stsFailureClass: "network" });
  }
  if (resp.status >= 300 && resp.status < 400) throw new Error(`STS AssumeRole: unexpected redirect (status ${resp.status}); the STS endpoint must not redirect a credentialed request`);
  // S-F3: a non-ok response is reported by STATUS ONLY; the body can carry an error document, but never
  // echo it (a 200-with-error or any body could leak a credential on some paths). The message uses the
  // "status NNN" vocabulary so withRetry/isTransient ride out a transient STS 5xx/429.
  if (!resp.ok) {
    // G136: the AssumeRole refusal used to be a BLACK BOX -- the body was deliberately never read (it can carry
    // a credential on other paths), so an AccessDenied on the role's TRUST POLICY, an ExpiredToken PRINCIPAL, a
    // mismatched ExternalId and a DELETED role were all the same "status 403" to support. Read the (already-
    // failed, bounded) ERROR document ONCE and use it ONLY to SELECT a member of the closed STS_FAILURE_CLASSES
    // (an allow-listed <Code> table): the enum is returned, the body is never stored, echoed or logged. The
    // message keeps the "status NNN" vocabulary so withRetry/isTransient ride out a transient STS 5xx/429.
    const cls = classifyStsErrorBody(await readStsErrorBody(resp));
    throw new DestBuildError("sts-assume-role-failed", `STS AssumeRole: status ${resp.status}`, { stsFailureClass: cls });
  }
  const xml = await resp.text();
  return parseAssumeRoleResponse(xml);
}
