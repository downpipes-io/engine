// Signing-and-addressing vectors for the S3 destination: the STS session
// token (x-amz-security-token) signed and sent on every request, path-style vs virtual-hosted
// addressing and the "auto" default, and the creation-only signed storage-class header.
// Behaviour-preserving: same assertions, same order as the original main().

import { S3Destination } from "../src/dest/s3.ts";
import { signV4 } from "../src/dest/sigv4.ts";
import { utf8 } from "../src/crypto/bytes.ts";
import { validateStorageClass } from "../src/dest/factory.ts";
import {
  ok,
  ENDPOINT,
  BUCKET,
  CREDS,
  FIXED_NOW,
  FIXED_AMZDATE,
  sha256Hex,
  installFetch,
  res,
} from "./validate-s3dest-shared.ts";

// STS temporary credentials: the x-amz-security-token MUST ride EVERY request, in BOTH the signed
// header set (so the signature covers it, or S3 rejects the request) AND on the wire. This covers the
// three distinct header-construction shapes (a write with a real payload hash, a read with
// UNSIGNED-PAYLOAD, a query-string list) plus the no-token byte-identical case.
async function sessionTokenSigning(): Promise<void> {
  console.log("STS session token (x-amz-security-token) is signed and sent on every request:");
  const TOKEN = "FwoGZXIvYXdzEXAMPLEsessiontoken9bQ8K//////////";
  const signedHeadersOf = (auth: string): string[] => (/SignedHeaders=([^,]+)/.exec(auth)?.[1] ?? "").split(";");

  // PUT: a write, signed over the REAL payload hash. Also recompute the signature independently WITH the
  // token in the canonical set, to prove the header is genuinely SIGNED, not merely sent unsigned.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, sessionToken: TOKEN });
      const body = utf8("a sealed segment body");
      await dest.put("seg/0001", body);
      const c = captures[0]!;
      ok("put: the token rides the wire as x-amz-security-token", c.headers["x-amz-security-token"] === TOKEN);
      ok("put: the token is in SignedHeaders (the signature covers it)", signedHeadersOf(c.headers["authorization"] ?? "").includes("x-amz-security-token"));
      const u = new URL(c.url);
      const payloadHash = await sha256Hex(body);
      const expect = await signV4("PUT", u.pathname, "", { host: u.host, "x-amz-date": FIXED_AMZDATE, "x-amz-content-sha256": payloadHash, "x-amz-security-token": TOKEN }, payloadHash, FIXED_AMZDATE, CREDS);
      ok("put: the signature matches an independent recompute that INCLUDES the token", c.headers["authorization"] === expect);
    } finally {
      restore();
    }
  }

  // GET: a read, signed with UNSIGNED-PAYLOAD (a different header shape).
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, sessionToken: TOKEN });
      await dest.get("seg/0001");
      const c = captures[0]!;
      ok("get: the token rides the wire", c.headers["x-amz-security-token"] === TOKEN);
      ok("get: the token is in SignedHeaders", signedHeadersOf(c.headers["authorization"] ?? "").includes("x-amz-security-token"));
    } finally {
      restore();
    }
  }

  // LIST: a query-string GET (the canonical-query shape).
  {
    const { captures, restore } = installFetch(() => res(200));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, sessionToken: TOKEN });
      await dest.list("run/");
      const c = captures[0]!;
      ok("list: the token rides the wire", c.headers["x-amz-security-token"] === TOKEN);
      ok("list: the token is in SignedHeaders", signedHeadersOf(c.headers["authorization"] ?? "").includes("x-amz-security-token"));
    } finally {
      restore();
    }
  }

  // No token (long-lived keys, the default): no header, and it is NOT in SignedHeaders, i.e. byte-identical.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      await dest.put("seg/0002", utf8("x"));
      const c = captures[0]!;
      ok("no token: no x-amz-security-token header is sent", c.headers["x-amz-security-token"] === undefined);
      ok("no token: x-amz-security-token is NOT in SignedHeaders", !signedHeadersOf(c.headers["authorization"] ?? "").includes("x-amz-security-token"));
    } finally {
      restore();
    }
  }
}

// Request addressing: path-style vs virtual-hosted, and the "auto" default. The signed host and
// canonical path are always derived from the URL url() builds, so this proves signing follows addressing,
// INCLUDING the bucket-root list / objectLockStatus calls whose canonical path becomes "/" under vhost.
async function addressingStyles(): Promise<void> {
  console.log("addressing: path-style, virtual-hosted, and the auto default:");
  const AWS = "https://s3.us-east-1.amazonaws.com";
  const R2 = "https://acct.r2.cloudflarestorage.com";
  const mk = (endpoint: string, bucket: string, addressing?: "auto" | "path" | "vhost"): S3Destination =>
    new S3Destination(endpoint, bucket, "us-east-1", CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, ...(addressing ? { addressing } : {}) });

  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk(AWS, "my-bucket", "path").put("seg/0001", utf8("x"));
      ok("path-style: url is host/bucket/key", captures[0]!.url === `${AWS}/my-bucket/seg/0001`);
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const body = utf8("x");
      await mk(AWS, "my-bucket", "vhost").put("seg/0001", body);
      const c = captures[0]!;
      ok("vhost: url is bucket.host/key (no bucket in the path)", c.url === "https://my-bucket.s3.us-east-1.amazonaws.com/seg/0001");
      const u = new URL(c.url);
      const payloadHash = await sha256Hex(body);
      const expect = await signV4("PUT", u.pathname, "", { host: u.host, "x-amz-date": FIXED_AMZDATE, "x-amz-content-sha256": payloadHash }, payloadHash, FIXED_AMZDATE, CREDS);
      ok("vhost: the signature is computed over the bucket.host host (signing follows addressing)", c.headers["authorization"] === expect);
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk(AWS, "simplebucket").put("k", utf8("x"));
      ok("auto: an AWS host + a DNS-safe bucket -> virtual-hosted", captures[0]!.url === "https://simplebucket.s3.us-east-1.amazonaws.com/k");
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk(AWS, "my.dotted.bucket").put("k", utf8("x"));
      ok("auto: an AWS host + a DOTTED bucket -> path-style (vhost + dots breaks TLS SNI)", captures[0]!.url === `${AWS}/my.dotted.bucket/k`);
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk(R2, "archive").put("k", utf8("x"));
      ok("auto: a non-AWS (R2) host stays path-style (byte-identical to before)", captures[0]!.url === `${R2}/archive/k`);
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200));
    try {
      await mk(AWS, "my-bucket", "vhost").list("run/");
      const u = new URL(captures[0]!.url);
      ok("vhost list: the bucket-root request host is bucket.host", u.host === "my-bucket.s3.us-east-1.amazonaws.com");
      ok("vhost list: the canonical path is / (not /bucket/)", u.pathname === "/");
      ok("vhost list: still carries a SigV4 Authorization", (captures[0]!.headers["authorization"] ?? "").startsWith("AWS4-HMAC-SHA256"));
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(404));
    try {
      await mk(AWS, "my-bucket", "vhost").objectLockStatus!();
      const u = new URL(captures[0]!.url);
      ok("vhost objectLockStatus: bucket-root is bucket.host with the ?object-lock subresource and path /", u.host === "my-bucket.s3.us-east-1.amazonaws.com" && u.pathname === "/" && u.search.includes("object-lock"));
    } finally {
      restore();
    }
  }
  {
    // V12.3.1: explicit vhost + a DOTTED bucket must stay honoured (a legitimate, if
    // TLS-SNI-risky, configuration this codebase surfaces elsewhere as dottedBucketVhostRisk in
    // support-sections-config.ts) -- the fix below rejects only a bucket that breaks the request host,
    // never a merely-dotted one.
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk(AWS, "my.dotted.bucket", "vhost").put("k", utf8("x"));
      ok("explicit vhost + a DOTTED bucket is still honoured (not rejected like VHOST_SAFE_BUCKET would)", captures[0]!.url === "https://my.dotted.bucket.s3.us-east-1.amazonaws.com/k");
    } finally {
      restore();
    }
  }
  {
    // An explicit vhost bucket is concatenated RAW into the request host (s3.ts's
    // `${bucket}.${host}`), so a bucket containing "/", "?", "#" or "\" would break out of the intended
    // authority once the result passes through the WHATWG URL parser (e.g. new URL("https://" +
    // "attacker.example/x" + ".s3.amazonaws.com") resolves host "attacker.example", not AWS).
    // Construction must throw before any request is issued, exactly like the https-enforcement check.
    const unsafeBuckets = ["attacker.example/x", "evil.example?x=", "evil.example#x", "evil.example\\x"];
    for (const bucket of unsafeBuckets) {
      const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
      try {
        let threw = false;
        try {
          mk(AWS, bucket, "vhost");
        } catch {
          threw = true;
        }
        ok(`explicit vhost REJECTS a bucket that would break the request host: ${JSON.stringify(bucket)}`, threw);
        ok(`rejecting ${JSON.stringify(bucket)} issued no request (fails loud at construction)`, captures.length === 0);
      } finally {
        restore();
      }
    }
  }
}

// Storage class: x-amz-storage-class is a creation-only, SIGNED header (PUT here, CreateMultipartUpload
// in the multipart test), never on reads. The factory's allow-list rejects the thaw-required archive tiers.
async function storageClassWrites(): Promise<void> {
  console.log("storage class: a signed creation-only header, allow-list excludes the archive tiers:");
  const mk = (sc?: string): S3Destination => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, ...(sc ? { storageClass: sc } : {}) });
  const signedHeadersOf = (auth: string): string[] => (/SignedHeaders=([^,]+)/.exec(auth)?.[1] ?? "").split(";");
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk("STANDARD_IA").put("seg/1", utf8("x"));
      const c = captures[0]!;
      ok("put: x-amz-storage-class rides the wire", c.headers["x-amz-storage-class"] === "STANDARD_IA");
      ok("put: x-amz-storage-class is in SignedHeaders (the signature covers it)", signedHeadersOf(c.headers["authorization"] ?? "").includes("x-amz-storage-class"));
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk("STANDARD_IA").get("seg/1");
      ok("get: NO x-amz-storage-class (a read is not an object creation)", captures[0]!.headers["x-amz-storage-class"] === undefined);
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      await mk().put("seg/1", utf8("x"));
      ok("no storage class: no header (the bucket default, byte-unchanged)", captures[0]!.headers["x-amz-storage-class"] === undefined);
    } finally {
      restore();
    }
  }
  ok("validateStorageClass accepts STANDARD_IA", validateStorageClass("STANDARD_IA") === "STANDARD_IA");
  ok("validateStorageClass accepts INTELLIGENT_TIERING", validateStorageClass("INTELLIGENT_TIERING") === "INTELLIGENT_TIERING");
  ok("validateStorageClass REJECTS GLACIER (needs a thaw, breaks verify-at-seal)", validateStorageClass("GLACIER") === undefined);
  ok("validateStorageClass REJECTS DEEP_ARCHIVE", validateStorageClass("DEEP_ARCHIVE") === undefined);
  ok("validateStorageClass REJECTS GLACIER_IR (kept out of the simple allow-list)", validateStorageClass("GLACIER_IR") === undefined);
  ok("validateStorageClass rejects garbage", validateStorageClass("nonsense") === undefined);
}

export async function run(): Promise<void> {
  await sessionTokenSigning();
  await addressingStyles();
  await storageClassWrites();
}
