// Validate the TypeScript SigV4 against the AWS test-suite get-vanilla vector, the same
// known answer the Go reference pins. Proves the destination writer signs correctly, and that the
// STS session-token (x-amz-security-token) is folded into the signed headers when present.

import { signV4, EMPTY_PAYLOAD_HASH, encodePath, awsUriEncode, type SigV4Creds } from "../src/dest/sigv4.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  const creds: SigV4Creds = { accessKeyID: "AKIDEXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "service" };
  const auth = await signV4("GET", "/", "", { host: "example.amazonaws.com", "x-amz-date": "20150830T123600Z" }, EMPTY_PAYLOAD_HASH, "20150830T123600Z", creds);
  const want = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
  ok("get-vanilla signature", auth === want);

  // STS temporary-credential path: when x-amz-security-token is present it MUST be folded into
  // both the signed canonical headers and the SignedHeaders list, or a token-bearing request would
  // be signed as if it had no session and reject at S3. Sign the same get-vanilla request with the
  // token header added and assert the token is in SignedHeaders and the signature shifts (the token
  // is genuinely bound into the canonical string, not dropped).
  const stsHeaders = { host: "example.amazonaws.com", "x-amz-date": "20150830T123600Z", "x-amz-security-token": "AQoEXAMPLEsessiontoken" };
  const stsAuth = await signV4("GET", "/", "", stsHeaders, EMPTY_PAYLOAD_HASH, "20150830T123600Z", creds);
  ok("session-token is listed in SignedHeaders", stsAuth.includes("SignedHeaders=host;x-amz-date;x-amz-security-token"));
  ok("session-token changes the signature (bound into the canonical headers)", stsAuth !== auth && /Signature=[0-9a-f]{64}$/.test(stsAuth));

  ok("encodePath leaves safe chars", encodePath("run/abc/root.manifest.json") === "run/abc/root.manifest.json");
  ok("encodePath escapes specials", encodePath("a+b/c=d") === "a%2Bb/c%3Dd");

  // Mechanical proof of the underlying collapse mechanism, built directly from awsUriEncode (which
  // leaves '.' unescaped, correctly per the SigV4 spec) rather than encodePath below, as an independent
  // check: it is exactly what a destination's `new URL(io.url(key))` step (dest/s3-read-ops.ts /
  // dest/s3.ts) does to a dotty key before signing. A runId of "../../evil-bucket" builds this key
  // (format/reader.ts's `run/${runID}/root.manifest.json` template) and the WHATWG URL parser's
  // RFC-3986 dot-segment removal pops the "run/" prefix AND the bucket path segment itself off the
  // signed request.
  {
    const rawPathFor = (key: string) => key.split("/").map(awsUriEncode).join("/");
    const key = "run/../../evil-bucket/root.manifest.json";
    const u = new URL(`https://s3.us-east-1.amazonaws.com/customer-backups/${rawPathFor(key)}`);
    ok("dot-segment collapse is real: '..' pops the bucket segment off the signed path", u.pathname === "/evil-bucket/root.manifest.json");
    ok("the collapsed request still targets the same signed host (only the path/bucket moves)", u.host === "s3.us-east-1.amazonaws.com");
  }

  // encodePath refuses to build a path for such a key at all -- it is the single
  // function every S3Destination operation (put/putConditional/get/headStatus/del) funnels a key
  // through (dest/s3.ts's private url()), so this closes the collapse for the whole sink, not just
  // the restore call site.
  {
    let threw = false;
    try {
      encodePath("run/../../evil-bucket/root.manifest.json");
    } catch {
      threw = true;
    }
    ok("encodePath throws on a key with a '..' segment", threw);
  }
  {
    let threw = false;
    try {
      encodePath("./run/x");
    } catch {
      threw = true;
    }
    ok("encodePath throws on a key with a '.' segment", threw);
  }
  // Dotted (not dot-) segments are real keys this format mints (a manifest file name, a write-probe
  // key) and must still pass through untouched: the guard rejects a segment that IS "." or "..", not
  // one that merely contains a period, so neither is a dot-segment the URL parser would collapse.
  ok("encodePath still allows a dotted (not dot-) segment", encodePath("run/abc/root.manifest.json") === "run/abc/root.manifest.json");
  ok("encodePath still allows a leading-dot segment that is not literally '.' or '..'", encodePath("_RECOVERY/.write-probe") === "_RECOVERY/.write-probe");

  console.log(failures === 0 ? "\nSIGV4 VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
