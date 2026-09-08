// Known-answer vectors for the Azure Shared Key signer.
//
// These grade the STRING TO SIGN, character for character, not merely that a signature came out. Two
// signers that differ by one empty line both produce a plausible base64 signature and a 403 that names
// nothing, so a test that only checked "a signature was produced" would pass on a signer that cannot
// authenticate a single request.
//
// The first two vectors are Microsoft's own published worked examples, transcribed with their expected
// string-to-sign inline. They are committed here as this repo's own fixtures rather than read across a
// repo boundary at test time: a fixture that resolves somewhere else is a fixture that can go stale
// without this repo's CI noticing.
//
// The remaining vectors pin the two rules this implementation is most likely to get wrong, each of which
// fails in a way that reads like a permission problem:
//
//   the eleven standard fields are POSITIONAL, so an absent header is an empty LINE and not an omitted one
// a zero Content-Length signs as EMPTY, never as "0" (the rule)
//
// Run: node test/validate-azure-sharedkey.ts

import { AZURE_API_VERSION, signAzureSharedKey } from "../src/dest/azure-sharedkey.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: string): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}${!cond && detail ? `\n         ${detail}` : ""}`);
  if (!cond) failures++;
}

// A syntactically valid base64 key that is NOT a real credential. The string-to-sign vectors do not
// depend on the key at all (they grade the canonical string), and the signature-shape vector below only
// needs the key to decode.
const CREDS = { account: "myaccount", accountKeyBase64: "ZmFrZS1rZXktZm9yLXN0cmluZy10by1zaWduLW9ubHk=" };
const FIXED = (): Date => new Date("2015-06-26T23:39:12Z");

async function microsoftGetContainerMetadata(): Promise<void> {
  console.log("Microsoft's worked example: GET container metadata with three query parameters");
  const signed = await signAzureSharedKey(
    {
      method: "GET",
      path: "/mycontainer",
      query: { restype: "container", comp: "metadata", timeout: "20" },
      headers: { "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": "2015-02-21" },
    },
    CREDS,
    FIXED,
  );
  const want = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20";
  ok("the string to sign matches Microsoft's published example character for character", signed.stringToSign === want, `got:  ${JSON.stringify(signed.stringToSign)}\n         want: ${JSON.stringify(want)}`);
}

async function microsoftListBlobs(): Promise<void> {
  console.log("Microsoft's worked example: list blobs with a multi-value include parameter");
  const signed = await signAzureSharedKey(
    {
      method: "GET",
      path: "/mycontainer",
      query: { restype: "container", comp: "list", include: "metadata,snapshots,uncommittedblobs" },
      headers: { "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": "2015-02-21" },
    },
    CREDS,
    FIXED,
  );
  const want = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\nx-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:list\ninclude:metadata,snapshots,uncommittedblobs\nrestype:container";
  ok("a comma-joined multi-value query parameter is signed as one line, unsplit", signed.stringToSign === want, `got:  ${JSON.stringify(signed.stringToSign)}\n         want: ${JSON.stringify(want)}`);
}

async function positionalFields(): Promise<void> {
  console.log("the eleven standard fields are positional:");
  const signed = await signAzureSharedKey({ method: "HEAD", path: "/c/blob", headers: { "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": AZURE_API_VERSION } }, CREDS, FIXED);
  const head = signed.stringToSign.split("\n").slice(0, 12);
  ok("VERB then exactly eleven standard lines, all empty when no such header is present", head.length === 12 && head[0] === "HEAD" && head.slice(1).every((l) => l === ""), JSON.stringify(head));

  // The one that is easiest to get wrong in the other direction: a header that IS present must land in
  // its own slot rather than being appended anywhere.
  const withType = await signAzureSharedKey(
    { method: "PUT", path: "/c/blob", headers: { "content-type": "application/octet-stream", "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": AZURE_API_VERSION }, contentLength: 7 },
    CREDS,
    FIXED,
  );
  const lines = withType.stringToSign.split("\n");
  ok("Content-Length lands in slot 3", lines[3] === "7", JSON.stringify(lines.slice(0, 7)));
  ok("Content-Type lands in slot 5, two lines below Content-MD5", lines[5] === "application/octet-stream", JSON.stringify(lines.slice(0, 7)));
  // THIS ASSERTION WAS VACUOUS AND A PORT OF THESE VECTORS TO GO FOUND IT. The fixture above supplies no
  // `date` header, so slot 6 is empty whether the signer BLANKS it deliberately or merely finds nothing
  // there. It could not tell those apart, which is the whole of what it claims to grade. The fixture below
  // supplies a real Date header and still requires the slot to be empty, which is the actual rule: x-ms-date
  // carries the timestamp and is signed among the x-ms-* lines, so signing Date as well would mean any skew
  // between the two produced a 403 that nothing explains.
  const withDate = await signAzureSharedKey(
    {
      method: "PUT",
      path: "/c/blob",
      headers: { date: "Sat, 27 Jun 2015 01:02:03 GMT", "content-type": "application/octet-stream", "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": AZURE_API_VERSION },
      contentLength: 7,
    },
    CREDS,
    FIXED,
  );
  const dateLines = withDate.stringToSign.split("\n");
  ok("the Date slot stays EMPTY even when a Date header IS supplied, because x-ms-date carries the timestamp", dateLines[6] === "", JSON.stringify(dateLines.slice(0, 8)));
  ok("CONTROL: that fixture really did carry a Date header, so the assertion above is not vacuous", withDate.headers.date === "Sat, 27 Jun 2015 01:02:03 GMT");
  ok("...and the supplied Date is not smuggled in among the x-ms lines either", !withDate.stringToSign.split("\n").slice(12).some((l) => l.startsWith("date:")));
}

async function zeroLengthIsEmpty(): Promise<void> {
  console.log("a zero Content-Length signs as an empty line, never as \"0\":");
  const signed = await signAzureSharedKey({ method: "GET", path: "/c/blob", headers: { "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": AZURE_API_VERSION }, contentLength: 0 }, CREDS, FIXED);
  const lines = signed.stringToSign.split("\n");
  ok("an explicit zero is the empty string", lines[3] === "");
  const absent = await signAzureSharedKey({ method: "GET", path: "/c/blob", headers: { "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": AZURE_API_VERSION } }, CREDS, FIXED);
  ok("an omitted contentLength is byte-identical to an explicit zero", absent.stringToSign === signed.stringToSign);
  // The positive control: a NON-zero length must still appear, or the assertion above would pass for a
  // signer that dropped the field entirely.
  const seven = await signAzureSharedKey({ method: "PUT", path: "/c/blob", headers: { "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": AZURE_API_VERSION }, contentLength: 7 }, CREDS, FIXED);
  ok("CONTROL: a non-zero length is still written", seven.stringToSign.split("\n")[3] === "7");
}

async function headerSortingAndDefaults(): Promise<void> {
  console.log("x-ms headers are lower-cased, sorted and whitespace-collapsed:");
  const signed = await signAzureSharedKey(
    {
      method: "PUT",
      path: "/c/blob",
      headers: { "X-MS-Meta-Zebra": "z", "x-ms-blob-type": "BlockBlob", "X-Ms-Date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": AZURE_API_VERSION, "content-type": "text/plain" },
    },
    CREDS,
    FIXED,
  );
  const canon = signed.stringToSign.split("\n").slice(12);
  // Ordinal by the lower-cased name: blob-type < date < meta-zebra < version. Written out in full rather
  // than as a sorted() call, because computing the expected order the same way the implementation does
  // would assert only that the code agrees with itself.
  ok(
    "every x-ms header is lower-cased and ordinal-sorted, and a non-x-ms header is not among them",
    canon[0] === "x-ms-blob-type:BlockBlob" && canon[1] === "x-ms-date:Fri, 26 Jun 2015 23:39:12 GMT" && canon[2] === "x-ms-meta-zebra:z" && canon[3] === `x-ms-version:${AZURE_API_VERSION}` && canon[4] === "/myaccount/c/blob",
    JSON.stringify(canon.slice(0, 5)),
  );
  ok("content-type is signed in its positional slot and NOT repeated among the x-ms lines", !canon.some((l) => l.startsWith("content-type")));

  console.log("the module supplies its own date and version when the caller omits them:");
  const bare = await signAzureSharedKey({ method: "GET", path: "/c/blob", headers: {} }, CREDS, FIXED);
  ok("x-ms-date is added", bare.headers["x-ms-date"] === new Date("2015-06-26T23:39:12Z").toUTCString());
  ok("x-ms-version is added and is the version this module signs for", bare.headers["x-ms-version"] === AZURE_API_VERSION);
}

async function authorizationShape(): Promise<void> {
  console.log("the Authorization header:");
  const signed = await signAzureSharedKey({ method: "GET", path: "/c/blob", headers: {} }, CREDS, FIXED);
  ok("is SharedKey <account>:<base64>", /^SharedKey myaccount:[A-Za-z0-9+/]+=*$/.test(signed.authorization), signed.authorization);
  ok("and rides in the returned header set", signed.headers.Authorization === signed.authorization);

  // Two DIFFERENT strings must give two different signatures. Without this, a signer that ignored its
  // input entirely and returned a constant would pass every assertion above.
  const other = await signAzureSharedKey({ method: "PUT", path: "/c/blob", headers: {} }, CREDS, FIXED);
  ok("CONTROL: a different request signs differently", other.authorization !== signed.authorization);

  // And a different KEY must give a different signature, which proves the key is actually decoded and
  // used rather than the string being hashed unkeyed.
  const otherKey = await signAzureSharedKey({ method: "GET", path: "/c/blob", headers: {} }, { account: "myaccount", accountKeyBase64: "YW5vdGhlci1mYWtlLWtleS12YWx1ZS1oZXJlLW9r" }, FIXED);
  ok("CONTROL: a different account key signs differently, so the key is genuinely keying the HMAC", otherKey.authorization !== signed.authorization);
}

// signatureBytesAreKnownAnswer pins the SIGNATURE BYTES. Nothing above did.
//
// WHY IT EXISTS, measured rather than supposed. Appending a single byte to the string to sign, so that
// every signature this engine produces is wrong, passed this file with failures=0. The vectors above grade
// the string to sign character for character against Microsoft's published examples and then hand the
// authorization to a shape regex and two differs-from controls. A consistently corrupted input keeps the
// SharedKey <account>:<base64> shape, still varies by request and still varies by key, so it satisfies
// every one of them.
//
// What that leaves is a signer that is well shaped, request dependent, key dependent and wrong, arriving
// as 403 AuthenticationFailed on every call and reading as a container permissions problem rather than a
// signing fault.
//
// THE ROOT CAUSE IS THE VENDOR'S DOCUMENTATION, not this file's care. AWS publishes complete expected
// Authorization headers with public test credentials, so the sigv4 side inherited a signature-level oracle
// by copying them. Microsoft publishes only the STRING TO SIGN, because the account key in its worked
// examples is secret. Porting Microsoft's material faithfully yields a canonicalisation oracle and nothing
// whatever about the HMAC over it.
//
// THE EXPECTED VALUE WAS COMPUTED INDEPENDENTLY, by a separate HMAC-SHA256 implementation over CREDS and
// the string to sign Microsoft publishes for this request, NOT by calling signAzureSharedKey and recording
// what it returned. A value taken from the code under test pins the current behaviour including its bugs.
// The same value is pinned in the downpipe Go reader at internal/source/azuresharedkey_test.go, so the two
// independent implementations of this signer are now held to one number.
async function signatureBytesAreKnownAnswer(): Promise<void> {
  console.log("the signature bytes, against an independently computed HMAC:");
  const signed = await signAzureSharedKey(
    {
      method: "GET",
      path: "/mycontainer",
      query: { restype: "container", comp: "metadata", timeout: "20" },
      headers: { "x-ms-date": "Fri, 26 Jun 2015 23:39:12 GMT", "x-ms-version": "2015-02-21" },
    },
    CREDS,
    FIXED,
  );
  const wantSignature = "Eyq+9Glv4SxYroGFuBfjFYRVuvcbVQXTxuc+kvQZMdg=";
  const wantAuthorization = `SharedKey myaccount:${wantSignature}`;
  ok(
    "the Authorization matches the independently computed HMAC over Microsoft's published string to sign",
    signed.authorization === wantAuthorization,
    `got:  ${JSON.stringify(signed.authorization)}\n         want: ${JSON.stringify(wantAuthorization)}`,
  );
}

console.log("azure shared key: known-answer vectors\n");
await microsoftGetContainerMetadata();
await microsoftListBlobs();
await positionalFields();
await zeroLengthIsEmpty();
await headerSortingAndDefaults();
await authorizationShape();
await signatureBytesAreKnownAnswer();

console.log(failures === 0 ? "\nall azure shared key checks passed" : `\n${failures} check(s) FAILED`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
