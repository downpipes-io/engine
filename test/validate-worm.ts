// Proves the WORM / Object-Lock feature (real, store-enforced immutability) end to end, OFFLINE
// (fetch is stubbed; no network, no deploy):
//
//   1. A WORM-policy PUT carries the correct S3 Object-Lock headers (x-amz-object-lock-mode +
//      x-amz-object-lock-retain-until-date), the mode matches the policy (GOVERNANCE|COMPLIANCE),
//      and the retain-until-date is a correctly-derived RFC-3339 instant (retentionDays from the
//      write clock).
//   2. Those two headers are in the SigV4 SIGNED-headers set (so the signature actually covers them;
//      an unsigned header would be stripped/rejected by the store), verified by recomputing the
//      Authorization independently and by inspecting the SignedHeaders list.
//   3. A NON-WORM PUT is BYTE-UNCHANGED: no object-lock headers at all, and the request is identical
//      to the pre-WORM wire shape.
//   4. The conditional PUT and the multipart INITIATE carry the lock headers under a policy; the
//      individual multipart PARTS do NOT (S3 binds retention at object-create, not per part).
//   5. The capability probe (objectLockStatus / GetObjectLockConfiguration) parses an ENABLED bucket
//      (with and without a default retention rule), a NOT-ENABLED bucket (200 "Disabled" and a 404),
//      and degrades to "unknown" on an unparseable body or a transport fault.
//   6. The config interpreters (parseWormPolicy / validateWormPolicyValue) are FAIL-SAFE: both knobs
//      valid -> armed; a partial/invalid policy -> configured-but-misconfigured (arms nothing); unset
//      -> off. buildDestination arms WORM on the writer ONLY for a valid policy.
//   7. The posture immutability check reports enforced / configured-but-unenforced / not-configured
//      correctly (the real signal, not inferred from delete permission).
//   8. router-posture.ts end to end against a REAL SchedulerDO (the same in-memory double the posture
//      validator uses) plus the destination fetch stub: probeDestination's error classification (a
//      403/401 auth-denied with and without a bucket name, a 301/redirect region hint, and the generic
//      URL-sanitised fall-through) and its delete-refusal "denied" reading; statusSliceForPosture's
//      env projection; gatherWormSlice's console-policy-wins / invalid-console-policy / live-probe /
//      no-destination paths; reportPeriodFromQuery's point-in-time null, default window, garbled
//      fallback and from>to swap; signReportFailOpen's no-signer, signed and throwing-signer paths;
//      and handleReport / buildReportBody across every report kind, the JSON and PDF renders, and the
//      unknown-kind / unknown-framework 404s, including the regression-routing branch of
//      computePostureViaDO.
//
// Run: node test/validate-worm.ts

import { S3Destination } from "../src/dest/s3.ts";
import { signV4, type SigV4Creds } from "../src/dest/sigv4.ts";
import { utf8, b64urlEncode, base64Encode, hexDecode } from "../src/crypto/bytes.ts";
import { s3ErrorCode, s3WriteFailure, EMPTY_BODY_MD5 } from "../src/dest/s3-worm.ts";
import { coarseRunError } from "../src/seal/slice.ts";
import { parseWormPolicy, validateWormPolicyValue, buildDestination, type RuntimeDestConfig } from "../src/dest/factory.ts";
import { computePosture, type PostureInput } from "../src/admin/posture.ts";
import {
  probeDestination,
  statusSliceForPosture,
  gatherWormSlice,
  computePostureViaDO,
  reportPeriodFromQuery,
  signReportFailOpen,
  handleReport,
  buildReportBody,
} from "../src/admin/router-posture.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { encodeCaller, type Caller } from "../src/admin/identity.ts";
import { makeReport, type Report } from "../src/admin/reports.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENDPOINT = "https://s3.example.com";
const BUCKET = "archive-bucket";
const CREDS: SigV4Creds = { accessKeyID: "AKIDEXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "s3" };
// A fixed clock so the amzDate + retain-until + SigV4 signature are all deterministic.
const FIXED_NOW = () => new Date("2026-06-08T12:34:56.000Z");
const FIXED_AMZDATE = "20260608T123456Z";

interface Captured {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Uint8Array;
  redirect: RequestInit["redirect"] | undefined;
}

// installFetch swaps globalThis.fetch for a stub capturing each request and replying with a scripted
// Response (the same shape validate-s3dest.ts uses).
function installFetch(script: (cap: Captured) => Response): { captures: Captured[]; restore: () => void } {
  const captures: Captured[] = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const method = (init?.method ?? "GET").toUpperCase();
    const headers: Record<string, string> = {};
    const h = init?.headers;
    if (h) {
      if (h instanceof Headers) for (const [k, v] of h.entries()) headers[k.toLowerCase()] = v;
      else if (Array.isArray(h)) for (const [k, v] of h) headers[k.toLowerCase()] = v;
      else for (const [k, v] of Object.entries(h)) headers[k.toLowerCase()] = String(v);
    }
    const rawBody = init?.body;
    let body = new Uint8Array(0);
    if (rawBody instanceof ReadableStream) {
      const parts: Uint8Array[] = [];
      const reader = rawBody.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) parts.push(value);
      }
      let n = 0;
      for (const p of parts) n += p.length;
      body = new Uint8Array(n);
      let off = 0;
      for (const p of parts) {
        body.set(p, off);
        off += p.length;
      }
    } else if (rawBody instanceof Uint8Array) {
      // Copy into a fresh ArrayBuffer-backed array: init.body is a BodyInit so its bytes may be
      // ArrayBufferLike (SharedArrayBuffer-backed), which is not assignable to Uint8Array<ArrayBuffer>.
      body = new Uint8Array(rawBody);
    } else if (rawBody instanceof ArrayBuffer) {
      body = new Uint8Array(rawBody.slice(0));
    } else if (ArrayBuffer.isView(rawBody)) {
      const v = rawBody as ArrayBufferView;
      const copy = new Uint8Array(v.byteLength);
      copy.set(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
      body = copy;
    } else if (typeof rawBody === "string") {
      body = utf8(rawBody);
    }
    captures.push({ method, url, headers, body, redirect: init?.redirect });
    return script(captures[captures.length - 1]!);
  }) as typeof fetch;
  return { captures, restore: () => { globalThis.fetch = real; } };
}

function res(status: number, headers?: Record<string, string>, bodyText?: string): Response {
  const hasBody = bodyText !== undefined;
  // Spread headers only when present: ResponseInit.headers is optional and exactOptionalPropertyTypes
  // rejects an explicit undefined.
  return new Response(hasBody ? bodyText : status === 204 || status === 404 || status === 412 ? null : "", { status, ...(headers !== undefined ? { headers } : {}) });
}

const GOV_30 = { mode: "governance" as const, retentionDays: 30 };
const COMP_7 = { mode: "compliance" as const, retentionDays: 7 };
// 5 minutes: tolerance for real-clock skew between buildDestination and the assertion.
const RETAIN_UNTIL_TOLERANCE_MS = 5 * 60 * 1000;

// The independently-expected retain-until for the fixed clock + a window of N days: floored to whole
// seconds and formatted without milliseconds, exactly as the destination derives it.
function expectRetainUntil(days: number): string {
  const ms = FIXED_NOW().getTime() + days * 24 * 60 * 60 * 1000;
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

// ---- 1+2: a WORM PUT carries the correct, SIGNED object-lock headers; retain-until is correct ------
async function wormPutHeaders(): Promise<void> {
  console.log("WORM PUT: object-lock headers, correct mode + retain-until, in the SIGNED set:");
  const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
  try {
    const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, worm: GOV_30 });
    const key = "seg/0001";
    const body = utf8("a sealed segment body");
    await dest.put(key, body);
    ok("one request issued", captures.length === 1);
    const c = captures[0]!;
    ok("PUT carries x-amz-object-lock-mode", c.headers["x-amz-object-lock-mode"] === "GOVERNANCE");
    ok("governance mode is the UPPER-CASE S3 token", c.headers["x-amz-object-lock-mode"] === "GOVERNANCE");
    const retain = c.headers["x-amz-object-lock-retain-until-date"];
    ok("PUT carries x-amz-object-lock-retain-until-date", typeof retain === "string" && retain.length > 0);
    ok("retain-until is the correctly-derived RFC-3339 instant (30 days from the write clock)", retain === expectRetainUntil(30));
    ok("retain-until is RFC-3339 UTC with no milliseconds", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(retain ?? ""));

    // AWS S3 REQUIRES a Content-MD5 or x-amz-checksum-* header on any Object-Lock PutObject; the
    // engine sends x-amz-checksum-sha256 = standard-base64(SHA-256(body)). Without this every WORM seal to
    // AWS failed with InvalidRequest. Assert the header is present and is the correct standard-base64 digest.
    const payloadHash = await sha256Hex(body);
    const expectChecksum = base64Encode(hexDecode(payloadHash));
    ok("WORM PUT carries x-amz-checksum-sha256", c.headers["x-amz-checksum-sha256"] === expectChecksum);
    ok("the checksum is STANDARD base64 (padded, +/ alphabet), the form S3 requires", /^[A-Za-z0-9+/]+={0,2}$/.test(c.headers["x-amz-checksum-sha256"] ?? ""));

    // The crux: the headers must be in the SignedHeaders set AND the recomputed signature must match,
    // proving the body hash + the lock headers + the checksum are all covered by the SAME signature.
    const auth = c.headers["authorization"] ?? "";
    const signedHeadersList = /SignedHeaders=([^,]+)/.exec(auth)?.[1] ?? "";
    ok("SignedHeaders includes x-amz-object-lock-mode", signedHeadersList.split(";").includes("x-amz-object-lock-mode"));
    ok("SignedHeaders includes x-amz-object-lock-retain-until-date", signedHeadersList.split(";").includes("x-amz-object-lock-retain-until-date"));
    ok("SignedHeaders includes x-amz-checksum-sha256 (the checksum is signed, not strippable)", signedHeadersList.split(";").includes("x-amz-checksum-sha256"));
    const u = new URL(c.url);
    const expectAuth = await signV4(
      "PUT",
      u.pathname,
      "",
      { host: u.host, "x-amz-date": FIXED_AMZDATE, "x-amz-content-sha256": payloadHash, "x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": expectRetainUntil(30), "x-amz-checksum-sha256": expectChecksum },
      payloadHash,
      FIXED_AMZDATE,
      CREDS,
    );
    ok("Authorization matches a signature recomputed WITH the lock + checksum headers (all signed, not stripped)", auth === expectAuth);
  } finally {
    restore();
  }

  // Compliance mode emits the COMPLIANCE token + its own window.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, worm: COMP_7 });
      await dest.put("seg/0002", utf8("x"));
      const c = captures[0]!;
      ok("compliance mode emits the COMPLIANCE token", c.headers["x-amz-object-lock-mode"] === "COMPLIANCE");
      ok("compliance retain-until uses the policy's 7-day window", c.headers["x-amz-object-lock-retain-until-date"] === expectRetainUntil(7));
    } finally {
      restore();
    }
  }
}

async function sha256Hex(b: Uint8Array): Promise<string> {
  const { hexEncode } = await import("../src/crypto/bytes.ts");
  // Copy into a fresh ArrayBuffer-backed view so the argument satisfies BufferSource (a plain Uint8Array
  // may be ArrayBufferLike-backed under TS6's stricter typed-array generics).
  const src = new Uint8Array(b);
  return hexEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", src)));
}

// ---- 3: a NON-WORM PUT is byte-unchanged (no object-lock headers) ---------------------------------
async function nonWormPutUnchanged(): Promise<void> {
  console.log("non-WORM PUT is byte-unchanged (no object-lock headers):");
  const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
  try {
    // No worm arg => the default OFF path.
    const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
    const key = "seg/plain";
    const body = utf8("a sealed segment body");
    await dest.put(key, body);
    const c = captures[0]!;
    ok("no x-amz-object-lock-mode on a non-WORM PUT", !("x-amz-object-lock-mode" in c.headers));
    ok("no x-amz-object-lock-retain-until-date on a non-WORM PUT", !("x-amz-object-lock-retain-until-date" in c.headers));
    // The signature must equal the pre-WORM shape (host + x-amz-date + x-amz-content-sha256 only).
    const u = new URL(c.url);
    const payloadHash = await sha256Hex(body);
    const expectAuth = await signV4("PUT", u.pathname, "", { host: u.host, "x-amz-date": FIXED_AMZDATE, "x-amz-content-sha256": payloadHash }, payloadHash, FIXED_AMZDATE, CREDS);
    ok("non-WORM Authorization is the unchanged pre-WORM signature", c.headers["authorization"] === expectAuth);
    const signed = /SignedHeaders=([^,]+)/.exec(c.headers["authorization"] ?? "")?.[1] ?? "";
    ok("non-WORM SignedHeaders has NO object-lock header", !signed.includes("object-lock"));
  } finally {
    restore();
  }
}

// ---- 4: conditional PUT + multipart initiate carry the lock headers; PARTS do not -----------------
async function conditionalAndMultipart(): Promise<void> {
  console.log("conditional PUT + multipart initiate carry lock headers; parts do not:");
  // Conditional create under a policy: the RUNLOG-style write is locked too.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"rl"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, worm: GOV_30 });
      await dest.putConditional("_RECOVERY/RUNLOG", utf8("v1"), { ifNoneMatch: "*" });
      const c = captures[0]!;
      ok("conditional PUT carries the object-lock mode under a policy", c.headers["x-amz-object-lock-mode"] === "GOVERNANCE");
      ok("conditional PUT carries the retain-until under a policy", c.headers["x-amz-object-lock-retain-until-date"] === expectRetainUntil(30));
      ok("conditional PUT still carries its If-None-Match", c.headers["if-none-match"] === "*");
    } finally {
      restore();
    }
  }
  // A non-WORM conditional PUT stays byte-unchanged.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"rl"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      await dest.putConditional("_RECOVERY/RUNLOG", utf8("v1"), { ifNoneMatch: "*" });
      ok("non-WORM conditional PUT carries NO object-lock header", !("x-amz-object-lock-mode" in captures[0]!.headers));
    } finally {
      restore();
    }
  }
  // Multipart: initiate carries the lock headers; each part does NOT; complete does not. We drive a
  // small multipart by declaring a streamed size whose sealed bound exceeds the threshold so the
  // multipart path is taken, with two parts.
  {
    // Script the multipart conversation: POST ?uploads (initiate) -> 200 with UploadId; PUT part ->
    // 200 with ETag; POST ?uploadId (complete) -> 200.
    const xmlInit = `<?xml version="1.0"?><InitiateMultipartUploadResult><UploadId>UP1</UploadId></InitiateMultipartUploadResult>`;
    const { captures, restore } = installFetch((cap) => {
      if (cap.method === "POST" && cap.url.includes("uploads")) return res(200, undefined, xmlInit);
      if (cap.method === "PUT") return res(200, { etag: '"part"' });
      if (cap.method === "POST") return res(200, undefined, `<CompleteMultipartUploadResult></CompleteMultipartUploadResult>`);
      return res(200);
    });
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, worm: GOV_30 });
      // Build a stream of ~40 MiB declared so the sealed bound exceeds the 32 MiB multipart threshold,
      // producing an initiate + parts + complete. The bytes are arbitrary; only the request shapes matter.
      const chunk = new Uint8Array(8 * 1024 * 1024); // 8 MiB chunks
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          for (let i = 0; i < 5; i++) controller.enqueue(chunk); // 40 MiB
          controller.close();
        },
      });
      await dest.putStream("seg/big", stream, 40 * 1024 * 1024);
      const initiate = captures.find((c) => c.method === "POST" && c.url.includes("uploads"));
      const parts = captures.filter((c) => c.method === "PUT");
      const complete = captures.find((c) => c.method === "POST" && !c.url.includes("uploads"));
      ok("multipart initiate was issued", initiate !== undefined);
      ok("multipart initiate carries the object-lock mode", initiate?.headers["x-amz-object-lock-mode"] === "GOVERNANCE");
      ok("multipart initiate carries the retain-until", initiate?.headers["x-amz-object-lock-retain-until-date"] === expectRetainUntil(30));
      ok("at least one multipart PART was uploaded", parts.length >= 1);
      ok("multipart PARTS carry NO object-lock header (retention binds at create, not per part)", parts.every((p) => !("x-amz-object-lock-mode" in p.headers)));
      ok("multipart COMPLETE carries NO object-lock header", complete !== undefined && !("x-amz-object-lock-mode" in complete.headers));
    } finally {
      restore();
    }
  }
}

// ---- the S3 Object-Lock checksum requirement + the real-<Code> error surfacing ---------------------
// AWS S3 MANDATES a Content-MD5 or x-amz-checksum-* header on any PutObject (and CreateMultipartUpload)
// carrying Object-Lock parameters; the engine omitted it, so EVERY WORM seal to AWS failed with a generic
// "destination access error" that hid the real InvalidRequest. These nine assertions pin the fix offline:
// the checksum header is present + correct + signed under WORM (and absent without it), the empty-body
// Content-MD5 rides the multipart initiate under a policy (not the parts), and the failure path now surfaces
// the REAL, sanitised S3 <Code> end to end (through put + coarseRunError) instead of the generic class.
async function wormChecksumAndErrors(): Promise<void> {
  console.log("Object-Lock checksum header + real-<Code> error surfacing:");

  // 1. A WORM PUT carries x-amz-checksum-sha256 = standard-base64(SHA-256(body)).
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, worm: GOV_30 });
      const body = utf8("a sealed segment body");
      await dest.put("seg/ck", body);
      const expect = base64Encode(hexDecode(await sha256Hex(body)));
      ok("WORM PUT carries x-amz-checksum-sha256 = standard-base64(SHA-256(body))", captures[0]!.headers["x-amz-checksum-sha256"] === expect);
    } finally {
      restore();
    }
  }

  // 2. A non-WORM PUT carries NO checksum header (byte-unchanged on R2 and any non-WORM write).
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      await dest.put("seg/plain", utf8("x"));
      ok("non-WORM PUT carries NO x-amz-checksum-sha256 (byte-unchanged)", !("x-amz-checksum-sha256" in captures[0]!.headers));
    } finally {
      restore();
    }
  }

  // 3. A WORM conditional PUT carries the checksum header AND it is in the SignedHeaders set.
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"rl"' }));
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, worm: GOV_30 });
      const body = utf8("runlog v1");
      await dest.putConditional("_RECOVERY/RUNLOG", body, { ifNoneMatch: "*" });
      const c = captures[0]!;
      const expect = base64Encode(hexDecode(await sha256Hex(body)));
      const signed = /SignedHeaders=([^,]+)/.exec(c.headers["authorization"] ?? "")?.[1] ?? "";
      ok("WORM conditional PUT carries the checksum header and it is SIGNED", c.headers["x-amz-checksum-sha256"] === expect && signed.split(";").includes("x-amz-checksum-sha256"));
    } finally {
      restore();
    }
  }

  // 4. s3WriteFailure surfaces the REAL S3 <Code> for a denied write.
  {
    const e = s3WriteFailure("PUT", "seg/0001", 403, "<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
    ok("s3WriteFailure surfaces the real <Code> (AccessDenied) and keeps the status", e.message === "PUT seg/0001: status 403 (AccessDenied)");
  }

  // 5. s3WriteFailure names the Object-Lock checksum cause when AWS reports it.
  {
    const body = "<Error><Code>InvalidRequest</Code><Message>Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests with Object Lock parameters</Message></Error>";
    const e = s3WriteFailure("PUT", "seg/0001", 400, body);
    ok("s3WriteFailure appends the object-lock checksum hint on the InvalidRequest body", e.message === "PUT seg/0001: status 400 (InvalidRequest: object lock write requires a checksum)");
  }

  // 6. A body with no parseable <Code> falls back to the bare "status N" (the classifiers still fire).
  {
    const e = s3WriteFailure("conditional PUT", "k", 500, "not xml");
    ok("s3WriteFailure with no <Code> is the bare 'status N' (classifier-compatible)", e.message === "conditional PUT k: status 500");
    ok("s3ErrorCode returns undefined for a body with no <Code>", s3ErrorCode("not xml") === undefined);
  }

  // 7. coarseRunError round-trips the real code instead of collapsing to the generic class.
  {
    ok("coarseRunError surfaces the real S3 code (403 AccessDenied -> named)", coarseRunError("PUT seg/0001: status 403 (AccessDenied)") === "destination rejected the write (AccessDenied)");
  }

  // 8. coarseRunError still maps a plain "status N" (no code) to the generic availability class.
  {
    ok("coarseRunError still maps a plain 'status 400' to the generic destination access class", coarseRunError("PUT seg/x: status 400") === "destination access error");
  }

  // 9. The multipart INITIATE under an Object-Lock policy carries the empty-body Content-MD5; PARTS do not.
  {
    const xmlInit = `<?xml version="1.0"?><InitiateMultipartUploadResult><UploadId>UP1</UploadId></InitiateMultipartUploadResult>`;
    const { captures, restore } = installFetch((cap) => {
      if (cap.method === "POST" && cap.url.includes("uploads")) return res(200, undefined, xmlInit);
      if (cap.method === "PUT") return res(200, { etag: '"part"' });
      if (cap.method === "POST") return res(200, undefined, `<CompleteMultipartUploadResult></CompleteMultipartUploadResult>`);
      return res(200);
    });
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW, worm: GOV_30 });
      const chunk = new Uint8Array(8 * 1024 * 1024);
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          for (let i = 0; i < 5; i++) controller.enqueue(chunk);
          controller.close();
        },
      });
      await dest.putStream("seg/biglock", stream, 40 * 1024 * 1024);
      const initiate = captures.find((c) => c.method === "POST" && c.url.includes("uploads"));
      const parts = captures.filter((c) => c.method === "PUT");
      const signed = /SignedHeaders=([^,]+)/.exec(initiate?.headers["authorization"] ?? "")?.[1] ?? "";
      ok("multipart initiate under Object-Lock carries the empty-body Content-MD5, signed", initiate?.headers["content-md5"] === EMPTY_BODY_MD5 && signed.split(";").includes("content-md5"));
      ok("multipart PARTS carry NO Content-MD5 (the checksum binds at create, not per part)", parts.length >= 1 && parts.every((p) => !("content-md5" in p.headers)));
    } finally {
      restore();
    }
  }

  // A non-WORM multipart initiate carries NO Content-MD5 (byte-unchanged).
  {
    const xmlInit = `<?xml version="1.0"?><InitiateMultipartUploadResult><UploadId>UP2</UploadId></InitiateMultipartUploadResult>`;
    const { captures, restore } = installFetch((cap) => {
      if (cap.method === "POST" && cap.url.includes("uploads")) return res(200, undefined, xmlInit);
      if (cap.method === "PUT") return res(200, { etag: '"part"' });
      if (cap.method === "POST") return res(200, undefined, `<CompleteMultipartUploadResult></CompleteMultipartUploadResult>`);
      return res(200);
    });
    try {
      const dest = new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });
      const chunk = new Uint8Array(8 * 1024 * 1024);
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          for (let i = 0; i < 5; i++) controller.enqueue(chunk);
          controller.close();
        },
      });
      await dest.putStream("seg/bigplain", stream, 40 * 1024 * 1024);
      const initiate = captures.find((c) => c.method === "POST" && c.url.includes("uploads"));
      ok("non-WORM multipart initiate carries NO Content-MD5 (byte-unchanged)", initiate !== undefined && !("content-md5" in initiate.headers));
    } finally {
      restore();
    }
  }
}

// ---- 5: the capability probe parses enabled / not-enabled / unknown -------------------------------
async function capabilityProbe(): Promise<void> {
  console.log("capability probe (GetObjectLockConfiguration) distinguishes enforcing vs not:");
  const make = () => new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: FIXED_NOW });

  // ENABLED with a default retention rule -> enabled:true + defaultMode/defaultDays.
  {
    const xml = `<?xml version="1.0"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>` +
      `<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>`;
    const { captures, restore } = installFetch(() => res(200, undefined, xml));
    try {
      const st = await make().objectLockStatus!();
      ok("probe: an ENABLED bucket reports enabled:true", st.enabled === true);
      ok("probe: the default retention mode is surfaced", st.defaultMode === "compliance");
      ok("probe: the default retention days are surfaced", st.defaultDays === 30);
      ok("probe: the request used the ?object-lock subresource", captures[0]!.url.includes("object-lock"));
      ok("probe: the request was a signed GET", captures[0]!.method === "GET" && (captures[0]!.headers["authorization"] ?? "").startsWith("AWS4-HMAC-SHA256"));
      ok("probe: the request was issued with redirect:manual", captures[0]!.redirect === "manual");
    } finally {
      restore();
    }
  }
  // ENABLED with NO default rule -> enabled:true, no defaultMode/defaultDays.
  {
    const xml = `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`;
    const { restore } = installFetch(() => res(200, undefined, xml));
    try {
      const st = await make().objectLockStatus!();
      ok("probe: ENABLED with no default rule is enabled:true, no default mode/days", st.enabled === true && st.defaultMode === undefined && st.defaultDays === undefined);
    } finally {
      restore();
    }
  }
  // Years default rule normalises to days (x365).
  {
    const xml = `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>` +
      `<Rule><DefaultRetention><Mode>GOVERNANCE</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>`;
    const { restore } = installFetch(() => res(200, undefined, xml));
    try {
      const st = await make().objectLockStatus!();
      ok("probe: a Years default rule normalises to days (2y -> 730d)", st.enabled === true && st.defaultDays === 730 && st.defaultMode === "governance");
    } finally {
      restore();
    }
  }
  // NOT enabled: a 200 body that does not say Enabled -> enabled:false (honest, not an error).
  {
    const xml = `<ObjectLockConfiguration><ObjectLockEnabled>Disabled</ObjectLockEnabled></ObjectLockConfiguration>`;
    const { restore } = installFetch(() => res(200, undefined, xml));
    try {
      const st = await make().objectLockStatus!();
      ok("probe: a 200 that does not say Enabled is enabled:false (not an error)", st.enabled === false);
    } finally {
      restore();
    }
  }
  // 404 (ObjectLockConfigurationNotFoundError) -> enabled:false (the bucket has no lock config).
  {
    const { restore } = installFetch(() => res(404, undefined, `<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>`));
    try {
      const st = await make().objectLockStatus!();
      ok("probe: a 404 (no lock configuration) is the honest enabled:false", st.enabled === false);
    } finally {
      restore();
    }
  }
  // Unparseable body on a 200 -> unknown (cannot confirm; never silently treated as enabled).
  {
    const { restore } = installFetch(() => res(200, undefined, `not xml at all`));
    try {
      const st = await make().objectLockStatus!();
      ok("probe: an unparseable 200 body is 'unknown' (never silently 'enabled')", st.enabled === "unknown");
    } finally {
      restore();
    }
  }
  // A 500 -> unknown.
  {
    const { restore } = installFetch(() => res(500));
    try {
      const st = await make().objectLockStatus!();
      ok("probe: a 500 degrades to 'unknown' (cannot confirm)", st.enabled === "unknown");
    } finally {
      restore();
    }
  }
  // A transport fault (fetch throws) -> unknown, never throws out of the probe.
  {
    const real = globalThis.fetch;
    globalThis.fetch = (async () => { throw new Error("network down"); }) as typeof fetch;
    try {
      const st = await make().objectLockStatus!();
      ok("probe: a transport fault degrades to 'unknown' and does NOT throw", st.enabled === "unknown");
    } finally {
      globalThis.fetch = real;
    }
  }
}

// ---- 6: config interpreters are fail-safe; buildDestination arms only a valid policy --------------
async function configFailSafe(): Promise<void> {
  console.log("config interpreters are fail-safe (parseWormPolicy / validateWormPolicyValue):");
  const env = (o: Record<string, string | undefined>): Env => o as unknown as Env;

  // Unset both -> OFF (configured:false).
  {
    const p = parseWormPolicy(env({}));
    ok("parse: neither knob set -> configured:false (off, unchanged behaviour)", p.configured === false);
  }
  // Both set + valid -> armed policy.
  {
    const p = parseWormPolicy(env({ DEST_WORM_MODE: "compliance", DEST_WORM_RETENTION_DAYS: "30" }));
    ok("parse: both valid -> configured + not misconfigured + the policy", p.configured === true && p.misconfigured === false && p.configured === true && (p.misconfigured === false ? p.policy.mode === "compliance" && p.policy.retentionDays === 30 : false));
  }
  // Mode set, days missing -> configured but misconfigured (a partial policy never silently arms nothing).
  {
    const p = parseWormPolicy(env({ DEST_WORM_MODE: "governance" }));
    ok("parse: mode set, days missing -> configured + misconfigured (fail-safe warning)", p.configured === true && p.misconfigured === true);
  }
  // Days set, mode missing -> configured but misconfigured.
  {
    const p = parseWormPolicy(env({ DEST_WORM_RETENTION_DAYS: "30" }));
    ok("parse: days set, mode missing -> configured + misconfigured", p.configured === true && p.misconfigured === true);
  }
  // Invalid mode -> misconfigured.
  {
    const p = parseWormPolicy(env({ DEST_WORM_MODE: "lenient", DEST_WORM_RETENTION_DAYS: "30" }));
    ok("parse: an unknown mode -> configured + misconfigured", p.configured === true && p.misconfigured === true);
  }
  // Non-positive / non-integer days -> misconfigured. Bind and narrow on `configured` first (as the cases
  // above do): WormPolicyParse is a union discriminated on `configured`, and `misconfigured` only exists on
  // the configured:true arms. Each input here sets DEST_WORM_MODE, so `configured` is always true.
  {
    const zero = parseWormPolicy(env({ DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "0" }));
    ok("parse: zero days -> misconfigured", zero.configured === true && zero.misconfigured === true);
    const neg = parseWormPolicy(env({ DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "-5" }));
    ok("parse: negative days -> misconfigured", neg.configured === true && neg.misconfigured === true);
    const frac = parseWormPolicy(env({ DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "1.5" }));
    ok("parse: fractional days -> misconfigured", frac.configured === true && frac.misconfigured === true);
    const nonNum = parseWormPolicy(env({ DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "soon" }));
    ok("parse: non-numeric days -> misconfigured", nonNum.configured === true && nonNum.misconfigured === true);
  }
  // Case-insensitive mode is accepted.
  {
    const p = parseWormPolicy(env({ DEST_WORM_MODE: "COMPLIANCE", DEST_WORM_RETENTION_DAYS: "10" }));
    ok("parse: mode is case-insensitive (COMPLIANCE)", p.configured === true && p.misconfigured === false);
  }

  // validateWormPolicyValue (the stored/console-set value gate).
  ok("validate: a valid stored policy passes", JSON.stringify(validateWormPolicyValue({ mode: "governance", retentionDays: 14 })) === JSON.stringify({ mode: "governance", retentionDays: 14 }));
  ok("validate: a bad mode is rejected (null)", validateWormPolicyValue({ mode: "nope", retentionDays: 14 }) === null);
  ok("validate: non-positive days rejected (null)", validateWormPolicyValue({ mode: "governance", retentionDays: 0 }) === null);
  ok("validate: a non-object is rejected (null)", validateWormPolicyValue("governance") === null);
  ok("validate: null is rejected (null)", validateWormPolicyValue(null) === null);

  // buildDestination arms WORM on the writer ONLY for a valid policy (proved by the headers on the wire).
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      const e = env({ DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK", DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "30" });
      const dest = await buildDestination(e);
      await dest.put("seg/x", utf8("y"));
      ok("buildDestination(valid env policy) arms WORM (the PUT carries the lock mode)", captures[0]!.headers["x-amz-object-lock-mode"] === "GOVERNANCE");
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      // A MISCONFIGURED env policy (mode without days) must arm NOTHING: a backup still writes, but with
      // no object-lock headers (never claims protection it is not applying).
      const e = env({ DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK", DEST_WORM_MODE: "governance" });
      const dest = await buildDestination(e);
      await dest.put("seg/x", utf8("y"));
      ok("buildDestination(misconfigured env policy) arms NOTHING (no lock header; the write still happens)", !("x-amz-object-lock-mode" in captures[0]!.headers));
    } finally {
      restore();
    }
  }
  {
    const { captures, restore } = installFetch(() => res(200, { etag: '"e"' }));
    try {
      // A console-set override policy WINS over env. Here the override carries a compliance/7 policy.
      // buildDestination does not inject a clock (it uses the real one), so we assert the MODE wins and
      // the retain-until is present and lands ~7 days out (not the env's 30), rather than an exact instant.
      const e = env({ DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "30" });
      const dest = await buildDestination(e, undefined, { endpoint: ENDPOINT, bucket: BUCKET, region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK", worm: { mode: "compliance", retentionDays: 7 } });
      await dest.put("seg/x", utf8("y"));
      const retainMs = Date.parse(captures[0]!.headers["x-amz-object-lock-retain-until-date"] ?? "");
      const sevenDaysOut = Date.now() + 7 * 24 * 60 * 60 * 1000;
      ok(
        "buildDestination: a console-set WORM policy WINS over env (compliance mode, ~7-day window not env's 30)",
        captures[0]!.headers["x-amz-object-lock-mode"] === "COMPLIANCE" && Number.isFinite(retainMs) && Math.abs(retainMs - sevenDaysOut) < RETAIN_UNTIL_TOLERANCE_MS,
      );
    } finally {
      restore();
    }
  }
}

// POSTURE_BASE is the healthy posture input with only the WORM slice left to vary. It sits at module
// scope because TWO groups need it: the pure check states in group 7 below, and group 13's provider
// assertions, which run a REAL gatherWormSlice output straight through computePosture to prove the field
// it plumbs actually changes the sentence an operator reads.
const POSTURE_BASE: PostureInput = {
  status: { destConfigured: true, breakGlassConfigured: true, operationalConfigured: { public: true, private: false }, tokenFallbackDisabled: true, adminTokenPresent: false, bootstrapConsumed: true, breakGlassTokenRetired: false, recoveryBreakGlassReady: true },
  downpipes: [],
  expiry: [],
  notifyFailureRuleSet: true,
  ownerCount: 2,
  operationalPrivatePresent: false,
  beaconEnabled: false,
  overrides: new Map(),
  // No pin recorded in this fixture. Stated rather than omitted: PostureInput makes this REQUIRED
  // and nullable so a caller cannot silently default a tamper signal to "no drift".
  recipientPinDrift: null,
};
const POSTURE_NOW = Date.UTC(2026, 5, 8);

// ---- 7: the posture immutability check reports the three states correctly --------------------------
function postureStates(): void {
  console.log("posture immutability check reports enforced / configured-but-unenforced / not-configured:");
  const base = POSTURE_BASE;
  const NOW = POSTURE_NOW;
  const find = (i: PostureInput) => computePosture(i, NOW).checks.find((c) => c.id === "immutability");

  // not configured -> pass (informational).
  ok("posture: not configured -> immutability passes (informational)", find({ ...base, worm: { configured: false, misconfigured: false, bucketEnforces: false } })?.status === "pass");
  // configured + enforced -> pass.
  ok("posture: configured + bucket enforces -> immutability passes", find({ ...base, worm: { configured: true, misconfigured: false, mode: "compliance", retentionDays: 30, bucketEnforces: true } })?.status === "pass");
  // configured + NOT enforced -> fail (warning).
  const unenf = find({ ...base, worm: { configured: true, misconfigured: false, mode: "governance", retentionDays: 14, bucketEnforces: false } });
  ok("posture: configured but bucket does not enforce -> immutability FAILS", unenf?.status === "fail");
  ok("posture: the configured-but-unenforced finding is medium", unenf?.severity === "medium");
  // configured + unknown -> fail (cannot confirm).
  ok("posture: configured but probe unknown -> immutability FAILS (cannot confirm)", find({ ...base, worm: { configured: true, misconfigured: false, mode: "governance", retentionDays: 14, bucketEnforces: "unknown" } })?.status === "fail");
  // absent slice -> pass (not configured).
  ok("posture: an absent worm slice -> immutability passes (not configured)", find({ ...base })?.status === "pass");
}

// ---- 8: probeDestination maps the LIVE object-lock verdict (enforced / not-enforced / unknown) ------
// The store-time write probe also reads the bucket's Object-Lock capability and returns it as objectLock.
// This is the value the console keys its immutability badge on, NEVER the stored policy alone, so the
// three verdicts must come straight from the live objectLockStatus read and a probe fault must degrade to
// "unknown" (cannot-confirm), never a false "enforced". The write/delete result decides ok independently.
async function probeObjectLock(): Promise<void> {
  const override = { endpoint: ENDPOINT, bucket: BUCKET, region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "secret" };
  const ENV = {} as Env;
  // A scripted store: HEAD (exists, 404 first-run is fine), PUT (write probe ok), DELETE (cleanup ok),
  // and a GET on the ?object-lock subresource whose response decides the verdict.
  const drive = async (lockResponse: () => Response): Promise<"enforced" | "not-enforced" | "unknown" | "err"> => {
    const fx = installFetch((cap) => {
      const u = new URL(cap.url);
      if (cap.method === "HEAD") return res(404);
      if (cap.method === "PUT") return res(200);
      if (cap.method === "DELETE") return res(204);
      if (cap.method === "GET" && u.search.includes("object-lock")) return lockResponse();
      return res(500);
    });
    try {
      const p = await probeDestination(ENV, override);
      return p.ok ? p.objectLock : "err";
    } finally {
      fx.restore();
    }
  };
  ok(
    "probeDestination: bucket reports Enabled -> objectLock 'enforced'",
    (await drive(() => res(200, {}, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"))) === "enforced",
  );
  ok("probeDestination: bucket has no lock config (404) -> objectLock 'not-enforced'", (await drive(() => res(404))) === "not-enforced");
  ok("probeDestination: probe fault (500) -> objectLock 'unknown' (cannot confirm, never a false enforced)", (await drive(() => res(500))) === "unknown");

  // The NO-OVERRIDE path: with no submitted config, probeDestination targets the DEPLOY-TIME env
  // destination. The bucket name for the auth-denied reason then comes from env.DEST_BUCKET (the override?.
  // bucket left side is nullish), and buildDestination is invoked with a null override. A clean
  // HEAD/PUT/DELETE plus an Enabled object-lock answer proves ok:true against the env destination and a
  // surfaced 'enforced' verdict, exercising both the env-bucket fallback and the null-override build arm.
  {
    const envDest = {
      DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1",
      DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK",
    } as unknown as Env;
    const fx = installFetch((cap) => {
      const u = new URL(cap.url);
      if (cap.method === "HEAD") return res(404);
      if (cap.method === "PUT") return res(200);
      if (cap.method === "DELETE") return res(204);
      if (cap.method === "GET" && u.search.includes("object-lock")) return res(200, undefined, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>");
      return res(500);
    });
    try {
      const p = await probeDestination(envDest);
      ok("probeDestination: with no override it probes the env destination and succeeds (ok:true)", p.ok === true);
      ok("probeDestination: the env-destination probe surfaces the live 'enforced' verdict", p.ok === true && !!p.ok && p.objectLock === "enforced");
    } finally {
      fx.restore();
    }
  }

  // AN AZURE SAS CARRIES ITS OWN DEATH, AND THE POSTURE NOW CARRIES THE READING. Wired,
  // and the reason it needed wiring is the assertion worth keeping: AzureBlobDestination.sasExpiry() had
  // existed with three tests and a doc comment naming "a surface that warns before the day comes", and a
  // sweep of src/ found ZERO production callers. The reading was parsed, proven and dropped.
  //
  // Driven through the OVERRIDE, not through env: the env knobs carry DEST_KIND, which is the legacy
  // two-value r2-or-s3 switch and refuses "azure" outright, so a stored destination config is the only
  // route by which an Azure endpoint reaches this probe at all.
  {
    const override = {
      endpoint: "https://acct.blob.core.windows.net",
      bucket: "container",
      region: "auto",
      accessKeyId: "acct",
      secretAccessKey: "sv=2022-11-02&se=2027-01-01T00%3A00%3A00Z&sig=abc123",
    };
    const fx = installFetch((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(201) : cap.method === "DELETE" ? res(202) : res(200)));
    try {
      const p = await probeDestination({} as Env, override);
      ok(
        "probeDestination: an Azure SAS destination reports its credential expiry in the posture",
        p.ok === true && !!p.ok && p.credentialExpiry?.kind === "sas" && p.credentialExpiry.expiresAtMs === Date.parse("2027-01-01T00:00:00Z"),
      );
    } finally {
      fx.restore();
    }
  }

  // THE THIRD CASE, and the one a mutation arm proved was unasserted until now. A SAS carrying no `se`
  // parameter is LEGAL: a service SAS can take its expiry from a stored access policy on the container.
  // Its reading is "expiry not visible to us", which must reach the posture as expiresAtMs null INSIDE a
  // present field, never as an absent field. Absent means "no self-expiring credential here"; null means
  // "there is one and we cannot see its date, so a human has to go and look". Collapsing the second into
  // the first silently converts a destination that needs attention into one that needs none, which is the
  // exact confusion AzureBlobDestination.sasExpiry()'s own header warns a caller not to make.
  {
    const override = {
      endpoint: "https://acct.blob.core.windows.net",
      bucket: "container",
      region: "auto",
      accessKeyId: "acct",
      secretAccessKey: "sv=2022-11-02&sr=c&sig=abc123",
    };
    const fx = installFetch((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(201) : cap.method === "DELETE" ? res(202) : res(200)));
    try {
      const p = await probeDestination({} as Env, override);
      ok(
        "probeDestination: a SAS with no se reports a PRESENT field with a null instant, not an absent one",
        p.ok === true && !!p.ok && p.credentialExpiry?.kind === "sas" && p.credentialExpiry.expiresAtMs === null,
      );
    } finally {
      fx.restore();
    }
  }

  // THE CONTROL, without which the assertion above is satisfied by a field that is always populated. An S3
  // destination has no self-expiring credential, so the posture must carry NO reading at all. Absent and
  // "a SAS whose expiry we cannot see" are different facts, and only one of them means no warning is owed.
  {
    const envDest = {
      DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1",
      DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK",
    } as unknown as Env;
    const fx = installFetch((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(200) : res(204)));
    try {
      const p = await probeDestination(envDest);
      ok("CONTROL: an S3 destination carries no credentialExpiry, because its key dies only when rotated", p.ok === true && !!p.ok && p.credentialExpiry === undefined);
    } finally {
      fx.restore();
    }
  }

  // The env-bucket name reaches the auth-denied reason when there is no override. A 403 on the env
  // destination's write -> the actionable reason names env.DEST_BUCKET (proving the override?.bucket ??
  // env.DEST_BUCKET fallback supplied the bucket clause from env, not from a submitted override).
  {
    const envDest = {
      DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1",
      DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK",
    } as unknown as Env;
    const fx = installFetch((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(403) : res(204)));
    try {
      const p = await probeDestination(envDest);
      ok("probeDestination: a 403 on the env destination names env.DEST_BUCKET in the reason", p.ok === false && !p.ok && p.reason.includes(`"${BUCKET}"`) && p.reason.includes("HTTP 403"));
    } finally {
      fx.restore();
    }
  }
}

// ---- 9: probeDestination error classification + delete-refusal reading -----------------------------
// The store-time probe turns the raw transport failure into an ACTIONABLE operator message: an auth
// denial names the bucket and the likely scoped-token cause; a redirect points at the region; everything
// else falls through to a length-bounded, URL-sanitised reason (an endpoint never leaks). A delete
// refusal on an otherwise-good write is the honest "denied" reading (an object-locked bucket), never a
// probe failure. None of these is reachable from the live-verdict tests above, which all succeed.
async function probeErrorClassification(): Promise<void> {
  console.log("probeDestination classifies the probe failure into an actionable reason:");
  const ENV = {} as Env;
  const override: RuntimeDestConfig = { endpoint: ENDPOINT, bucket: BUCKET, region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "secret" };

  // Run the probe against a store scripted by method, returning the result for assertions. The probe
  // does HEAD (exists) then PUT (write probe) then DELETE (cleanup), so a per-method script can fail any
  // one leg.
  type ProbeResult = Awaited<ReturnType<typeof probeDestination>>;
  const runProbe = async (script: (cap: Captured) => Response, env: Env = ENV, ov: RuntimeDestConfig | undefined = override): Promise<ProbeResult> => {
    const fx = installFetch(script);
    try {
      return await probeDestination(env, ov);
    } finally {
      fx.restore();
    }
  };

  // A 403 on the credentialed write -> ok:false with the bucket NAMED and the scoped-token guidance.
  {
    const r = await runProbe((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(403) : res(204)));
    ok("probe: a 403 on the write -> ok:false", r.ok === false);
    ok("probe: the 403 reason names the bucket (actionable, operator's own bucket)", !r.ok && r.reason.includes(`"${BUCKET}"`));
    ok("probe: the 403 reason carries the HTTP code", !r.ok && r.reason.includes("HTTP 403"));
    ok("probe: the 403 reason explains the scoped-token cause, not the credential value", !r.ok && /not authorised here/.test(r.reason));
  }

  // A 401 takes the same auth-denied branch (the status group covers 401 and 403).
  {
    const r = await runProbe((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(401) : res(204)));
    ok("probe: a 401 also takes the auth-denied branch (HTTP 401 named)", r.ok === false && !r.ok && r.reason.includes("HTTP 401"));
  }

  // A 403 with NO bucket known (the override carries no bucket and the env has none) -> the auth-denied
  // reason still fires but omits the bucket clause (the empty `where`).
  {
    const noBucket: RuntimeDestConfig = { endpoint: ENDPOINT, bucket: "", region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "secret" };
    const r = await runProbe((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(403) : res(204)), ENV, noBucket);
    ok("probe: a 403 with no bucket known still denies, with no bucket clause", r.ok === false && !r.ok && r.reason.includes("HTTP 403") && !r.reason.includes(' to bucket "'));
  }

  // A 301 (or the dest layer's "unexpected redirect") -> the region-mismatch hint, not the auth branch.
  {
    const r = await runProbe((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(301) : res(204)));
    ok("probe: a redirect -> ok:false with the region hint", r.ok === false && !r.ok && /region is wrong for this bucket/.test(r.reason));
    ok("probe: the redirect reason does NOT mention authorisation (it took the region branch)", !r.ok && !/not authorised here/.test(r.reason));
  }

  // A generic non-auth, non-redirect failure (a 500) -> the URL-sanitised, length-bounded fall-through.
  // The endpoint URL must be replaced by <endpoint> and the reason capped at 200 chars.
  {
    const r = await runProbe((cap) => (cap.method === "HEAD" ? res(404) : cap.method === "PUT" ? res(500) : res(204)));
    ok("probe: a 500 falls through to the generic reason (ok:false)", r.ok === false);
    ok("probe: the generic reason is length-bounded to 200 chars", !r.ok && r.reason.length <= 200);
    ok("probe: the generic reason carries no raw endpoint URL (sanitised)", !r.ok && !/https?:\/\//.test(r.reason));
  }

  // The write succeeds but the DELETE is refused -> ok:true with deleteProbe "denied" (an object-locked
  // archive bucket is a deliberate hardening, not a probe failure). objectLock stays "unknown" here (no
  // objectLockStatus answer scripted), proving deleteProbe is independent of the lock verdict.
  {
    const r = await runProbe((cap) => {
      const u = new URL(cap.url);
      if (cap.method === "HEAD") return res(404);
      if (cap.method === "PUT") return res(200);
      if (cap.method === "DELETE") return res(403); // the bucket refuses the delete
      if (cap.method === "GET" && u.search.includes("object-lock")) return res(500); // probe cannot confirm
      return res(500);
    });
    ok("probe: a refused DELETE is ok:true with deleteProbe 'denied' (object-locked bucket, not a failure)", r.ok === true && !!r.ok && r.deleteProbe === "denied");
    ok("probe: deleteProbe 'denied' still reads objectLock independently (here 'unknown')", r.ok === true && !!r.ok && r.objectLock === "unknown");
  }

  // No override AND an env with no DEST_BUCKET: the bucket resolution exhausts both sides (override?.bucket
  // is nullish, then env.DEST_BUCKET is absent), so the bucket stays undefined. buildDestination then
  // throws on the empty env (no destination configured), which the probe catches and sanitises into the
  // generic, length-bounded, URL-free reason. The result proves probeDestination degrades to ok:false with
  // a safe reason even when there is nothing to probe, rather than throwing out of the store-time check.
  {
    const r = await probeDestination({} as Env);
    ok("probe: no override and no env destination -> ok:false (the unconfigured fall-through)", r.ok === false);
    ok("probe: the unconfigured reason is length-bounded and carries no endpoint URL", r.ok === false && !r.ok && r.reason.length <= 200 && !/https?:\/\//.test(r.reason));
  }
}

// ---- 10: statusSliceForPosture projects exactly the four env-derived presence fields ----------------
// computePosture runs in the DO, which holds no env, so the router projects the env presence slice for it.
// The projection must narrow buildStatus to the fields posture reads and carry only booleans (no secret),
// so the posture and the onboarding status agree on what "configured" means.
function statusSliceProjection(): void {
  console.log("statusSliceForPosture projects the env presence booleans the DO cannot read:");
  const env = (o: Record<string, string | undefined>): Env => o as unknown as Env;

  // A fully-configured S3 destination + break-glass recipient + admin token -> every presence flag true.
  const configured = statusSliceForPosture(
    env({ DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK", BREAK_GLASS_PUBLIC: "bg", ADMIN_TOKEN: "tok", OPERATIONAL_PUBLIC: "op", DISABLE_TOKEN_FALLBACK: "true" }),
  );
  ok("slice: a configured destination -> destConfigured true", configured.destConfigured === true);
  ok("slice: a break-glass recipient -> breakGlassConfigured true", configured.breakGlassConfigured === true);
  ok("slice: an admin token present -> adminTokenPresent true", configured.adminTokenPresent === true);
  ok("slice: an operational public recipient -> operationalConfigured.public true", configured.operationalConfigured.public === true);

  // An empty env -> every flag false (the safe not-configured reading), and the slice carries ONLY
  // booleans (no secret material crosses to the DO).
  const empty = statusSliceForPosture(env({}));
  ok("slice: an empty env -> destConfigured false", empty.destConfigured === false);
  ok("slice: an empty env -> breakGlassConfigured false", empty.breakGlassConfigured === false);
  ok("slice: an empty env -> adminTokenPresent false", empty.adminTokenPresent === false);
  ok(
    "slice: every projected field is a boolean (no secret crosses)",
    typeof empty.destConfigured === "boolean" &&
      typeof empty.breakGlassConfigured === "boolean" &&
      typeof empty.tokenFallbackDisabled === "boolean" &&
      typeof empty.adminTokenPresent === "boolean" &&
      typeof empty.operationalConfigured.public === "boolean" &&
      typeof empty.operationalConfigured.private === "boolean",
  );
}

// ---- 11: reportPeriodFromQuery derives the window from ?from=&to= or the default ---------------------
// The point-in-time kinds (posture, immutability) ignore the period (null); the time-bounded kinds take
// ?from=&to= (epoch seconds), defaulting to the last 90 days, and a garbled value falls back to the
// default window rather than 400ing a read. A from after a to is swapped so the order is always sane.
function reportPeriod(): void {
  console.log("reportPeriodFromQuery derives the report window (point-in-time null / default / swap):");
  const NOW_MS = Date.parse("2026-06-09T00:00:00.000Z");
  const nowSec = Math.floor(NOW_MS / 1000);
  const NINETY = 90 * 24 * 60 * 60;
  const q = (s: string): URLSearchParams => new URLSearchParams(s);

  // The point-in-time kinds ignore the period entirely.
  ok("period: posture is point-in-time -> null", reportPeriodFromQuery("posture", q("from=1&to=2"), NOW_MS) === null);
  ok("period: immutability is point-in-time -> null", reportPeriodFromQuery("immutability", q(""), NOW_MS) === null);

  // No from/to on a time-bounded kind -> the last 90 days ending now.
  const def = reportPeriodFromQuery("restore-tests", q(""), NOW_MS);
  ok("period: no from/to -> the default 90-day window ending now", def !== null && def.toSeconds === nowSec && def.fromSeconds === nowSec - NINETY);

  // Explicit from + to are honoured (epoch seconds).
  const explicit = reportPeriodFromQuery("sla-compliance", q("from=1700000000&to=1700100000"), NOW_MS);
  ok("period: explicit from/to are honoured", explicit !== null && explicit.fromSeconds === 1700000000 && explicit.toSeconds === 1700100000);

  // A to only -> from defaults to to minus the 90-day window.
  const toOnly = reportPeriodFromQuery("restore-tests", q("to=1700100000"), NOW_MS);
  ok("period: to only -> from is to minus the default window", toOnly !== null && toOnly.toSeconds === 1700100000 && toOnly.fromSeconds === 1700100000 - NINETY);

  // A garbled (non-numeric) from -> treated as absent, so it falls back to the default window from `to`.
  const garbled = reportPeriodFromQuery("restore-tests", q("from=soon&to=1700100000"), NOW_MS);
  ok("period: a garbled from falls back to the default window (never 400s the read)", garbled !== null && garbled.fromSeconds === 1700100000 - NINETY);

  // A negative from -> rejected (treated as absent), again the default window.
  const negative = reportPeriodFromQuery("restore-tests", q("from=-5&to=1700100000"), NOW_MS);
  ok("period: a negative from is rejected (parsed as absent)", negative !== null && negative.fromSeconds === 1700100000 - NINETY);

  // from AFTER to -> the two are swapped so fromSeconds <= toSeconds always holds.
  const swapped = reportPeriodFromQuery("sla-compliance", q("from=1700100000&to=1700000000"), NOW_MS);
  ok("period: from after to is swapped (fromSeconds <= toSeconds)", swapped !== null && swapped.fromSeconds === 1700000000 && swapped.toSeconds === 1700100000);

  // A fractional from is floored to whole seconds.
  const frac = reportPeriodFromQuery("restore-tests", q("from=1700000000.9&to=1700100000"), NOW_MS);
  ok("period: a fractional from is floored to whole seconds", frac !== null && frac.fromSeconds === 1700000000);
}

// A 64-byte SIGNER_PRIVATE (ed25519 seed(32) || ML-DSA-87 seed(32)), the value loadSigner expects.
function signerPrivate(): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));
}

// ---- 12: signReportFailOpen signs when it can, never 500s a read otherwise --------------------------
// A report read must never fail on a missing/broken signer: the unsigned report is still valuable and the
// console surfaces the signature-verified state honestly. With a valid signer the report comes back signed;
// with no signer or a signer that throws, the original (unsigned) report is returned unchanged.
async function signFailOpen(): Promise<void> {
  console.log("signReportFailOpen signs with a signer, else returns the unsigned report (never throws):");
  const report: Report = makeReport("posture", { checks: [] }, null, Date.parse("2026-06-09T00:00:00.000Z"));

  // No signer configured -> the unchanged, unsigned report (the SAME object, no signature added).
  {
    const out = await signReportFailOpen({} as Env, report);
    ok("sign: no signer configured -> the unsigned report is returned unchanged", out === report && !("signature" in out));
  }

  // A valid signer -> a signed report (a signature is attached, the kind/data preserved).
  {
    const signed = await signReportFailOpen({ SIGNER_PRIVATE: signerPrivate() } as Env, report);
    ok("sign: a valid signer attaches a signature", typeof (signed as Report & { signature?: unknown }).signature === "string");
    ok("sign: the signed report preserves the kind", signed.kind === "posture");
  }

  // A signer present but UNLOADABLE (a too-short SIGNER_PRIVATE makes loadSigner throw) -> fail-open to
  // the unsigned report rather than 500ing the read.
  {
    const out = await signReportFailOpen({ SIGNER_PRIVATE: b64urlEncode(new Uint8Array(8)) } as Env, report);
    ok("sign: an unloadable signer fails open to the unsigned report (no throw, no signature)", out === report && !("signature" in out));
  }
}

import { MockStorage } from "./mock-storage.ts";

function makeScheduler(): SchedulerDO {
  const storage = new MockStorage();
  const state = { storage } as unknown as DurableObjectState;
  return new SchedulerDO(state);
}

// stubFor wraps a real SchedulerDO as a DurableObjectStub the way the runtime presents one. The router
// helpers call scheduler.fetch(urlString, init) (the platform's RequestInfo + RequestInit overload, which
// the Workers runtime turns into a Request before it reaches the DO), but SchedulerDO.fetch takes a single
// Request. So the bare DO cast to a stub would receive the URL string as its req and break on req.json().
// This wrapper normalises a (url, init) call into a Request and forwards a Request through unchanged, the
// same coercion the live binding performs, so the same one path under test runs offline.
function stubFor(do_: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> =>
      do_.fetch(input instanceof Request ? input : new Request(input, init)),
  } as unknown as DurableObjectStub;
}

const OWNER_ACCESS: Caller = { method: "access", email: "o@example.au", subject: "subject-o@example.au", role: "owner", groups: [] };
const TOKEN_CALLER: Caller = { method: "token", email: null, subject: null, role: "owner", groups: [] };

// seedDestConfig stores a console-set destination on the DO so fetchDestConfig (and thus gatherWormSlice)
// resolves an override. POST /dest-config is a gated OWNER-EXCLUSIVE op: the DO re-resolves the role from
// its OWN tables (it never trusts the forwarded role), and a fresh DO has no role mapping, so an Access
// caller would resolve to viewer and be refused. The bare-token break-glass is the legitimate Owner
// authority here (roleForCaller maps method:"token" to owner), so the seed uses TOKEN_CALLER, the same
// internal owner-authority the engine itself forwards. The route body is { config }, and with no dual
// control configured it commits immediately (200), not a pending approval (202). The status is asserted so
// a silent seed refusal can never leave the downstream console-policy assertions reading a stale override.
async function seedDestConfig(do_: SchedulerDO, config: Record<string, unknown>): Promise<void> {
  const url = "https://scheduler.internal/dest-config";
  const resp = await do_.fetch(
    new Request(url, {
      method: "POST",
      headers: { "content-type": "application/json", "x-downpipe-caller": encodeCaller(TOKEN_CALLER) },
      body: JSON.stringify({ config }),
    }),
  );
  ok("seed: POST /dest-config committed the console destination (200, owner-authorised)", resp.status === 200);
}

// ---- 13: gatherWormSlice combines env config, a console policy, and the live probe -----------------
// The WORM observable state the DO cannot read: the env policy OR a console-set per-destination policy
// (console wins), plus a live objectLockStatus probe of the default destination. Every fault degrades to
// the safe reading (no probe verdict, never a false enforced), and a console policy is re-validated so a
// malformed stored value reads configured-but-misconfigured rather than arming nothing silently.
async function gatherWorm(): Promise<void> {
  console.log("gatherWormSlice merges env/console WORM config with the live capability probe:");

  // Env policy only (no console destination stored). The probe builds a destination from the env config;
  // script the object-lock GET to report Enabled with a default rule so the probe verdict surfaces.
  {
    const do_ = makeScheduler();
    const lockXml = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>" +
      "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule></ObjectLockConfiguration>";
    const fx = installFetch((cap) => (cap.method === "GET" && cap.url.includes("object-lock") ? res(200, undefined, lockXml) : res(200, { etag: '"e"' })));
    try {
      const env = {
        DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK",
        DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "14",
      } as unknown as Env;
      const slice = await gatherWormSlice(env, stubFor(do_));
      ok("worm: a valid env policy -> configured, not misconfigured", slice !== undefined && slice.configured === true && slice.misconfigured === false);
      ok("worm: the env policy mode/days are surfaced", slice?.mode === "governance" && slice?.retentionDays === 14);
      ok("worm: the live probe verdict (bucket Enabled) is carried through", slice?.bucketEnforces === true);
      ok("worm: the probe's default mode/days are surfaced", slice?.probeMode === "compliance" && slice?.probeDays === 30);
      // The RETENTION axis. A lock-enabled bucket retains nothing by itself, so the slice carries whether
      // this one actually has a DEFAULT RETENTION RULE, which is what the signed immutability report's
      // strongest sentence rests on when no valid policy is armed (reports.ts). Here the rule is present.
      ok("worm: a lock-enabled bucket WITH a default retention rule reports defaultRetention true", slice?.defaultRetention === true);
      // THE PROVIDER AXIS. The slice has to name WHICH STORE this is, because the four
      // supported providers have four different immutability mechanisms and the check's remedy is chosen
      // from it. Without this field the branch in posture-checks.ts silently falls back to the S3 sentence
      // for every destination, which is the defect it was built to close, and nothing else would notice.
      ok("worm: the slice names the STORE behind the default destination (an s3 endpoint -> s3)", slice?.provider === "s3");
    } finally {
      fx.restore();
    }
  }

  // The R2 arm, and it is the one that matters: R2 is the single provider with NO remedy, so the slice
  // naming it is what stops the immutability check offering "re-create the bucket with Object-Lock
  // enabled" about a bucket that can never have one. Measured: R2's S3 endpoint answers a
  // lock-bearing PUT 501 NotImplemented.
  {
    const do_ = makeScheduler();
    const fx = installFetch((cap) => (cap.method === "GET" && cap.url.includes("object-lock") ? res(404) : res(200, { etag: '"e"' })));
    try {
      const env = {
        DEST_KIND: "s3", DEST_ENDPOINT: "https://acct.r2.cloudflarestorage.com", DEST_BUCKET: BUCKET, DEST_REGION: "auto", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK",
        DEST_WORM_MODE: "compliance", DEST_WORM_RETENTION_DAYS: "30",
      } as unknown as Env;
      const slice = await gatherWormSlice(env, stubFor(do_));
      ok("worm: an R2 S3 endpoint is named as r2, not as a generic s3 store", slice?.provider === "r2");
      // End to end through the check, because the field is only worth carrying if the sentence changes.
      const remedy = computePosture({ ...POSTURE_BASE, ...(slice !== undefined ? { worm: slice } : {}) }, POSTURE_NOW).checks.find((c) => c.id === "immutability")?.remediation ?? "";
      ok("worm: ...so the immutability remedy is R2's own (no bucket to re-create, no S3-endpoint escape)", /501 NotImplemented/.test(remedy) && !/Object-Lock ENABLED/.test(remedy));
    } finally {
      fx.restore();
    }
  }

  // A CONSOLE-SET destination decides the provider from ITS endpoint, not from env, matching the same
  // precedence the factory and the status report apply.
  {
    const do_ = makeScheduler();
    await seedDestConfig(do_, { endpoint: "https://storage.googleapis.com", bucket: BUCKET, region: "auto", accessKeyId: "AK", secretAccessKey: "SK" });
    const fx = installFetch((cap) => (cap.method === "GET" && cap.url.includes("object-lock") ? res(404) : res(200, { etag: '"e"' })));
    try {
      const env = { DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK" } as unknown as Env;
      const slice = await gatherWormSlice(env, stubFor(do_));
      ok("worm: a console-set destination's own endpoint decides the provider (gcs, not the env's s3)", slice?.provider === "gcs");
    } finally {
      fx.restore();
    }
  }

  // Object-Lock ENABLED with NO <Rule> at all: the bucket has lock switched on and retains nothing on its
  // own. This is the state the report used to answer with "a compromised delete-credential cannot
  // hard-delete an archive within its retention window", and it is only distinguishable here.
  {
    const do_ = makeScheduler();
    const lockXml = "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
    const fx = installFetch((cap) => (cap.method === "GET" && cap.url.includes("object-lock") ? res(200, undefined, lockXml) : res(200, { etag: '"e"' })));
    try {
      const env = {
        DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK",
      } as unknown as Env;
      const slice = await gatherWormSlice(env, stubFor(do_));
      ok("worm: a lock-enabled bucket with NO default rule still reports the bucket as enforcing", slice?.bucketEnforces === true);
      ok("worm: a lock-enabled bucket with NO default rule reports defaultRetention false", slice?.defaultRetention === false);
      ok("worm: with no default rule the probe mode/days stay absent", slice?.probeMode === undefined && slice?.probeDays === undefined);
    } finally {
      fx.restore();
    }
  }

  // A bucket that does NOT enforce (404) leaves defaultRetention honestly ABSENT rather than false: there
  // is no default rule to have, and cannot-confirm on the retention axis must never be written as a false.
  {
    const do_ = makeScheduler();
    const fx = installFetch((cap) => (cap.method === "GET" && cap.url.includes("object-lock") ? res(404) : res(200, { etag: '"e"' })));
    try {
      const env = {
        DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK",
      } as unknown as Env;
      const slice = await gatherWormSlice(env, stubFor(do_));
      ok("worm: a NOT-enforcing bucket leaves defaultRetention absent, never false", slice?.bucketEnforces === false && slice?.defaultRetention === undefined);
    } finally {
      fx.restore();
    }
  }

  // A console-set per-destination WORM policy WINS over env, and is re-validated. A VALID console policy.
  {
    const do_ = makeScheduler();
    await seedDestConfig(do_, { endpoint: ENDPOINT, bucket: BUCKET, region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK", worm: { mode: "compliance", retentionDays: 7 } });
    const fx = installFetch((cap) => (cap.method === "GET" && cap.url.includes("object-lock") ? res(404) : res(200, { etag: '"e"' })));
    try {
      // The env says governance/30; the console policy (compliance/7) must win.
      const env = { DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "30" } as unknown as Env;
      const slice = await gatherWormSlice(env, stubFor(do_));
      ok("worm: a console-set policy wins over env (compliance/7, not governance/30)", slice?.configured === true && slice?.misconfigured === false && slice?.mode === "compliance" && slice?.retentionDays === 7);
      ok("worm: a 404 lock config -> bucketEnforces false (the bucket has no Object-Lock)", slice?.bucketEnforces === false);
    } finally {
      fx.restore();
    }
  }

  // An INVALID stored console policy (a positive-days but bad mode) is DROPPED at the fetchDestConfig
  // boundary: validateWormPolicyValue returns null for an unknown mode, so the resolved override carries NO
  // worm field at all. gatherWormSlice therefore never sees a console policy and falls back to the ENV
  // policy. Here the env carries a VALID governance/21 policy, so the slice reads exactly that env policy
  // (the stripped console value contributes nothing), which is the real fail-safe: a malformed stored
  // policy never claims protection, and it never masks a valid env policy either. This is why the inline
  // re-validation else-arm in gatherWormSlice (override.worm present but invalid) is unreachable through the
  // real fetchDestConfig path: the factory has already stripped any invalid stored policy before it returns.
  {
    const do_ = makeScheduler();
    await seedDestConfig(do_, { endpoint: ENDPOINT, bucket: BUCKET, region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK", worm: { mode: "lenient", retentionDays: 7 } });
    const fx = installFetch((cap) => (cap.method === "GET" && cap.url.includes("object-lock") ? res(404) : res(200, { etag: '"e"' })));
    try {
      const env = { DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "21" } as unknown as Env;
      const slice = await gatherWormSlice(env, stubFor(do_));
      ok("worm: an invalid stored console policy is dropped, so the env policy stands (configured, not misconfigured)", slice?.configured === true && slice?.misconfigured === false);
      ok("worm: with the console policy stripped, the env governance/21 mode/days are surfaced", slice?.mode === "governance" && slice?.retentionDays === 21);
    } finally {
      fx.restore();
    }
  }

  // No destination at all (no env, no console config) -> the env policy is off and the probe is skipped
  // (buildDestination throws on no config, which is caught), so bucketEnforces is left ABSENT and the
  // slice reads not-configured. The function still returns the honest env-shape, never undefined here.
  {
    const do_ = makeScheduler();
    const env = {} as unknown as Env;
    const slice = await gatherWormSlice(env, stubFor(do_));
    ok("worm: no destination -> not configured, probe skipped (bucketEnforces absent)", slice !== undefined && slice.configured === false && slice.bucketEnforces === undefined);
    // Honestly absent, never guessed: with nothing selected there is no store to name, and a fabricated
    // "s3" here would put Amazon's remedy on a destination that does not exist.
    ok("worm: no destination -> the provider is honestly absent, not guessed", slice?.provider === undefined);
  }

  // A DO that REFUSES the dest-config read (a non-ok response) makes fetchDestConfig throw; gatherWormSlice
  // catches that and treats it as no console override (override = null), then still reports the ENV policy.
  // With a valid env governance/45 policy the slice reads configured + not misconfigured from env alone, so
  // an unreadable stored config never erases a valid env policy nor fabricates a verdict (the resilient
  // read path). A stub returning 500 for the dest-config GET drives the override-read catch.
  {
    const refusingStub = { fetch: async (): Promise<Response> => new Response(null, { status: 500 }) } as unknown as DurableObjectStub;
    const env = { DEST_WORM_MODE: "governance", DEST_WORM_RETENTION_DAYS: "45" } as unknown as Env;
    const slice = await gatherWormSlice(env, refusingStub);
    ok("worm: an unreadable stored config is caught and the env policy still stands (configured, not misconfigured)", slice?.configured === true && slice?.misconfigured === false && slice?.mode === "governance" && slice?.retentionDays === 45);
    ok("worm: with no readable destination the probe is skipped (bucketEnforces absent)", slice?.bucketEnforces === undefined);
  }
}

// ---- 14: computePostureViaDO computes via the DO and routes any regression ------------------------
// The single posture computation path: it gathers the WORM slice, posts to the DO (which adds DO-owned
// state, runs the pure check set, snapshots, and detects regressions against the prior snapshot), then
// routes any regression as a fire-and-forget notification. A second compute after a check flips to failing
// must return the SAME report kind while having driven the regression branch (which must not throw).
async function postureViaDO(): Promise<void> {
  console.log("computePostureViaDO computes through the DO and survives the regression-routing branch:");
  const do_ = makeScheduler();
  const stub = stubFor(do_);
  // No destination configured, so gatherWormSlice skips the probe. A fetch stub is still installed so any
  // incidental destination build attempt is offline.
  const fx = installFetch(() => res(404));
  try {
    // A healthy-ish env: destination + break-glass present so the first posture has those checks passing.
    const goodEnv = { DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK", BREAK_GLASS_PUBLIC: "bg" } as unknown as Env;
    const first = await computePostureViaDO(goodEnv, stub, OWNER_ACCESS);
    ok("posture-via-do: the first compute returns a posture report with checks", Array.isArray(first.checks) && first.checks.length > 0);
    const destCheckFirst = first.checks.find((c) => c.id === "destination-configured");
    ok("posture-via-do: a configured destination passes the destination check", destCheckFirst?.status === "pass");

    // Now REMOVE the destination from env so destination-configured flips pass -> fail. The second compare
    // against the persisted snapshot detects the regression and routes it (fire-and-forget). The call must
    // return the report and must not throw out of the routing guard.
    const degradedEnv = { BREAK_GLASS_PUBLIC: "bg" } as unknown as Env;
    const second = await computePostureViaDO(degradedEnv, stub, OWNER_ACCESS);
    const destCheckSecond = second.checks.find((c) => c.id === "destination-configured");
    ok("posture-via-do: removing the destination flips its check to fail (drives the regression branch)", destCheckSecond?.status === "fail");
    ok("posture-via-do: the regression-routing compute still returns a posture report (fire-and-forget, no throw)", Array.isArray(second.checks) && second.checks.length > 0);

    // A bare-token caller (email null) takes the no-callerEmail branch of the POST body (no per-email
    // recovery set), and still computes a report.
    const tokenReport = await computePostureViaDO(goodEnv, stub, TOKEN_CALLER);
    ok("posture-via-do: a bare-token caller (no email) still computes a report", Array.isArray(tokenReport.checks) && tokenReport.checks.length > 0);
  } finally {
    fx.restore();
  }

  // The regression ROUTING itself failing must never fail the posture READ: the route is fire-and-forget
  // inside a guard that swallows the error (logging it). Drive a fresh DO to a passing destination check,
  // then compute against a degraded env through a stub that REJECTS the /notify/resolve call routePostureRegressions
  // makes. The regression is detected and routing is attempted, the routing promise rejects, the guard
  // catches it (the non-critical log), and the read still returns a full report. A trailing microtask drain
  // lets the fire-and-forget rejection settle so the guard's catch is genuinely taken, not merely scheduled.
  {
    const do2 = makeScheduler();
    // A stub that forwards /posture to the real DO (so the report computes and a regression is produced) but
    // rejects /notify/resolve (so routePostureRegressions throws inside the fire-and-forget guard).
    const failingNotifyStub = {
      fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
        if (url.includes("/notify/resolve")) return Promise.reject(new Error("notify subsystem unreachable"));
        return do2.fetch(input instanceof Request ? input : new Request(input, init));
      },
    } as unknown as DurableObjectStub;
    const fx2 = installFetch(() => res(404));
    try {
      const goodEnv = { DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK", BREAK_GLASS_PUBLIC: "bg" } as unknown as Env;
      // First compute snapshots destination-configured as passing.
      await computePostureViaDO(goodEnv, failingNotifyStub, OWNER_ACCESS);
      // Second compute against a degraded env produces a destination-configured regression, so routing runs
      // and rejects; the guard must swallow it and the read must still return a full report.
      const degradedEnv = { BREAK_GLASS_PUBLIC: "bg" } as unknown as Env;
      const out = await computePostureViaDO(degradedEnv, failingNotifyStub, OWNER_ACCESS);
      // Drain the microtask queue so the fire-and-forget routing rejection settles into the guard's catch.
      await new Promise((resolve) => setTimeout(resolve, 0));
      ok("posture-via-do: a routing failure is swallowed and the read still returns a full report", Array.isArray(out.checks) && out.checks.length > 0);
      ok("posture-via-do: the regression that triggered the failing route was a destination-configured fail", out.checks.find((c) => c.id === "destination-configured")?.status === "fail");
    } finally {
      fx2.restore();
    }
  }
}

// ---- 15: handleReport / buildReportBody across every kind, JSON + PDF, and the 404 guards ----------
// handleReport validates the :kind, gathers the per-kind data (posture/evidence-pack via the DO posture
// path; immutability from the env slice + WORM probe; restore-tests/sla-compliance from DO-owned data),
// signs fail-open, and returns JSON or, with ?format=pdf, a rendered PDF. An unknown kind or an unknown
// evidence-pack framework is a 404, so a typo never silently yields an empty pack.
async function reportHandler(): Promise<void> {
  console.log("handleReport / buildReportBody assemble each report kind (JSON + PDF) and 404 the unknowns:");
  const do_ = makeScheduler();
  const stub = stubFor(do_);
  const env = { DEST_KIND: "s3", DEST_ENDPOINT: ENDPOINT, DEST_BUCKET: BUCKET, DEST_REGION: "us-east-1", DEST_ACCESS_KEY_ID: "AK", DEST_SECRET_ACCESS_KEY: "SK", BREAK_GLASS_PUBLIC: "bg", SIGNER_PRIVATE: signerPrivate() } as unknown as Env;
  const p = (s: string): URLSearchParams => new URLSearchParams(s);
  // Any destination build inside the WORM probe stays offline (no real network).
  const fx = installFetch(() => res(404));
  try {
    // An unknown kind -> 404 with the unknown-kind error.
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "not-a-kind", p(""));
      ok("report: an unknown kind is a 404", r.status === 404);
      ok("report: the unknown-kind body names the error", JSON.stringify(await r.json()).includes("unknown report kind"));
    }

    // An unknown evidence-pack framework -> 404 with the unknown-framework error.
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "evidence-pack", p("framework=not-a-framework"));
      ok("report: an unknown evidence-pack framework is a 404", r.status === 404);
      ok("report: the unknown-framework body names the error", JSON.stringify(await r.json()).includes("unknown framework"));
    }

    // posture -> a signed JSON report (the signer is configured, so a signature is attached).
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "posture", p(""));
      ok("report: posture returns 200 JSON", r.status === 200 && (r.headers.get("content-type") ?? "").includes("application/json"));
      const body = (await r.json()) as Report & { signature?: unknown };
      ok("report: the posture report is the posture kind and is signed", body.kind === "posture" && typeof body.signature === "string");
    }

    // immutability -> a JSON report (point-in-time, null period; reads the env slice + the WORM probe).
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "immutability", p(""));
      const body = (await r.json()) as Report;
      ok("report: immutability returns the immutability kind with a null period", body.kind === "immutability" && body.period === null);
    }

    // evidence-pack (all frameworks, the default) -> a JSON report of the evidence-pack kind.
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "evidence-pack", p(""));
      const body = (await r.json()) as Report;
      ok("report: evidence-pack (all frameworks) returns the evidence-pack kind", body.kind === "evidence-pack");
    }

    // evidence-pack (a single KNOWN framework) -> still the evidence-pack kind (the framework filter path).
    // soc-2 is a real framework id (see frameworks.ts), so isFrameworkId admits it and getFramework resolves
    // exactly one framework, exercising the single-framework filter arm rather than the "all" default.
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "evidence-pack", p("framework=soc-2"));
      ok("report: evidence-pack with a known framework returns 200 of the evidence-pack kind", r.status === 200 && ((await r.json()) as Report).kind === "evidence-pack");
    }

    // restore-tests -> a time-bounded JSON report (the DO supplies the data; the default 90-day period).
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "restore-tests", p(""));
      const body = (await r.json()) as Report;
      ok("report: restore-tests returns the restore-tests kind with a bounded period", body.kind === "restore-tests" && body.period !== null);
    }

    // sla-compliance -> the final buildReportBody branch (the DO sla-data path).
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "sla-compliance", p(""));
      const body = (await r.json()) as Report;
      ok("report: sla-compliance returns the sla-compliance kind with a bounded period", body.kind === "sla-compliance" && body.period !== null);
    }

    // ?format=pdf on posture -> an application/pdf response named for the kind (the PDF render path).
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "posture", p("format=pdf"));
      ok("report: ?format=pdf returns an application/pdf body", (r.headers.get("content-type") ?? "") === "application/pdf");
      ok("report: the posture PDF is named for the kind", (r.headers.get("content-disposition") ?? "").includes("downpipe-posture-report.pdf"));
      const bytes = new Uint8Array(await r.arrayBuffer());
      ok("report: the PDF body is a non-empty %PDF document", bytes.length > 4 && String.fromCharCode(bytes[0]!, bytes[1]!, bytes[2]!, bytes[3]!) === "%PDF");
    }

    // ?format=pdf on an evidence-pack names the FRAMEWORK in the filename (the evidence-pack filename arm).
    {
      const r = await handleReport(env, stub, OWNER_ACCESS, "evidence-pack", p("format=pdf&framework=soc-2"));
      ok("report: an evidence-pack PDF names the framework in the filename", (r.headers.get("content-disposition") ?? "").includes("downpipe-evidence-pack-soc-2.pdf"));
    }

    // buildReportBody directly for sla-compliance with an explicit period proves the unsigned assembly
    // (handleReport wraps this, but the direct call pins the final branch's period passthrough).
    {
      const period = reportPeriodFromQuery("sla-compliance", p("from=1700000000&to=1700100000"), Date.now());
      const built = await buildReportBody(env, stub, OWNER_ACCESS, "sla-compliance", period, Date.now());
      ok("buildReportBody: sla-compliance carries the supplied period through unsigned", built.kind === "sla-compliance" && built.period !== null && built.period.fromSeconds === 1700000000);
    }

    // buildReportBody for evidence-pack with the framework argument OMITTED. handleReport always passes a
    // framework (defaulting to "all"), but the helper is independently callable, so the framework ?? "all"
    // fallback must default to the every-framework pack rather than crashing on an absent target. A direct
    // call with no framework proves that fallback yields the evidence-pack kind over all frameworks.
    {
      const built = await buildReportBody(env, stub, OWNER_ACCESS, "evidence-pack", null, Date.now());
      ok("buildReportBody: evidence-pack with no framework defaults to the all-frameworks pack", built.kind === "evidence-pack");
    }
  } finally {
    fx.restore();
  }
}

async function main(): Promise<void> {
  await wormPutHeaders();
  await nonWormPutUnchanged();
  await conditionalAndMultipart();
  await wormChecksumAndErrors();
  await capabilityProbe();
  await configFailSafe();
  await probeObjectLock();
  postureStates();
  await probeErrorClassification();
  statusSliceProjection();
  reportPeriod();
  await signFailOpen();
  await gatherWorm();
  await postureViaDO();
  await reportHandler();
  console.log(failures === 0 ? "\nWORM / OBJECT-LOCK PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
