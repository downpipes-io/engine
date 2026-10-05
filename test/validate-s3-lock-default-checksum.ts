// Proves the S3 destination writes into a bucket whose Object Lock DEFAULT RETENTION rule demands an
// integrity header on every write, and that a store which must not receive that header never does.
//
// THE DEFECT (reported live against AWS S3). A bucket with an Object Lock default retention
// rule makes AWS refuse EVERY PutObject that carries neither Content-MD5 nor an x-amz-checksum-* header,
// with 400 InvalidRequest, including a write that carries no lock header of its own. The engine sent
// x-amz-checksum-sha256 only when the destination had its own WORM policy, so the save-time write probe
// (which deliberately never arms WORM) failed with "PUT _RECOVERY/.write-probe: status 400 (InvalidRequest:
// object lock write requires a checksum)", and so would every run write from a destination without a
// policy, single-shot and multipart alike.
//
// THE FAKE. fakeS3 below is a stateful, offline S3 bucket behind a fetch stub. It verifies the SigV4
// signature of every request against the credentials it was given, refuses any wire header that the
// signature does not cover, stores objects and multipart parts, and models the AWS rules this fix depends on:
//   - with defaultRetention, a PutObject (and, per `demand`, a CreateMultipartUpload or an UploadPart) with
//     no Content-MD5 and no x-amz-checksum-* is refused with AWS's own 400 InvalidRequest body;
//   - a sent x-amz-checksum-sha256 must equal the base64 SHA-256 of the body, or 400 BadDigest;
//   - a part's checksum must match the algorithm its upload was created with (x-amz-checksum-algorithm), and
//     a checksummed upload must name every part's ChecksumSHA256 at completion, or 400.
// With rejectChecksumHeader it is instead a store that answers any x-amz-checksum-* header with 400
// "Unsupported header", which is how a provider that must not receive the header is graded: a single stray
// header turns the run red. With stubborn it refuses even a checksummed request, which grades the guards that
// stop the destination retrying a request that already carried one. A Content-MD5 must be the MD5 of the body.
//
// FAIL BEFORE, PASS AFTER. Against the code before this fix, sections 2 to 5c fail (the probe, the run PUT,
// the conditional PUT and both multipart shapes are refused by the fake); section 6 passes before and after,
// because it guards what the fix must NOT change. Section 1 is the negative control: it shows the fake
// really does refuse, so a green run cannot come from a fake that accepts everything.
//
// Run: node test/validate-s3-lock-default-checksum.ts

import { createHash } from "node:crypto";
import { base64Encode, hexDecode, utf8 } from "../src/crypto/bytes.ts";
import { probeDestination } from "../src/admin/router-posture.ts";
import { S3Destination } from "../src/dest/s3.ts";
import { signV4, type SigV4Creds } from "../src/dest/sigv4.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { type Captured, fill, getFailures, installFetch, MULTIPART_SIZE, ok, sha256Hex, streamOf } from "./validate-s3dest-shared.ts";

const ENDPOINT = "https://s3.example.com";
const BUCKET = "locked-bucket";
const CREDS: SigV4Creds = { accessKeyID: "AKIDEXAMPLE", secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "s3" };

// AWS's own refusal text for a write with no integrity header into an Object Lock bucket.
const AWS_MISSING_CHECKSUM =
  "<Error><Code>InvalidRequest</Code><Message>Content-MD5 OR x-amz-checksum- HTTP header is required for Put Object requests with Object Lock parameters</Message><RequestId>R1</RequestId></Error>";

interface FakeOpts {
  creds: SigV4Creds;
  // The bucket has an Object Lock default retention rule (AWS then demands an integrity header).
  defaultRetention?: boolean;
  // GetObjectLockConfiguration reads Enabled (with or without a default rule).
  lockEnabled?: boolean;
  // Which multipart step AWS refuses without a checksum. Both are modelled, because which of the two a real
  // bucket refuses first does not change what the destination must do.
  demand?: "initiate" | "part";
  // A store that rejects every x-amz-checksum-* header.
  rejectChecksumHeader?: boolean;
  // A STUBBORN store: it answers AWS's missing-checksum refusal to every request of this kind, even one that
  // carries a checksum. It grades the guards that stop the destination retrying a write that already sent one.
  stubborn?: "put" | "initiate" | "part";
}

interface Upload {
  algorithm: string | undefined;
  parts: Map<number, { bytes: Uint8Array; checksum: string | undefined }>;
  done: boolean;
}

interface Fake {
  captures: Captured[];
  objects: Map<string, Uint8Array>;
  uploads: Map<string, Upload>;
  refusals: string[];
  restore: () => void;
}

function xmlRes(status: number, body: string, headers?: Record<string, string>): Response {
  return new Response(body, { status, headers: { "content-type": "application/xml", ...(headers ?? {}) } });
}

function hasIntegrity(c: Captured): boolean {
  return c.headers["content-md5"] !== undefined || Object.keys(c.headers).some((h) => h.startsWith("x-amz-checksum-") && h !== "x-amz-checksum-algorithm");
}

// verifySignature recomputes the SigV4 Authorization from the headers the request NAMED as signed, and also
// refuses any x-amz-* or content-md5 header on the wire that the signature does not cover. The host header is
// set by the runtime rather than by the caller, so it is taken from the URL, exactly as a real store sees it.
async function verifySignature(c: Captured, creds: SigV4Creds): Promise<string | null> {
  const auth = c.headers["authorization"] ?? "";
  const signed = (/SignedHeaders=([^,]+)/.exec(auth)?.[1] ?? "").split(";");
  const u = new URL(c.url);
  for (const h of Object.keys(c.headers)) {
    if ((h.startsWith("x-amz-") || h === "content-md5") && !signed.includes(h)) return `unsigned header ${h}`;
  }
  const headers: Record<string, string> = {};
  for (const h of signed) headers[h] = h === "host" ? u.host : (c.headers[h] ?? "");
  const payloadHash = c.headers["x-amz-content-sha256"] ?? "";
  if (payloadHash !== (await sha256Hex(c.body))) return "payload hash does not match the body";
  const expect = await signV4(c.method, u.pathname, u.search.replace(/^\?/, ""), headers, payloadHash, c.headers["x-amz-date"] ?? "", creds);
  return expect === auth ? null : "signature mismatch";
}

// fakeS3 installs the stateful bucket. Every refusal is recorded by a short reason so a failing assertion
// can say which rule fired.
function fakeS3(opts: FakeOpts): Fake {
  const objects = new Map<string, Uint8Array>();
  const uploads = new Map<string, Upload>();
  const refusals: string[] = [];
  let nextUpload = 1;
  let stubbornHits = 0;
  const refuse = (why: string, r: Response): Response => {
    refusals.push(why);
    return r;
  };
  const handle = async (c: Captured): Promise<Response> => {
    const u = new URL(c.url);
    const key = decodeURIComponent(u.pathname.replace(`/${BUCKET}/`, ""));
    const q = u.searchParams;
    const sigFault = await verifySignature(c, opts.creds);
    if (sigFault !== null) return refuse(sigFault, xmlRes(403, `<Error><Code>SignatureDoesNotMatch</Code></Error>`));
    if (opts.rejectChecksumHeader) {
      const bad = Object.keys(c.headers).find((h) => h.startsWith("x-amz-checksum"));
      if (bad !== undefined) return refuse(`unsupported ${bad}`, xmlRes(400, `<Error><Code>InvalidArgument</Code><Message>Unsupported header '${bad}' received for this API call.</Message></Error>`));
    }
    const sent = c.headers["x-amz-checksum-sha256"];
    if (sent !== undefined && sent !== base64Encode(hexDecode(await sha256Hex(c.body)))) return refuse("bad digest", xmlRes(400, `<Error><Code>BadDigest</Code></Error>`));
    // Content-MD5 is checked like AWS checks it: it must be the base64 MD5 of THIS request's body. On the
    // empty-body CreateMultipartUpload that is the fixed empty-body digest, and nothing else passes.
    const md5 = c.headers["content-md5"];
    if (md5 !== undefined && md5 !== createHash("md5").update(c.body).digest("base64")) return refuse("bad content-md5", xmlRes(400, `<Error><Code>BadDigest</Code></Error>`));
    const isPartReq = c.method === "PUT" && q.has("partNumber");
    const kind = c.method === "POST" && q.has("uploads") ? "initiate" : isPartReq ? "part" : c.method === "PUT" ? "put" : "other";
    if (opts.stubborn === kind) {
      stubbornHits++;
      // A backstop so a destination that loops on this answer ends the run rather than hanging it.
      if (stubbornHits > 6) return refuse("stubborn backstop", xmlRes(500, "<Error><Code>InternalError</Code></Error>"));
      return refuse(`stubborn ${kind}`, xmlRes(400, AWS_MISSING_CHECKSUM));
    }
    if (c.method === "GET" && q.has("object-lock")) {
      if (!opts.lockEnabled) return xmlRes(404, `<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>`);
      const rule = opts.defaultRetention ? "<Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Days>30</Days></DefaultRetention></Rule>" : "";
      return xmlRes(200, `<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled>${rule}</ObjectLockConfiguration>`);
    }
    if (c.method === "HEAD") return new Response(null, { status: objects.has(key) ? 200 : 404 });
    if (c.method === "DELETE" && q.has("uploadId")) {
      const up = uploads.get(q.get("uploadId") ?? "");
      if (up) up.done = true;
      return new Response(null, { status: 204 });
    }
    if (c.method === "DELETE") return new Response(null, { status: 204 });
    if (c.method === "POST" && q.has("uploads")) {
      if (opts.defaultRetention && opts.demand === "initiate" && !hasIntegrity(c)) return refuse("initiate without checksum", xmlRes(400, AWS_MISSING_CHECKSUM));
      const id = `up-${nextUpload++}`;
      uploads.set(id, { algorithm: c.headers["x-amz-checksum-algorithm"], parts: new Map(), done: false });
      return xmlRes(200, `<InitiateMultipartUploadResult><UploadId>${id}</UploadId></InitiateMultipartUploadResult>`);
    }
    if (c.method === "PUT" && q.has("partNumber")) {
      const up = uploads.get(q.get("uploadId") ?? "");
      if (!up || up.done) return refuse("no such upload", xmlRes(404, `<Error><Code>NoSuchUpload</Code></Error>`));
      if (up.algorithm === undefined && sent !== undefined) return refuse("part checksum on an upload created without one", xmlRes(400, `<Error><Code>InvalidRequest</Code><Message>Checksum Type mismatch occurred, expected checksum Type: null, actual checksum Type: sha256</Message></Error>`));
      if (up.algorithm === "SHA256" && sent === undefined) return refuse("part without the upload's checksum", xmlRes(400, `<Error><Code>InvalidRequest</Code><Message>x-amz-checksum-sha256 required</Message></Error>`));
      if (opts.defaultRetention && opts.demand === "part" && !hasIntegrity(c)) return refuse("part without checksum", xmlRes(400, AWS_MISSING_CHECKSUM));
      const n = Number(q.get("partNumber"));
      up.parts.set(n, { bytes: c.body, checksum: sent });
      return new Response(null, { status: 200, headers: { etag: `"etag-${n}"` } });
    }
    if (c.method === "POST" && q.has("uploadId")) {
      const up = uploads.get(q.get("uploadId") ?? "");
      if (!up || up.done) return refuse("complete of a closed upload", xmlRes(404, `<Error><Code>NoSuchUpload</Code></Error>`));
      const xml = new TextDecoder().decode(c.body);
      const named = [...xml.matchAll(/<Part><PartNumber>(\d+)<\/PartNumber><ETag>[^<]*<\/ETag>(?:<ChecksumSHA256>([^<]*)<\/ChecksumSHA256>)?<\/Part>/g)];
      const chunks: Uint8Array[] = [];
      for (const [, num, sum] of named) {
        const p = up.parts.get(Number(num));
        if (!p) return refuse("complete names a missing part", xmlRes(400, `<Error><Code>InvalidPart</Code></Error>`));
        if (up.algorithm === "SHA256" && sum !== p.checksum) return refuse("complete without the part checksum", xmlRes(400, `<Error><Code>InvalidPart</Code></Error>`));
        chunks.push(p.bytes);
      }
      const total = chunks.reduce((a, b) => a + b.length, 0);
      const whole = new Uint8Array(total);
      let off = 0;
      for (const ch of chunks) {
        whole.set(ch, off);
        off += ch.length;
      }
      objects.set(key, whole);
      up.done = true;
      return xmlRes(200, `<CompleteMultipartUploadResult><Key>${key}</Key><ETag>"whole"</ETag></CompleteMultipartUploadResult>`);
    }
    if (c.method === "PUT") {
      if (opts.defaultRetention && !hasIntegrity(c)) return refuse("put without checksum", xmlRes(400, AWS_MISSING_CHECKSUM));
      if (c.headers["if-none-match"] === "*" && objects.has(key)) return new Response(null, { status: 412 });
      objects.set(key, c.body);
      return new Response(null, { status: 200, headers: { etag: `"obj-${objects.size}"` } });
    }
    return refuse(`unmodelled ${c.method} ${u.search}`, xmlRes(500, "<Error><Code>InternalError</Code></Error>"));
  };
  const { captures, restore } = installFetch(() => new Response(null, { status: 599 }));
  // installFetch's script is synchronous; wrap the installed stub so the fake can hash and verify.
  const captureStub = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    await captureStub(input, init);
    return handle(captures[captures.length - 1]!);
  }) as typeof fetch;
  return { captures, objects, uploads, refusals, restore };
}

const newDest = (extra?: ConstructorParameters<typeof S3Destination>[5]): S3Destination =>
  new S3Destination(ENDPOINT, BUCKET, CREDS.region, CREDS.accessKeyID, CREDS.secretKey, { now: () => new Date("2026-09-24T01:02:03.000Z"), ...(extra ?? {}) });

const isPart = (c: Captured): boolean => c.method === "PUT" && c.url.includes("partNumber=");
const isInitiate = (c: Captured): boolean => c.method === "POST" && c.url.includes("uploads=");
const isComplete = (c: Captured): boolean => c.method === "POST" && c.url.includes("uploadId=");
const isAbort = (c: Captured): boolean => c.method === "DELETE" && c.url.includes("uploadId=");
const signedList = (c: Captured): string[] => (/SignedHeaders=([^,]+)/.exec(c.headers["authorization"] ?? "")?.[1] ?? "").split(";");

// ---- 1: negative control. The fake refuses what AWS refuses, so a green below means something ---------
async function negativeControl(): Promise<void> {
  console.log("1. negative control: the fake bucket refuses a write with no integrity header, and a wrong checksum:");
  const fake = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true });
  try {
    const u = new URL(`${ENDPOINT}/${BUCKET}/k`);
    const body = utf8("control");
    const payloadHash = await sha256Hex(body);
    const amzDate = "20260924T010203Z";
    const bare = { host: u.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash };
    const auth = await signV4("PUT", u.pathname, "", bare, payloadHash, amzDate, CREDS);
    const r1 = await fetch(u, { method: "PUT", headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, Authorization: auth }, body });
    ok("a signed PUT with no checksum is refused 400 with AWS's missing-checksum body", r1.status === 400 && (await r1.text()).includes("x-amz-checksum"));
    const wrong = { ...bare, "x-amz-checksum-sha256": base64Encode(new Uint8Array(32)) };
    const auth2 = await signV4("PUT", u.pathname, "", wrong, payloadHash, amzDate, CREDS);
    const r2 = await fetch(u, { method: "PUT", headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, "x-amz-checksum-sha256": wrong["x-amz-checksum-sha256"], Authorization: auth2 }, body });
    ok("a PUT whose checksum is not the body's SHA-256 is refused (BadDigest)", r2.status === 400 && fake.refusals.includes("bad digest"));
    const r3 = await fetch(u, { method: "PUT", headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, "x-amz-checksum-sha256": "unsigned", Authorization: auth }, body });
    ok("a checksum header the signature does not cover is refused (403)", r3.status === 403 && fake.refusals.includes("unsigned header x-amz-checksum-sha256"));
    const badMd5 = { ...bare, "content-md5": "1B2M2Y8AsgTpgAmY7PhCfg==" };
    const auth4 = await signV4("PUT", u.pathname, "", badMd5, payloadHash, amzDate, CREDS);
    const r4 = await fetch(u, { method: "PUT", headers: { "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash, "content-md5": badMd5["content-md5"], Authorization: auth4 }, body });
    ok("a Content-MD5 that is not the MD5 of the body (here the empty-body digest on a non-empty body) is refused", r4.status === 400 && fake.refusals.includes("bad content-md5"));
  } finally {
    fake.restore();
  }
}

// ---- 2: the save-time write probe against a bucket with a default retention rule ----------------------
async function probeAgainstDefaultRetention(): Promise<void> {
  console.log("2. the destination probe (validateAndProbeDestConfig's probeDestination) against a default-retention bucket:");
  const override = { endpoint: ENDPOINT, bucket: BUCKET, region: "us-east-1", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "probe-secret" };
  const fake = fakeS3({ creds: { accessKeyID: "AKIDEXAMPLE", secretKey: "probe-secret", region: "us-east-1", service: "s3" }, defaultRetention: true, lockEnabled: true });
  try {
    const p = await probeDestination({} as Env, override);
    ok("the probe succeeds (was: 'PUT _RECOVERY/.write-probe: status 400 (InvalidRequest: object lock write requires a checksum)')", p.ok === true);
    if (!p.ok) console.log(`       probe reason: ${p.reason}`);
    const puts = fake.captures.filter((c) => c.method === "PUT");
    ok("the probe PUT is sent at most twice (the refused one, then one with the checksum)", puts.length <= 2);
    const last = puts[puts.length - 1];
    ok("the accepted probe PUT carries x-amz-checksum-sha256 inside the signature", last !== undefined && last.headers["x-amz-checksum-sha256"] !== undefined && signedList(last).includes("x-amz-checksum-sha256"));
    ok("the accepted probe PUT carries NO Object-Lock header (the probe still never arms WORM)", last !== undefined && !Object.keys(last.headers).some((h) => h.startsWith("x-amz-object-lock")));
    ok("the probe object was really stored", fake.objects.has("_RECOVERY/.write-probe"));
    ok("the probe reads the bucket as enforced with a default retention rule", p.ok === true && p.objectLock === "enforced" && p.defaultRetention === true);
    ok("the probe reports checksumRequired, so the router can store it on the destination", p.ok === true && p.checksumRequired === true);
  } finally {
    fake.restore();
  }
}

// ---- 3: an ordinary run PUT and conditional PUT from a destination with no WORM policy -----------------
async function runPutsWithoutWorm(): Promise<void> {
  console.log("3. run writes (PUT, conditional PUT) from a destination with no worm config:");
  const fake = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true });
  try {
    const dest = newDest();
    const body = fill(4096);
    let threw = "";
    try {
      await dest.put("seg/0001", body);
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("a plain run PUT into a default-retention bucket succeeds", threw === "");
    ok("the relearning is counted for the support pack (destIo checksumRetries 1)", dest.destIo().checksumRetries === 1);
    if (threw !== "") console.log(`       threw: ${threw}`);
    ok("the stored bytes are the bytes sent", fake.objects.get("seg/0001")?.length === body.length);
    const before = fake.captures.length;
    await dest.put("seg/0002", fill(100)).catch(() => undefined);
    const second = fake.captures.slice(before);
    ok("the fact is remembered: the next PUT on the same instance is sent ONCE, with the checksum", second.length === 1 && second[0]!.headers["x-amz-checksum-sha256"] !== undefined);
    const cond = await dest.putConditional("_RECOVERY/RUNLOG", utf8("runlog"), { ifNoneMatch: "*" }).catch((e: Error) => e);
    ok("a conditional PUT (the RUNLOG write) succeeds too", !(cond instanceof Error) && cond.ok === true);

    const fresh = newDest();
    const condFresh = await fresh.putConditional("_RECOVERY/RUNLOG-2", utf8("runlog"), { ifNoneMatch: "*" }).catch((e: Error) => e);
    ok("a conditional PUT as the FIRST write of a fresh instance learns the rule and succeeds", !(condFresh instanceof Error) && condFresh.ok === true);
  } finally {
    fake.restore();
  }

  // A refusal of a write that ALREADY carried a checksum is an ordinary failure: no further retry.
  for (const [label, worm] of [
    ["a WORM destination (it sends the checksum from the start)", true],
    ["a destination with no policy (it learns, retries once, then stops)", false],
  ] as const) {
    const stubborn = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true, stubborn: "put" });
    try {
      const d = newDest(worm ? { worm: { mode: "compliance", retentionDays: 30 } } : undefined);
      const e = await d.put("seg/x", fill(10)).catch((err: Error) => err);
      const sends = stubborn.captures.filter((c) => c.method === "PUT").length;
      ok(`stubborn store, ${label}: the PUT throws after ${worm ? "ONE request" : "TWO requests"}`, e instanceof Error && sends === (worm ? 1 : 2) && /object lock write requires a checksum/.test(e.message));
    } finally {
      stubborn.restore();
    }
  }
}

// ---- 4 and 5: a multipart upload from a destination with no WORM policy -------------------------------
async function multipart(demand: "initiate" | "part"): Promise<void> {
  console.log(`${demand === "initiate" ? "4" : "5"}. multipart upload with no worm config, the bucket refusing the ${demand === "initiate" ? "CreateMultipartUpload" : "first UploadPart"} without a checksum:`);
  const fake = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true, demand });
  try {
    const dest = newDest();
    const chunk = fill(MULTIPART_SIZE);
    let threw = "";
    try {
      await dest.putStream("seg/big", streamOf(chunk), MULTIPART_SIZE);
    } catch (e) {
      threw = (e as Error).message;
    }
    ok("the multipart upload succeeds", threw === "");
    ok("the relearning is counted once for the support pack", dest.destIo().checksumRetries === 1);
    if (threw !== "") console.log(`       threw: ${threw}; refusals: ${fake.refusals.join(" | ")}`);
    const stored = fake.objects.get("seg/big");
    ok("the assembled object is every byte sent, in order", stored !== undefined && stored.length === chunk.length && stored[12345] === chunk[12345] && stored[stored.length - 1] === chunk[chunk.length - 1]);
    const initiates = fake.captures.filter(isInitiate);
    const lastInit = initiates[initiates.length - 1];
    ok("the upload that completed was created with x-amz-checksum-algorithm SHA256, signed", lastInit !== undefined && lastInit.headers["x-amz-checksum-algorithm"] === "SHA256" && signedList(lastInit).includes("x-amz-checksum-algorithm"));
    const okParts = fake.captures.filter(isPart).slice(-2);
    ok("every accepted part carries its own x-amz-checksum-sha256, signed", okParts.length === 2 && okParts.every((c) => c.headers["x-amz-checksum-sha256"] !== undefined && signedList(c).includes("x-amz-checksum-sha256")));
    ok("the completion names each part's ChecksumSHA256", fake.captures.filter(isComplete).some((c) => (new TextDecoder().decode(c.body).match(/<ChecksumSHA256>/g) ?? []).length === 2));
    if (demand === "part") ok("the upload created without a checksum was aborted, not stranded", fake.captures.some(isAbort) && [...fake.uploads.values()].every((u) => u.done));
    const before = fake.captures.length;
    await dest.putStream("seg/big2", streamOf(fill(MULTIPART_SIZE)), MULTIPART_SIZE).catch(() => undefined);
    const again = fake.captures.slice(before);
    ok("the fact is remembered: the next upload is created checksummed first time (one initiate, no abort)", again.filter(isInitiate).length === 1 && !again.some(isAbort) && fake.objects.has("seg/big2"));
  } finally {
    fake.restore();
  }

  // An object key that reads like a transport fault must not turn the refusal into a "transient" one: the
  // multipart retry matches its error MESSAGE, and that message carries the key.
  const keyed = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true, demand });
  try {
    const e = await newDest().putStream("seg/network-connection/timed-out/big", streamOf(fill(MULTIPART_SIZE)), MULTIPART_SIZE).catch((err: Error) => err);
    ok("a key that reads like a network fault still recovers (no transient retry, no re-wrap)", !(e instanceof Error) && keyed.objects.has("seg/network-connection/timed-out/big"));
    if (e instanceof Error) console.log(`       threw: ${e.message}`);
  } finally {
    keyed.restore();
  }
}

// ---- 5b: stubborn stores grade the guards that stop a checksummed request being retried again --------
async function stubbornMultipart(): Promise<void> {
  console.log("5b. a store that refuses the checksummed request too: the destination stops after one checksummed try:");
  const init = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true, stubborn: "initiate" });
  try {
    const e = await newDest().putStream("seg/big", streamOf(fill(MULTIPART_SIZE)), MULTIPART_SIZE).catch((err: Error) => err);
    const initiates = init.captures.filter(isInitiate);
    ok("initiate: exactly two initiates, the first bare and the second checksummed", initiates.length === 2 && initiates[0]!.headers["x-amz-checksum-algorithm"] === undefined && initiates[1]!.headers["x-amz-checksum-algorithm"] === "SHA256");
    ok("initiate: the upload fails with the store's refusal, not a loop", e instanceof Error && !init.refusals.includes("stubborn backstop"));
  } finally {
    init.restore();
  }
  const part = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true, stubborn: "part" });
  try {
    const dest = newDest();
    const e = await dest.putStream("seg/big", streamOf(fill(MULTIPART_SIZE)), MULTIPART_SIZE).catch((err: Error) => err);
    const parts = part.captures.filter(isPart);
    ok("part: exactly two sends of part 1, the first bare and the second checksummed", parts.length === 2 && parts[0]!.headers["x-amz-checksum-sha256"] === undefined && parts[1]!.headers["x-amz-checksum-sha256"] !== undefined);
    ok("part: the checksummed refusal is an ordinary fault, recorded in the fault ring", e instanceof Error && dest.destFaults().faults.some((f) => f.op === "multipart-part" && f.s3Code === "InvalidRequest"));
    ok("part: both uploads were aborted, none stranded", [...part.uploads.values()].every((u) => u.done));
  } finally {
    part.restore();
  }
}

// ---- 5c: the fact stored on the destination config seeds a fresh instance --------------------------
async function seededInstance(): Promise<void> {
  console.log("5c. a destination built with checksumRequired (the stored fact) pays for no refused write:");
  const fake = fakeS3({ creds: CREDS, defaultRetention: true, lockEnabled: true, demand: "part" });
  try {
    const dest = newDest({ checksumRequired: true });
    await dest.put("seg/one", fill(32)).catch(() => undefined);
    ok("the first PUT is ONE request and carries the checksum", fake.captures.length === 1 && fake.captures[0]!.headers["x-amz-checksum-sha256"] !== undefined);
    const before = fake.captures.length;
    await dest.putStream("seg/big", streamOf(fill(MULTIPART_SIZE)), MULTIPART_SIZE).catch(() => undefined);
    const mp = fake.captures.slice(before);
    ok("the first multipart is created checksummed: one initiate, no abort, stored", mp.filter(isInitiate).length === 1 && mp.filter(isInitiate)[0]!.headers["x-amz-checksum-algorithm"] === "SHA256" && !mp.some(isAbort) && fake.objects.has("seg/big"));
    ok("nothing was relearned (checksumRetries 0)", dest.destIo().checksumRetries === 0 && dest.checksumRequired());
  } finally {
    fake.restore();
  }
}

// ---- 6: a store that must NOT receive the header never does ---------------------------------------------
async function storesThatMustNotReceiveTheHeader(): Promise<void> {
  console.log("6. stores that reject the checksum header never receive it without a WORM policy:");
  for (const [label, lockEnabled] of [
    ["an Object Lock bucket that reads Enabled with no default rule", true],
    ["a bucket with no Object Lock at all (the R2 shape)", false],
  ] as const) {
    const fake = fakeS3({ creds: CREDS, lockEnabled, rejectChecksumHeader: true });
    try {
      const dest = newDest();
      const status = await dest.objectLockStatus();
      ok(`${label}: the lock reading is ${lockEnabled ? "Enabled" : "not enabled"}`, status.enabled === lockEnabled);
      const errs: string[] = [];
      await dest.put("seg/a", fill(64)).catch((e: Error) => errs.push(e.message));
      await dest.putConditional("_RECOVERY/RUNLOG", utf8("r"), { ifNoneMatch: "*" }).catch((e: Error) => errs.push(e.message));
      await dest.putStream("seg/big", streamOf(fill(MULTIPART_SIZE)), MULTIPART_SIZE).catch((e: Error) => errs.push(e.message));
      ok(`${label}: PUT, conditional PUT and multipart all succeed`, errs.length === 0);
      if (errs.length > 0) console.log(`       ${errs.join(" | ")}`);
      ok(`${label}: no request carried any x-amz-checksum-* header`, !fake.captures.some((c) => Object.keys(c.headers).some((h) => h.startsWith("x-amz-checksum"))));
      ok(`${label}: no initiate carried Content-MD5 (the ordinary multipart wire shape is unchanged)`, !fake.captures.filter(isInitiate).some((c) => c.headers["content-md5"] !== undefined));
      // Control for this section: the same store does refuse a write that carries the header, so the
      // "never received" verdict above is one this fake could have failed.
      const worm = await newDest({ worm: { mode: "governance", retentionDays: 1 } }).put("seg/control", fill(8)).catch((e: Error) => e);
      ok(`${label}: control: a write that carries the header is refused by this store`, worm instanceof Error && fake.refusals.includes("unsupported x-amz-checksum-sha256"));
    } finally {
      fake.restore();
    }
  }
}

async function main(): Promise<void> {
  await negativeControl();
  await probeAgainstDefaultRetention();
  await runPutsWithoutWorm();
  await multipart("initiate");
  await multipart("part");
  await stubbornMultipart();
  await seededInstance();
  await storesThatMustNotReceiveTheHeader();
  const failures = getFailures();
  console.log(failures === 0 ? "\nALL S3 DEFAULT-RETENTION CHECKSUM CHECKS PASSED" : `\n${failures} S3 DEFAULT-RETENTION CHECKSUM CHECK(S) FAILED`);
  verdictReached(failures);
  process.exitCode = failures === 0 ? 0 : 1;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
