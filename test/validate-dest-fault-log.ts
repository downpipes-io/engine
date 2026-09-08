// Validates the destination fault ring (src/dest/fault-log.ts + the S3 driver's recording sites).
//
// The gap: every destination op past the single-shot PUT (multipart initiate/part/complete/abort, GET,
// DELETE, LIST, the Object-Lock probe) failed as a bare "status 403", so a support pack could not separate
// an expired STS session from a bucket-policy denial from a WORM refusal, and could not tell a real
// permanent fault from one the classifier DEFAULTED to permanent because it could not read the message.
//
// This proves (a) the fault identity IS recorded on every fault path, in closed vocabularies, and (b) it is
// redaction-safe: a bucket name, a customer key, an IAM ARN, an opaque request id and an injected <Code>
// planted in the store's error body NEVER appear in the recorded snapshot.
//
// The S3 driver is driven over a stubbed global fetch; no network. Run: node test/validate-dest-fault-log.ts.

import { S3Destination } from "../src/dest/s3.ts";
import { closedS3Code, DEST_FAULT_SHAPES, type DestFaultSnapshot } from "../src/dest/fault-log.ts";
import { classifyDestErrorArm, destDownReason } from "../src/dest/classify.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// ---------------------------------------------------------------------------------------------------
// The customer values planted in every stubbed error body/header. NONE of them may reach a record.
// ---------------------------------------------------------------------------------------------------
const BUCKET = "acme-prod-archive-bucket";
const CUSTOMER_KEY = "seg/0001-ACME-PAYROLL";
const IAM_ARN = "arn:aws:iam::999999999999:user/acme-backup-robot";
const REQUEST_ID = "TXHJ8Q2ZKP0OPAQUE9";
const SECRETS = [BUCKET, CUSTOMER_KEY, IAM_ARN, REQUEST_ID, "acme", "Message", "Resource"];

// errorBody builds an S3 error document of the shape a real store returns, stuffed with customer values.
function errorBody(code: string, extra = ""): string {
  return `<?xml version="1.0"?><Error><Code>${code}</Code><Message>Denied for ${IAM_ARN} ${extra}</Message><Resource>/${BUCKET}/${CUSTOMER_KEY}</Resource><RequestId>${REQUEST_ID}</RequestId></Error>`;
}

type Reply = { status: number; body?: string; headers?: Record<string, string> } | { throws: Error };
let queue: Reply[] = [];
function stubFetch(replies: Reply[]): void {
  queue = [...replies];
  (globalThis as { fetch: unknown }).fetch = async (): Promise<Response> => {
    const r = queue.shift();
    if (r === undefined) throw new Error("stub fetch: no reply queued");
    if ("throws" in r) throw r.throws;
    return new Response(r.body ?? "", { status: r.status, headers: { "x-amz-request-id": REQUEST_ID, ...(r.headers ?? {}) } });
  };
}

function dest(): S3Destination {
  return new S3Destination("https://s3.example.com", BUCKET, "us-east-1", "AKIAEXAMPLE", "secret-key-value", { fetchTimeoutMs: 50 });
}

async function swallow(fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
  } catch {
    // Every case below is a FAULT path; the throw is expected and is not what is under test.
  }
}

function only(snap: DestFaultSnapshot): DestFaultSnapshot["faults"][number] {
  return snap.faults[0]!;
}

// ---------------------------------------------------------------------------------------------------
// 1. The closed S3 <Code> allow-list.
// ---------------------------------------------------------------------------------------------------
console.log("closed S3 error-code vocabulary");
ok("a documented code is recorded verbatim", closedS3Code(errorBody("SignatureDoesNotMatch")) === "SignatureDoesNotMatch");
ok("an UNDOCUMENTED code is coarsened to 'other'", closedS3Code(errorBody("AcmeCustomFailureXYZ")) === "other");
ok("a body with no code records 'none'", closedS3Code("<html>gateway error</html>") === "none");
ok("a hostile long/punctuated code cannot smuggle text", closedS3Code("<Code>Denied: /acme-prod-archive-bucket/seg/1</Code>") === "none");
ok("an empty body records 'none'", closedS3Code("") === "none");

// ---------------------------------------------------------------------------------------------------
// 2. The classifier ARM (the half of the diagnosis that was missing: permanent-because-403 vs
//    permanent-because-unreadable).
// ---------------------------------------------------------------------------------------------------
console.log("classifier arm");
ok("a status in the message reads as embedded-status", classifyDestErrorArm(new Error("PUT k: status 403")).arm === "embedded-status");
ok("... and carries the status int", classifyDestErrorArm(new Error("PUT k: status 403")).status === 403);
ok("a network shape reads as matched-network", classifyDestErrorArm(new Error("fetch failed")).arm === "matched-network");
ok("a Retry-After tag reads as matched-retry-after", classifyDestErrorArm(Object.assign(new Error("nope"), { retryAfterMs: 10 })).arm === "matched-retry-after");
ok("an UNREADABLE fault is flagged default-permanent (not silently 'permanent')", classifyDestErrorArm(new Error("something went wrong")).arm === "default-permanent");
ok("... and still classifies permanent (fail loud, unchanged)", classifyDestErrorArm(new Error("something went wrong")).fault === "permanent");

// ---------------------------------------------------------------------------------------------------
// 3. The closed destination down-reason vocabulary.
// ---------------------------------------------------------------------------------------------------
console.log("closed destination down-reason vocabulary");
ok("a 403 is auth", destDownReason(new Error("PUT k: status 403")) === "auth");
ok("an Object-Lock refusal is worm-refused", destDownReason(new Error("PUT k: status 400 (InvalidRequest: object lock write requires a checksum)")) === "worm-refused");
ok("a 503 is throttled", destDownReason(new Error("PUT k: status 503")) === "throttled");
ok("an abort bound is timeout", destDownReason(new Error("s3 request timed out after 120000ms")) === "timeout");
ok("a certificate fault is tls", destDownReason(new Error("TLS handshake failed: certificate expired")) === "tls");
ok("a connection fault is network", destDownReason(new Error("fetch failed")) === "network");
ok("an unreadable fault is other", destDownReason(new Error("???")) === "other");

// ---------------------------------------------------------------------------------------------------
// 4. Recording on the real fault paths of the S3 driver.
// ---------------------------------------------------------------------------------------------------
console.log("faults are recorded on every destination op");

// GET, 403 SignatureDoesNotMatch (a broken credential, not a policy denial).
{
  const d = dest();
  stubFetch([{ status: 403, body: errorBody("SignatureDoesNotMatch") }]);
  await swallow(() => d.get("seg/x"));
  const f = only(d.destFaults());
  ok("GET 403 records op=get", f.op === "get");
  ok("GET 403 records the status", f.httpStatus === 403);
  ok("GET 403 records the closed code", f.s3Code === "SignatureDoesNotMatch");
  ok("GET 403 records fault=auth", f.fault === "auth");
  ok("GET 403 records arm=matched-status", f.arm === "matched-status");
  ok("GET 403 records that the store returned a request id (presence only)", f.requestIdPresent === true);
}

// GET, 404: the NORMAL absent answer, never a fault.
{
  const d = dest();
  stubFetch([{ status: 404 }]);
  ok("GET 404 returns null", (await d.get("seg/x")) === null);
  ok("GET 404 records NO fault", d.destFaults().total === 0);
}

// PUT, 400 InvalidRequest with AWS's Object-Lock checksum complaint (the WORM-refused arm).
{
  const d = dest();
  stubFetch([{ status: 400, body: errorBody("InvalidRequest", "requires Content-MD5") }]);
  await swallow(() => d.put("seg/x", new Uint8Array([1])));
  const f = only(d.destFaults());
  ok("PUT 400 records op=put with the InvalidRequest code", f.op === "put" && f.s3Code === "InvalidRequest");
  ok("PUT 400 flags the Object-Lock checksum complaint", f.wormChecksumComplaint === true);
}

// DELETE, 403 AccessDenied: the prune permanently cannot reclaim (a locked/denied bucket).
{
  const d = dest();
  stubFetch([{ status: 403, body: errorBody("AccessDenied") }]);
  await swallow(() => d.delete("seg/x"));
  const f = only(d.destFaults());
  ok("DELETE 403 records op=delete + AccessDenied", f.op === "delete" && f.s3Code === "AccessDenied" && f.fault === "auth");
}

// LIST, 500.
{
  const d = dest();
  stubFetch([{ status: 500, body: errorBody("InternalError") }]);
  await swallow(() => d.list("seg/"));
  const f = only(d.destFaults());
  ok("LIST 500 records op=list, fault=transient", f.op === "list" && f.httpStatus === 500 && f.fault === "transient");
}

// HEAD, 403: the FALSE-GREEN the preflight exists to expose (exists() would collapse it to false).
{
  const d = dest();
  stubFetch([{ status: 403 }]);
  ok("headStatus still returns the raw status", (await d.headStatus("seg/x")) === 403);
  ok("HEAD 403 records op=head", only(d.destFaults()).op === "head");
}
{
  const d = dest();
  stubFetch([{ status: 404 }]);
  await d.exists("seg/x");
  ok("HEAD 404 (absent) records NO fault", d.destFaults().total === 0);
}

// Multipart initiate, 403 ExpiredToken: an STS session that lapsed mid-run.
{
  const d = dest();
  stubFetch([{ status: 403, body: errorBody("ExpiredToken") }]);
  const body = new ReadableStream<Uint8Array>({
    start(c) {
      c.close();
    },
  });
  await swallow(() => d.putStream("seg/big", body));
  const f = only(d.destFaults());
  ok("multipart initiate 403 records op=multipart-initiate", f.op === "multipart-initiate");
  ok("multipart initiate 403 records the ExpiredToken code (was a bare 'status 403')", f.s3Code === "ExpiredToken");
}

// The Object-Lock probe: a 403 was SWALLOWED to enabled:"unknown" with no reason at all.
{
  const d = dest();
  stubFetch([{ status: 403, body: errorBody("AccessDenied") }]);
  const st = await d.objectLockStatus();
  ok("the object-lock probe still degrades to the safe unknown", st.enabled === "unknown");
  const f = only(d.destFaults());
  ok("... but the swallowed probe fault is now recorded", f.op === "object-lock-probe" && f.s3Code === "AccessDenied");
}

// A TRANSPORT fault: no response at all.
{
  const d = dest();
  stubFetch([{ throws: new Error("fetch failed") }]);
  await swallow(() => d.get("seg/x"));
  const f = only(d.destFaults());
  ok("a transport fault records status 0 and arm=matched-network", f.httpStatus === 0 && f.arm === "matched-network" && f.op === "get");
  ok("... with no S3 code", f.s3Code === "none");
}

// A fault whose shape the classifier CANNOT read: the arm that was invisible.
{
  const d = dest();
  stubFetch([{ throws: new Error("the mysterious unexplained failure") }]);
  await swallow(() => d.get("seg/x"));
  const f = only(d.destFaults());
  ok("an unreadable transport fault records arm=default-permanent", f.arm === "default-permanent" && f.fault === "permanent");
}

// ---------------------------------------------------------------------------------------------------
// 5. Bounding: identical shapes collapse with a count; distinct shapes are hard-capped with an overflow.
// ---------------------------------------------------------------------------------------------------
console.log("the ring is bounded");
{
  const d = dest();
  stubFetch([
    { status: 503, body: errorBody("SlowDown") },
    { status: 503, body: errorBody("SlowDown") },
    { status: 503, body: errorBody("SlowDown") },
  ]);
  for (let i = 0; i < 3; i++) await swallow(() => d.list("seg/"));
  const snap = d.destFaults();
  ok("3 identical faults collapse to ONE shape", snap.faults.length === 1);
  ok("... with count 3 and total 3", only(snap).count === 3 && snap.total === 3);
}
{
  const d = dest();
  const statuses = [400, 402, 405, 406, 409, 410, 411, 413, 415, 451];
  stubFetch(statuses.map((s) => ({ status: s })));
  for (const _ of statuses) await swallow(() => d.headStatus("seg/x"));
  const snap = d.destFaults();
  ok(`${statuses.length} distinct shapes are capped at ${DEST_FAULT_SHAPES}`, snap.faults.length === DEST_FAULT_SHAPES);
  ok("the total still counts every fault", snap.total === statuses.length);
  ok("the dropped shapes are tallied as overflow (never silently green)", snap.overflow === statuses.length - DEST_FAULT_SHAPES);
}

// ---------------------------------------------------------------------------------------------------
// 6. REDACTION (no-custody, binding): no customer value planted in the store's error body or headers may
//    appear anywhere in the recorded snapshot, and an injected <Code> is coarsened, not echoed.
// ---------------------------------------------------------------------------------------------------
console.log("redaction: the recorded snapshot leaks nothing");
{
  const d = dest();
  stubFetch([
    { status: 403, body: errorBody("AccessDenied") },
    { status: 400, body: errorBody("AcmeInternalCodeLEAK") },
    { status: 500, body: `<Error><Code>InternalError</Code><Message>${CUSTOMER_KEY}</Message></Error>` },
    { throws: new Error(`fetch failed to https://${BUCKET}.s3.example.com/${CUSTOMER_KEY}`) },
  ]);
  await swallow(() => d.get("seg/a"));
  await swallow(() => d.put(CUSTOMER_KEY, new Uint8Array([1])));
  await swallow(() => d.list("seg/"));
  await swallow(() => d.delete(CUSTOMER_KEY));
  const snap = d.destFaults();
  const json = JSON.stringify(snap);
  ok("4 faults were recorded (the fault paths all fired)", snap.total === 4);
  for (const s of SECRETS) ok(`the snapshot does not contain "${s}"`, !json.toLowerCase().includes(s.toLowerCase()));
  ok("an injected non-allow-list <Code> is coarsened to 'other', never echoed", json.includes('"other"') && !json.includes("LEAK"));
  ok("no key/prefix rides in the record", !json.includes("seg/"));
  // Every recorded field must be a closed enum, a boolean or a clamped int: prove no string field is free text.
  const CLOSED_OPS = new Set(["put", "put-conditional", "multipart-initiate", "multipart-part", "multipart-complete", "multipart-abort", "get", "head", "delete", "list", "object-lock-probe"]);
  const CLOSED_FAULTS = new Set(["throttle", "transient", "auth", "permanent", "ok"]);
  const CLOSED_ARMS = new Set(["matched-status", "typed-status", "embedded-status", "matched-retry-after", "matched-network", "default-permanent", "object-lock-refusal"]);
  ok(
    "every record's fields are closed-vocabulary / clamped",
    snap.faults.every(
      (f) =>
        CLOSED_OPS.has(f.op) &&
        CLOSED_FAULTS.has(f.fault) &&
        CLOSED_ARMS.has(f.arm) &&
        Number.isInteger(f.httpStatus) &&
        f.httpStatus >= 0 &&
        f.httpStatus <= 999 &&
        typeof f.requestIdPresent === "boolean" &&
        typeof f.wormChecksumComplaint === "boolean" &&
        Number.isInteger(f.count),
    ),
  );
  // The snapshot's keys are a fixed set: nothing new can be smuggled in as an extra property.
  const keys = new Set(snap.faults.flatMap((f) => Object.keys(f)));
  ok("no unexpected field appears on a record", [...keys].every((k) => ["op", "httpStatus", "s3Code", "fault", "arm", "requestIdPresent", "wormChecksumComplaint", "count"].includes(k)));
}

console.log(failures === 0 ? "\nOK: destination fault ring records closed, bounded, redaction-safe fault identity" : `\n${failures} FAILURES`);
if (failures > 0) process.exitCode = 1;
process.exit(failures === 0 ? 0 : 1);
