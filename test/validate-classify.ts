// Vectors for the shared destination-fault classifier (dest/classify.ts, adaptive-dest-backpressure
// Layer 1a): the throttle/transient/auth/permanent/ok truth table, the throttle vs transient narrowing,
// the error-message vocabulary the dest/API layers throw, and the behavioural parity that lets
// seal/retry.ts isTransient delegate to it without changing which faults retry.
import { classifyDestStatus, classifyDestError, classifyDestErrorArm, isThrottleOrTransient, isThrottleClass, destDownReason } from "../src/dest/classify.ts";
import { s3WriteFailure } from "../src/dest/s3-worm.ts";
import { DestStatusError } from "../src/dest/types.ts";
import { isTransient } from "../src/seal/retry.ts";
import { CfApiError } from "../src/sources/cf-config-core.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

function main(): void {
  console.log("classifyDestStatus truth table:");
  ok("429 -> throttle", classifyDestStatus(429) === "throttle");
  ok("503 -> throttle", classifyDestStatus(503) === "throttle");
  ok("500 -> transient", classifyDestStatus(500) === "transient");
  ok("502 -> transient", classifyDestStatus(502) === "transient");
  ok("504 -> transient", classifyDestStatus(504) === "transient");
  ok("408 -> transient", classifyDestStatus(408) === "transient");
  ok("any other 5xx (507) -> transient", classifyDestStatus(507) === "transient");
  ok("401 -> auth (fail loud)", classifyDestStatus(401) === "auth");
  ok("403 -> auth (fail loud)", classifyDestStatus(403) === "auth");
  ok("400 -> permanent (WORM Content-MD5 etc.)", classifyDestStatus(400) === "permanent");
  ok("404 -> permanent (a conditional path that expected the object)", classifyDestStatus(404) === "permanent");
  ok("405 -> permanent", classifyDestStatus(405) === "permanent");
  ok("411 -> permanent", classifyDestStatus(411) === "permanent");
  ok("413 -> permanent", classifyDestStatus(413) === "permanent");
  ok("422 -> permanent", classifyDestStatus(422) === "permanent");
  ok("200 -> ok", classifyDestStatus(200) === "ok");
  ok("204 -> ok", classifyDestStatus(204) === "ok");
  ok("a Retry-After argument does NOT change the class (503 stays throttle)", classifyDestStatus(503, 5000) === "throttle");

  console.log("\nclassifyDestError over the thrown-message vocabulary:");
  ok("dest 'PUT seg/..: status 503' -> throttle", classifyDestError(new Error("PUT seg/3f/x.seg: status 503")) === "throttle");
  ok("conditional RUNLOG 'status 503' -> throttle", classifyDestError(new Error("conditional PUT _RECOVERY/RUNLOG: status 503")) === "throttle");
  ok("dest 'GET ..: status 500' -> transient", classifyDestError(new Error("GET _RECOVERY/RUNLOG: status 500")) === "transient");
  ok("CF API 'HTTP 429' -> throttle", classifyDestError(new Error("Cloudflare API GET /x: HTTP 429")) === "throttle");
  ok("dest 'status 403' -> auth (fail loud)", classifyDestError(new Error("PUT seg/x: status 403")) === "auth");
  ok("dest 'status 400' -> permanent (fail loud)", classifyDestError(new Error("PUT seg/x: status 400")) === "permanent");
  ok("a network shape 'fetch failed' -> transient", classifyDestError(new Error("fetch failed")) === "transient");
  ok("a Retry-After-tagged error -> throttle", classifyDestError(Object.assign(new Error("media upload x: throttled"), { retryAfterMs: 2000 })) === "throttle");
  ok("an unreadable fault defaults to permanent (fail loud, never retry-loop)", classifyDestError(new Error("something unexpected")) === "permanent");
  ok("a digit in a key (seg/3) is NOT read as a status", classifyDestError(new Error("PUT seg/3/x.seg failed")) === "permanent");

  console.log("\nthe TYPED status on the error beats any prose in its message:");
  // CfApiError builds its message as the joined Cloudflare error text `|| "HTTP <status>"`, so the status is
  // in the message ONLY when Cloudflare answered with no text. These are the same statuses in both shapes:
  // the class must not depend on whether Cloudflare happened to write a sentence, and it must never depend on
  // which words that sentence contained. Both harms are represented, and both are production-reachable
  // through withRetry (the CF account-API reads are wrapped in it).
  // The REAL producers, not a stand-in: the vector is bound to the shape production actually throws, so it
  // fails if either class ever stops carrying the status.
  const cfErr = (message: string, status: number): Error => new CfApiError(message, status, [], false);
  const dsErr = (message: string, status: number): Error => new DestStatusError(message, status);
  ok("503 with NO CF text (status is in the message) -> throttle", classifyDestError(cfErr("Cloudflare API GET /x: HTTP 503", 503)) === "throttle");
  ok("503 WITH CF text -> still throttle, from the typed status", classifyDestError(cfErr("Cloudflare API GET /x: Service temporarily unavailable", 503)) === "throttle");
  ok("500 WITH CF text that matches nothing -> transient, so a blip is RIDDEN OUT", isTransient(cfErr("Cloudflare API GET /x: An unknown error occurred", 500)) === true);
  ok("400 WITH CF text containing 'connection' -> permanent, NOT six retries per surface", classifyDestError(cfErr("Cloudflare API GET /x: Invalid connection string", 400)) === "permanent");
  ok("404 WITH CF text containing 'network' -> permanent, not retried", isTransient(cfErr("Cloudflare API GET /x: network binding not found", 404)) === false);
  ok("403 WITH CF text -> auth, not the unreadable default", classifyDestError(cfErr("Cloudflare API GET /x: Authentication error", 403)) === "auth");
  ok("DestStatusError's typed status agrees with its own message (no change on that path)", classifyDestError(dsErr("DELETE seg/x: status 503", 503)) === "throttle");
  ok("the ARM records that the status came from the field, not the text", classifyDestErrorArm(cfErr("Cloudflare API GET /x: Service temporarily unavailable", 503)).arm === "typed-status");
  ok("the arm carries the real status, so a 0 still means no status was ever seen", classifyDestErrorArm(cfErr("Cloudflare API GET /x: whatever", 500)).status === 500);
  // A `.status` that is not an HTTP status must not be read as one: the bound is what stops a socket close
  // code, a string or another library's enum from steering the retry decision.
  ok("a non-integer .status is ignored", classifyDestErrorArm(Object.assign(new Error("fetch failed"), { status: "503" })).arm === "matched-network");
  ok("an out-of-range .status (a 1006 close code) is ignored", classifyDestErrorArm(Object.assign(new Error("fetch failed"), { status: 1006 })).arm === "matched-network");
  ok("a .status of 0 is ignored, never read as a class", classifyDestError(Object.assign(new Error("something unexpected"), { status: 0 })) === "permanent");

  console.log("\nisThrottleOrTransient (the retry predicate) vs isThrottleClass (the park-and-resume predicate):");
  ok("503 is throttle-or-transient", isThrottleOrTransient(new Error("PUT x: status 503")));
  ok("500 is throttle-or-transient", isThrottleOrTransient(new Error("PUT x: status 500")));
  ok("403 is NOT throttle-or-transient (no retry)", !isThrottleOrTransient(new Error("PUT x: status 403")));
  ok("400 is NOT throttle-or-transient (no retry)", !isThrottleOrTransient(new Error("PUT x: status 400")));
  ok("503 IS the throttle class (routes to the resume ladder)", isThrottleClass(new Error("PUT x: status 503")));
  ok("429 IS the throttle class", isThrottleClass(new Error("PUT x: HTTP 429")));
  ok("500 is NOT the throttle class (a transient 5xx fails inline, not parked)", !isThrottleClass(new Error("PUT x: status 500")));
  ok("403 is NOT the throttle class (auth fails loud, never parks)", !isThrottleClass(new Error("PUT x: status 403")));

  console.log("\nseal/retry isTransient delegates to the classifier with no behaviour change:");
  for (const m of ["PUT x: status 503", "GET x: status 500", "PUT x: status 507", "fetch failed", "connection reset", "too many requests"]) {
    ok(`'${m}' stays retryable`, isTransient(new Error(m)) === true);
  }
  for (const m of ["PUT x: status 403", "PUT x: status 400", "missing required configuration", "source binding error"]) {
    ok(`'${m}' stays non-retryable`, isTransient(new Error(m)) === false);
  }
  ok("a Retry-After-tagged error stays retryable (CF API 429 parity)", isTransient(Object.assign(new Error("Cloudflare API GET /x: HTTP 429"), { retryAfterMs: 1000 })) === true);

  // ---- an Object-Lock refusal that arrives as a 403 must not read as a credentials fault ----------------
  // destDownReason is what the canary's write probe records as ailingCause (canary/cycle.ts) and what the
  // per-destination down indicator shows. S3 refuses a lock-protected overwrite with a 403, and a 403 is a
  // status, so the auth arm decided it before the Object-Lock net was ever reached: the operator was told to
  // look at their credentials when the destination's own immutability policy was refusing the write. Rotating
  // a credential cannot fix a retention policy. The verdict now comes from a BOOLEAN stamped by
  // s3WriteFailure from the real response body at the throw site, above the auth arm.
  console.log("\nObject-Lock refusals are told apart from credentials faults:");
  const lockBody = "<Error><Code>AccessDenied</Code><Message>Content-MD5 or x-amz-checksum header is required</Message></Error>";
  const retentionBody = "<Error><Code>InvalidRetentionPeriod</Code></Error>";
  const authBody = "<Error><Code>AccessDenied</Code><Message>not authorized to perform s3:PutObject</Message></Error>";
  // POSITIVE CONTROLS first, so a failure below is the defect and not the harness.
  ok("CONTROL: a plain 403 credentials refusal still reads as auth", destDownReason(s3WriteFailure("PUT", "seg/0001", 403, authBody)) === "auth");
  ok("CONTROL: a 400 Object-Lock refusal still reads as worm-refused (this arm always worked)", destDownReason(s3WriteFailure("PUT", "seg/0001", 400, retentionBody)) === "worm-refused");
  ok("CONTROL: a 429 still reads as throttled", destDownReason(new Error("PUT seg/0001: status 429")) === "throttled");
  // THE CASE: a 403 that IS an Object-Lock refusal.
  ok("a 403 Object-Lock refusal reads as worm-refused, NOT auth", destDownReason(s3WriteFailure("PUT", "seg/0001", 403, lockBody)) === "worm-refused");
  ok("a 403 InvalidRetentionPeriod refusal reads as worm-refused, NOT auth", destDownReason(s3WriteFailure("PUT", "seg/0001", 403, retentionBody)) === "worm-refused");
  // The stamp is ADDITIVE: the message every other consumer reads is byte-identical to what it was.
  ok("the message is unchanged by the stamp (the checksum hint case)", s3WriteFailure("PUT", "seg/0001", 403, lockBody).message === "PUT seg/0001: status 403 (AccessDenied: object lock write requires a checksum)");
  ok("the message is unchanged by the stamp (the plain code case)", s3WriteFailure("PUT", "seg/0001", 403, retentionBody).message === "PUT seg/0001: status 403 (InvalidRetentionPeriod)");
  ok("a body with no recognisable code still yields the bare status message", s3WriteFailure("PUT", "seg/0001", 500, "<html>gateway</html>").message === "PUT seg/0001: status 500");
  // The class is untouched: only the DOWN-REASON label moves. A 403 is still an auth-class fault that fails
  // loud, so nothing about retry or park changes.
  ok("the fault CLASS of a 403 lock refusal is still auth (retry behaviour unchanged)", classifyDestError(s3WriteFailure("PUT", "seg/0001", 403, lockBody)) === "auth");
  // A foreign truthy property of the same name must never steer the verdict.
  ok("a non-boolean objectLockRefusal property is ignored", destDownReason(Object.assign(new Error("PUT x: status 403"), { objectLockRefusal: "yes" })) === "auth");

  // ---- the same refusal on R2, which the whole apparatus above was blind to -----------------------------
  // WORM-ON-A-NON-LOCKED-BUCKET-STORES-AS-VERIFIED. R2 answers a lock-bearing PUT to a bucket
  // that is not Object-Lock enabled with "status 501 (NotImplemented)". NotImplemented was in neither
  // vocabulary, so the refusal read as http-5xx: the operator was sent to wait out a Cloudflare incident
  // that is not happening and will never clear. R2 is the primary store for this product, so the classifier
  // was blind exactly where it matters most. AWS's own answer to the SAME combination is the control, and it
  // has always worked -- it is kept green on BOTH sides so this is shown to ADD R2, not to move the class.
  console.log("\nR2's refusal of the same combination lands in the same class as AWS's:");
  const awsNoLockBody = "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>";
  const r2NoLockBody = "<Error><Code>NotImplemented</Code><Message>Object Lock is not enabled for this bucket</Message></Error>";
  // CONTROL: the AWS half of the measured pair, in the class it has always had.
  ok("CONTROL: AWS 400 ObjectLockConfigurationNotFoundError reads worm-refused", destDownReason(s3WriteFailure("PUT", "seg/0001", 400, awsNoLockBody, true)) === "worm-refused");
  ok("CONTROL: and it is a permanent fault, so it is never retried", isThrottleOrTransient(s3WriteFailure("PUT", "seg/0001", 400, awsNoLockBody, true)) === false);
  // THE CASE: the R2 half, on a write that ACTUALLY carried Object-Lock headers.
  const r2Refusal = s3WriteFailure("PUT", "seg/0001", 501, r2NoLockBody, true);
  ok("R2's 501 NotImplemented on a LOCK-ARMED write reads worm-refused, not http-5xx", destDownReason(r2Refusal) === "worm-refused");
  ok("... and it is PERMANENT, so withRetry stops spending six attempts per write on it", classifyDestError(r2Refusal) === "permanent" && isThrottleOrTransient(r2Refusal) === false);
  ok("... and the arm records that a retryable status was overruled by the stamped body fact", classifyDestErrorArm(r2Refusal).arm === "object-lock-refusal" && classifyDestErrorArm(r2Refusal).status === 501);
  ok("... and the message is unchanged, so every message-based consumer sees what it saw", r2Refusal.message === "PUT seg/0001: status 501 (NotImplemented)");
  // NARROWING CONTROL, and this is why fix 3 is not "501 is now permanent". A store answering NotImplemented
  // to a write that asked for NO lock is refusing something else entirely, and nothing establishes that it
  // will refuse identically for ever. It keeps the class it had.
  const plainNotImplemented = s3WriteFailure("PUT", "seg/0001", 501, r2NoLockBody);
  ok("NARROWING: NotImplemented on a write with NO lock headers is NOT a worm refusal", destDownReason(plainNotImplemented) === "other");
  ok("NARROWING: ... and stays TRANSIENT, so an unrelated 501 is still retried as before", classifyDestError(plainNotImplemented) === "transient" && isThrottleOrTransient(plainNotImplemented) === true);
  ok("NARROWING: a bare 501 with no code at all is unchanged too", classifyDestError(new Error("PUT seg/0001: status 501")) === "transient");
  // The override fires ONLY on a reading that was retryable. The two classes that already failed loud keep
  // the exact class and arm they had, so this adds a case rather than moving one.
  ok("the 400 lock refusal keeps its own arm (the override did not swallow it)", classifyDestErrorArm(s3WriteFailure("PUT", "k", 400, awsNoLockBody, true)).arm === "embedded-status");
  ok("the 403 lock refusal is still auth-class, arm unchanged", classifyDestErrorArm(s3WriteFailure("PUT", "k", 403, lockBody)).arm === "embedded-status");

  console.log(failures === 0 ? "\nDEST CLASSIFIER PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
