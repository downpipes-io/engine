// Prove buildDestination (src/dest/factory.ts) chooses the archive store TOTALLY and FAIL-LOUD, so a
// run or a restore drill writes through whichever store the customer configured and a misconfiguration
// never silently falls back to the wrong transport. This is pure config selection: no network, no
// credentials on the wire, no cost. It covers every branch:
//   - an explicit DEST_KIND wins ("r2" / "s3"), and an unrecognised DEST_KIND is REJECTED (a typo must
//     not silently fall back to S3);
//   - with no DEST_KIND, an R2 binding alone selects R2, S3 credentials alone select S3, NEITHER is
//     rejected, and the AMBIGUOUS case (both present) is refused rather than silently preferring one;
//   - the S3 path requires each of its five settings (requireEnv) and refuses a non-https endpoint at the
//     boundary (V12.3.1: the SigV4 credential and archive bytes must never ride cleartext).
// Run:
//   node test/validate-dest-factory.ts

import { buildDestination } from "../src/dest/factory.ts";
import { S3Destination } from "../src/dest/s3.ts";
import { R2Destination } from "../src/dest/r2.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A minimal R2 binding stand-in: R2Destination only stores the reference in its constructor, so any
// object satisfies the "present binding" condition the factory checks. No method is called here.
const R2_BINDING = {} as unknown as R2Bucket;

// The five S3 settings, all valid, with an https endpoint S3Destination accepts. Spread into an Env and
// override one field at a time to drive the requireEnv misses.
const S3_OK = {
  DEST_ENDPOINT: "https://s3.example.com",
  DEST_BUCKET: "archive-bucket",
  DEST_REGION: "ap-southeast-2",
  DEST_ACCESS_KEY_ID: "AKIAEXAMPLE",
  DEST_SECRET_ACCESS_KEY: "secret-example",
};

// env builds an Env from a partial; only the destination fields matter to buildDestination.
function env(partial: Record<string, unknown>): Env {
  return partial as unknown as Env;
}

// rejects runs an ASYNC fn and returns the rejection Error message, or null if it did NOT reject (so a
// missing throw is a visible failure). buildDestination is async (it may mint STS credentials for an
// AssumeRole destination), so its fail-loud branches REJECT rather than throw synchronously.
async function rejects(fn: () => Promise<unknown>): Promise<string | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

// ---- explicit DEST_KIND wins ------------------------------------------------------------
async function testExplicitKind(): Promise<void> {
  // kind "r2" selects R2 even with no other config; kind "s3" selects S3 (with valid S3 settings).
  ok("DEST_KIND=r2 selects R2Destination", (await buildDestination(env({ DEST_KIND: "r2", DEST_R2: R2_BINDING }))) instanceof R2Destination);
  ok("DEST_KIND=s3 selects S3Destination", (await buildDestination(env({ DEST_KIND: "s3", ...S3_OK }))) instanceof S3Destination);
  // DEST_KIND is trimmed before the check, so surrounding whitespace still resolves.
  ok("DEST_KIND is trimmed (' r2 ' still selects R2)", (await buildDestination(env({ DEST_KIND: " r2 ", DEST_R2: R2_BINDING }))) instanceof R2Destination);
  // An explicit kind "r2" wins even when S3 credentials are ALSO present (kind is the override, so this
  // is NOT the ambiguous case).
  ok("DEST_KIND=r2 wins over present S3 creds (kind is the override, not ambiguous)",
    (await buildDestination(env({ DEST_KIND: "r2", DEST_R2: R2_BINDING, ...S3_OK }))) instanceof R2Destination);
  // An explicit kind "s3" wins even when an R2 binding is ALSO present.
  ok("DEST_KIND=s3 wins over a present R2 binding",
    (await buildDestination(env({ DEST_KIND: "s3", DEST_R2: R2_BINDING, ...S3_OK }))) instanceof S3Destination);
}

// ---- an unrecognised DEST_KIND is rejected (a typo must not silently fall back) ----------
async function testUnrecognisedKind(): Promise<void> {
  const msg = await rejects(() => buildDestination(env({ DEST_KIND: "gcs", DEST_R2: R2_BINDING })));
  ok("an unrecognised DEST_KIND throws (no silent fallback)", msg !== null);
  ok('the rejection names DEST_KIND and the bad value', msg !== null && /DEST_KIND must be "r2" or "s3"/.test(msg) && /gcs/.test(msg));
  // An empty-string DEST_KIND trims to "" which is not undefined and not r2/s3, so it is also rejected
  // (rather than being treated as "unset").
  const emptyMsg = await rejects(() => buildDestination(env({ DEST_KIND: "   ", DEST_R2: R2_BINDING })));
  ok("a whitespace-only DEST_KIND (trims to empty) is rejected, not treated as unset", emptyMsg !== null && /DEST_KIND must be/.test(emptyMsg));
}

// ---- no DEST_KIND: infer from what is configured ----------------------------------------
async function testInferFromConfig(): Promise<void> {
  // R2 binding alone -> R2.
  ok("no DEST_KIND, R2 binding alone selects R2", (await buildDestination(env({ DEST_R2: R2_BINDING }))) instanceof R2Destination);
  // S3 credentials alone -> S3. (s3Configured is true if ANY one S3 field is set; here all are.)
  ok("no DEST_KIND, S3 creds alone select S3", (await buildDestination(env({ ...S3_OK }))) instanceof S3Destination);
  // A SINGLE S3 field is enough to mark S3 "configured": with no R2 binding it selects S3 (and then the
  // requireEnv checks fire for the missing fields), proving s3Configured is an OR over the five fields.
  const partialS3 = await rejects(() => buildDestination(env({ DEST_ENDPOINT: "https://s3.example.com" })));
  ok("no DEST_KIND, a single S3 field marks S3 configured then requires the rest", partialS3 !== null && /missing required configuration: DEST_BUCKET/.test(partialS3));
}

// ---- the AMBIGUOUS case is refused (both R2 and S3 present, no DEST_KIND) ----------------
async function testAmbiguous(): Promise<void> {
  const msg = await rejects(() => buildDestination(env({ DEST_R2: R2_BINDING, ...S3_OK })));
  ok("no DEST_KIND with BOTH R2 and S3 configured is refused (ambiguous)", msg !== null);
  ok("the ambiguity rejection tells the operator to set DEST_KIND", msg !== null && /ambiguous destination/.test(msg) && /set DEST_KIND/.test(msg));
}

// ---- NEITHER configured is refused (no DEST_KIND, no R2, no S3) --------------------------
async function testNeitherConfigured(): Promise<void> {
  // useR2 resolves to false (r2 is undefined), so the S3 path runs and its first requireEnv (the
  // endpoint) throws: a totally unconfigured destination fails loud rather than returning a dud store.
  const msg = await rejects(() => buildDestination(env({})));
  ok("no DEST_KIND and nothing configured is refused (S3 path, missing DEST_ENDPOINT)", msg !== null && /missing required configuration: DEST_ENDPOINT/.test(msg));
}

// ---- DEST_KIND=r2 but the binding is missing --------------------------------------------
async function testMissingR2Binding(): Promise<void> {
  // kind forces R2, but no DEST_R2 binding is present: the R2 path requires it and fails loud.
  const msg = await rejects(() => buildDestination(env({ DEST_KIND: "r2" })));
  ok("DEST_KIND=r2 with no DEST_R2 binding is refused (missing DEST_R2)", msg !== null && /missing required configuration: DEST_R2/.test(msg));
}

// ---- the S3 path requires each of its five settings (requireEnv) ------------------------
async function testS3RequiredFields(): Promise<void> {
  // Omit one field at a time; the matching requireEnv must fire with that field's name. Driven via
  // DEST_KIND=s3 so the S3 path is taken deterministically regardless of the other fields.
  const fields: Array<keyof typeof S3_OK> = ["DEST_ENDPOINT", "DEST_BUCKET", "DEST_REGION", "DEST_ACCESS_KEY_ID", "DEST_SECRET_ACCESS_KEY"];
  for (const f of fields) {
    const partial: Record<string, unknown> = { DEST_KIND: "s3", ...S3_OK };
    delete partial[f];
    const msg = await rejects(() => buildDestination(env(partial)));
    ok(`S3 path requires ${f} (requireEnv)`, msg !== null && new RegExp(`missing required configuration: ${f}`).test(msg));
  }
  // An empty string (not just undefined) is also "missing": requireEnv uses falsiness, so "" is rejected.
  const emptyMsg = await rejects(() => buildDestination(env({ DEST_KIND: "s3", ...S3_OK, DEST_BUCKET: "" })));
  ok("S3 path treats an EMPTY string field as missing (requireEnv falsiness)", emptyMsg !== null && /missing required configuration: DEST_BUCKET/.test(emptyMsg));
}

// ---- the S3 path refuses a non-https endpoint at the boundary (V12.3.1) ------------------
async function testHttpsEnforcement(): Promise<void> {
  // A plain http:// endpoint must be rejected by the S3Destination constructor BEFORE any credential or
  // byte is signed, so the SigV4 Authorization header and archive bytes never ride cleartext.
  const httpMsg = await rejects(() => buildDestination(env({ DEST_KIND: "s3", ...S3_OK, DEST_ENDPOINT: "http://s3.example.com" })));
  ok("S3 path refuses a non-https (http://) endpoint", httpMsg !== null);
  // http://localhost is the single permitted exception (local MinIO/LocalStack), so it constructs.
  ok("S3 path permits http://localhost (the local test exception)",
    (await buildDestination(env({ DEST_KIND: "s3", ...S3_OK, DEST_ENDPOINT: "http://localhost:9000" }))) instanceof S3Destination);
}

async function main(): Promise<void> {
  await testExplicitKind();
  await testUnrecognisedKind();
  await testInferFromConfig();
  await testAmbiguous();
  await testNeitherConfigured();
  await testMissingR2Binding();
  await testS3RequiredFields();
  await testHttpsEnforcement();

  console.log("");
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.log(`DEST FACTORY: ${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("DEST FACTORY SELECTION PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
