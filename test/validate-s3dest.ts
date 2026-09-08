// Prove the S3 destination satisfies the Destination contract over real fetch HTTP, with the
// emphasis on the production PUT wire shape: every
// write goes out as a length-delimited (buffered, NOT chunked) request carrying an explicit
// Content-Length and a SigV4 Authorization header, the x-amz-content-sha256 binds the real
// body hash (not UNSIGNED-PAYLOAD) even on the streamed path, and a non-https DEST_ENDPOINT is
// rejected at construction (V12.3.1) before any credential or byte is signed or sent.
//
// fetch is stubbed (no network, no deploy): the stub captures the method/url/headers/body of
// each request and returns a scripted Response, so the canonical signed path is checked
// against what is actually put on the wire, exactly as validate-r2dest.ts does for the R2
// binding path. Run:
//   node test/validate-s3dest.ts
//
// This file was one ~1440-line module. It is now a thin ORCHESTRATOR: each
// cohesive group of vectors lives in a sibling validate-s3dest-<area>.ts module that exports a run(),
// and the shared fetch stub, the ok() assertion sink, the fixed clock/credentials and the byte
// builders live in validate-s3dest-shared.ts. main() imports and CALLS each group in the same order
// the original ran them, so this command still executes the full suite with the same assertions.
//
// What this covers (unchanged across the split):
//  - the production PUT wire shape + putStream drain-to-a-single-PUT (validate-s3dest-wire.ts);
//  - the STS session token signing, path-style/virtual-hosted addressing and the storage-class
//    header (validate-s3dest-signing.ts);
//  - the Destination HTTP contract, https enforcement, the absent-ETag fix, redirect:manual
//    and the delete + list retention-prune write side (validate-s3dest-contract.ts);
//  - the multipart error and retry paths (validate-s3dest-multipart.ts);
//  - the meter tagging, the conditional/get/list/probe error arms and the drainBounded edge arms
//    (validate-s3dest-edges.ts);
//  - resolveAddressing's arms, and the doubled-endpoint refusal that stops a pasted per-bucket URL
//    becoming "mybucket.mybucket.s3.amazonaws.com" (validate-s3dest-addressing.ts);
//  - the response-body read caps (V12.3.1): every destination response read is bounded by
//    its actual bytes regardless of whether/what Content-Length claims (validate-s3dest-response-cap.ts).

import { getFailures } from "./validate-s3dest-shared.ts";
import { run as runWire } from "./validate-s3dest-wire.ts";
import { run as runSigning } from "./validate-s3dest-signing.ts";
import { run as runContract } from "./validate-s3dest-contract.ts";
import { run as runMultipart } from "./validate-s3dest-multipart.ts";
import { run as runEdges } from "./validate-s3dest-edges.ts";
import { run as runAddressing } from "./validate-s3dest-addressing.ts";
import { run as runResponseCap } from "./validate-s3dest-response-cap.ts";

async function main(): Promise<void> {
  await runWire();
  await runSigning();
  await runContract();
  await runMultipart();
  await runEdges();
  await runAddressing();
  await runResponseCap();

  const failures = getFailures();
  console.log(failures === 0 ? "\nS3 DESTINATION HTTP CONTRACT PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
