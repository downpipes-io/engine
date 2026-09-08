// Prove the engine's OWN passkey (WebAuthn) sign-in front door end to end, SERVER-SIDE, driving the
// REAL verifier (src/admin/passkey.ts) through the REAL scheduler DO (src/sched/scheduler-do.ts), with
// in-memory doubles only. No network, no deploy, no cost. Run:
//   node test/validate-passkey.ts
//
// The engine is its own identity provider, independent of Cloudflare Access (not free over 50 users):
// this is the free, self-contained multi-user front door. These tests stand up a fake-but-REAL
// authenticator: it generates a genuine P-256 (ES256) or RSA (RS256) keypair with Web Crypto, builds
// real WebAuthn structures (a CBOR attestationObject with fmt "none", authenticatorData carrying the
// COSE public key, a clientDataJSON echoing the server challenge), and SIGNS real assertions over
// (authenticatorData || SHA-256(clientDataJSON)). The DO issues + single-use consumes the challenge, runs
// the production verifyRegistration/verifyAssertion, persists the credential + signCount, and bootstraps
// the first registrant to Owner. So the verification path under test is the one that ships, not a copy.
//
// What this proves:
//  - a full register -> login ROUND TRIP verifies (ES256 and RS256), driving the real verifier;
//  - WRONG challenge, WRONG origin, WRONG rpIdHash, TAMPERED signature, BACKWARDS signCount (clone),
//    UNKNOWN credential, and a REPLAYED/consumed challenge are ALL rejected;
//  - the FIRST registrant becomes Owner (the bootstrap), and a SECOND registrant does not;
//  - malformed COSE is rejected;
//  - the coarse client reason is returned while the precise detail goes to console.error with an opaque
//    error id (the errId discipline), and the negative controls are written so they would FAIL if the
//    verifier stopped checking the corresponding fact.
//
// This file is the thin ORCHESTRATOR: the harness (the fake authenticator, the in-memory DO, the HTTP
// drivers and the shared ok() pass-counter) lives in validate-passkey-harness.ts, and the test groups are
// the validate-passkey-*.ts siblings. Each group exports a run(); this file calls them IN ORDER so the
// full suite still runs end to end via `node test/validate-passkey.ts`. The split keeps each file (and
// each function) under the size threshold without dropping, weakening or reordering any assertion.

import { failureCount } from "./validate-passkey-harness.ts";
import { run as runRoundtrip } from "./validate-passkey-roundtrip.ts";
import { run as runNegative } from "./validate-passkey-negative.ts";
import { run as runDer } from "./validate-passkey-der.ts";
import { run as runCose } from "./validate-passkey-cose.ts";
import { run as runCbor } from "./validate-passkey-cbor.ts";
import { run as runAuthz } from "./validate-passkey-authz.ts";
import { run as runSessionMint } from "./validate-passkey-session-mint.ts";
import { run as runWitness } from "./validate-passkey-witness.ts";

async function run(): Promise<void> {
  console.log("validate-passkey: the engine's own WebAuthn passkey front door, driving the real verifier");

  // 1-2. The full ES256/RS256 register -> login round trip and the first-user bootstrap.
  await runRoundtrip();
  // 3-15. The ceremony negative controls plus the uniqueness/not-Owner/fail-closed checks.
  await runNegative();
  // 16. The strict DER -> raw ECDSA converter unit tests.
  await runDer();
  // 17. The COSE_Key parser bounds.
  await runCose();
  // 17b. The bounded CBOR decoder primitives.
  await runCbor();
  // 18-28b. The account-takeover fix (registration authorisation) and the remaining front-door controls.
  await runAuthz();
  // 29. The sessionCookieForFinish mint-path error branches, isolated.
  await runSessionMint();
  // 30. The USABILITY WITNESS: lastAssertedAt stamped only on a verified assertion, stamped even when the
  // counter does not move, never stamped on a refusal, and the four-way evidence enum that keeps "unknown"
  // distinguishable from "never".
  await runWitness();

  const failures = failureCount();
  console.log(failures === 0 ? "\nvalidate-passkey: ALL PASS" : `\nvalidate-passkey: ${failures} FAILED`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});
