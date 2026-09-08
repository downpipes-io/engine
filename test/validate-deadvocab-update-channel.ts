// DEAD-VOCABULARY PRODUCERS: THE UPDATE PIPELINE'S CHANNEL AND DIGEST LEGS.
//
// Four members of the update-fault ring were declared and could never be emitted: the `channel` COMPONENT,
// the `channel-verify` STEP, the `digest-check` STEP and the `digest-mismatch` CAUSE. The consequences were
// not symmetric with the usual "an absent row":
//
//   - A channel that will NOT VERIFY (a rotated release signer, a truncated CDN object, a producer drift)
//     produced a pack in which the update pipeline had never been touched at all: the customer cannot update,
//     and the evidence says nothing happened. loadVerifiedChannel COMPUTED the closed cause and then threw it
//     away one line later, because its declared return type was `{ error: string }`.
//   - A DIGEST MISMATCH -- the downloaded artefact does not hash to what the SIGNED channel declares, which is
//     CDN corruption or TAMPER -- had no arm in classifyUpdateFailStep, so it fell through to the residual
//     {version-post, other}: a CLOUDFLARE UPLOAD FAULT, reported for a release that was never uploaded,
//     because Cloudflare had not been called yet. Three wrong facts in one row, in the highest-impact failure mode domain.
//
// These blocks drive the REAL producers: verifyAndGuard (the guard sequence every apply and ramp runs) with a
// real artefact whose hash does not match, and loadVerifiedChannel (the resolver the apply route calls) with a
// real env. The refusal SENTENCES are never hand-typed: they are taken from the product's own message table,
// so a reworded message cannot silently un-wire the classifier while this test keeps passing.
//
// Run: node test/validate-deadvocab-update-channel.ts

import { verifyAndGuard } from "../src/admin/update-types.ts";
import { PROMOTE_GUARD_MESSAGES } from "../src/admin/update-apply.ts";
import { compareSemver, isEngineCompatible, loadVerifiedChannel } from "../src/admin/updates.ts";
import { channelFaultStep, classifyUpdateFailStep } from "../src/admin/diag-records.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { hexEncode, utf8 } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";

declare const process: { exit(code?: number): never };

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DEPS = { sha384, hexEncode, isEngineCompatible, compareSemver };
// The driver the guard reads the live version through. It is the only I/O verifyAndGuard does.
const DRIVER = {
  currentLiveVersionId: async (): Promise<string> => "ver-live-1",
  currentLiveVersions: async (): Promise<Array<{ versionId: string; percentage: number }>> => [{ versionId: "ver-live-1", percentage: 100 }],
};

// ---------------------------------------------------------------------------------------------------------
// digest-check / digest-mismatch. THE REAL PRODUCER: verifyAndGuard's verify-before-deploy arm, the one every
// apply and every ramp runs. Its refusal reason flows to the route, which classifies it into the ring.
// ---------------------------------------------------------------------------------------------------------
async function testDigestMismatch(): Promise<void> {
  console.log("\ndigest-check / digest-mismatch: the artefact that does not hash to the signed channel's claim");
  const artefact = utf8("the bytes the CDN actually served");
  const trueHash = hexEncode(await sha384(artefact));

  // THE HONEST PATH FIRST: bytes that DO match must pass the guard and produce no fault at all.
  {
    const g = await verifyAndGuard(DRIVER, {
      recommendedVersion: "0.2.0",
      runningVersion: "0.1.9",
      artefact,
      expectedSha384: trueHash,
      meta: {},
    } as never, PROMOTE_GUARD_MESSAGES, () => {}, DEPS);
    ok("a matching digest passes the guard (nothing is classified, nothing is recorded)", g.ok === true);
  }

  // THE FAULT: the signed channel declares one hash and the CDN served other bytes. The guard REFUSES (nothing
  // is deployed, which is correct and unchanged), and the refusal reason is what the route records from.
  {
    const g = await verifyAndGuard(DRIVER, {
      recommendedVersion: "0.2.0",
      runningVersion: "0.1.9",
      artefact,
      expectedSha384: "0".repeat(96), // the SIGNED channel's claim; the bytes do not hash to it
      meta: {},
    } as never, PROMOTE_GUARD_MESSAGES, () => {}, DEPS);
    ok("the guard refuses and deploys nothing (behaviour unchanged)", g.ok === false);
    const reason = g.ok === false ? g.reason : "";
    ok("the refusal is the product's own verify-mismatch sentence", reason === PROMOTE_GUARD_MESSAGES.verifyMismatch());
    const cls = classifyUpdateFailStep(new Error(reason));
    ok("the update-fault ring records step digest-check", cls.step === "digest-check");
    ok("the update-fault ring records cause digest-mismatch (CDN corruption or tamper, NOT a Cloudflare upload fault)", cls.cause === "digest-mismatch");
  }

  // The two neighbouring verify refusals are the SAME STEP and a different cause: the channel declared no hash
  // at all, so the download cannot be verified. That is a publisher fault, not a mismatch, and calling it one
  // would tell an operator their CDN is corrupting bytes when the release simply shipped without a digest.
  {
    const cls = classifyUpdateFailStep(new Error(PROMOTE_GUARD_MESSAGES.verifyNoHash()));
    ok("a hash-less channel is digest-check, and is NOT reported as a mismatch", cls.step === "digest-check" && cls.cause !== "digest-mismatch");
  }

  // THE REGRESSION THIS EXISTS TO CATCH: these must never fall back to the residual {version-post, other},
  // which is a CLOUDFLARE UPLOAD fault for a release that was never uploaded.
  {
    const cls = classifyUpdateFailStep(new Error(PROMOTE_GUARD_MESSAGES.verifyMismatch()));
    ok("a digest mismatch is NEVER filed as a Cloudflare version-post fault", cls.step !== "version-post");
  }
}

// ---------------------------------------------------------------------------------------------------------
// component `channel` + step `channel-verify`. THE REAL PRODUCER: loadVerifiedChannel, the resolver POST
// /admin/update/apply calls before anything is downloaded. Its failure carries the closed cause the route
// records; until now the type erased it and nothing could ever record the channel leg.
// ---------------------------------------------------------------------------------------------------------
async function testChannelFaults(): Promise<void> {
  console.log("\nchannel / channel-verify: the signed channel that will not verify");
  const never = async (): Promise<Uint8Array | null> => null;

  // KEY-CONFIG: the operator set a channel URL and the pinned signer key is unusable (a truncated paste is the
  // likeliest real cause). The document cannot be TRUSTED, so it is a VERIFY fault, not a fetch one.
  {
    const art = await loadVerifiedChannel({ UPDATE_CHANNEL_URL: "https://updates.example.com/channel.json", UPDATE_SIGNER_PUBLIC: "not-a-key" } as unknown as Env, never);
    ok("a mangled signer key fails the consult", "error" in art);
    const cause = "error" in art ? art.causeClass : "other";
    ok("the closed cause survives the return type (it used to be computed and thrown away)", cause === "key-config");
    ok("it is recorded against the channel-VERIFY step", channelFaultStep(cause) === "channel-verify");
  }

  // URL-CONFIG: the address is wrong. The document never arrives, so it is a FETCH fault. The two are
  // different owners and different questions, and that is the whole reason the step axis exists.
  {
    const art = await loadVerifiedChannel({ UPDATE_CHANNEL_URL: "http://updates.example.com/channel.json", UPDATE_SIGNER_PUBLIC: "AAAA" } as unknown as Env, never);
    ok("a non-https channel URL fails the consult", "error" in art);
    const cause = "error" in art ? art.causeClass : "other";
    ok("the cause is url-config", cause === "url-config");
    ok("it is recorded against the channel-FETCH step", channelFaultStep(cause) === "channel-fetch");
  }

  // AN ENGINE WITH NO UPDATE CHANNEL AT ALL is a CHOICE, not a fault: it must never produce a row. (It still
  // answers an error to the caller -- "updates not configured" -- and that is what the route reports.) The
  // recorder's noise line is drawn at the route, which only records when an apply was actually attempted.
  {
    const art = await loadVerifiedChannel({} as unknown as Env, never);
    ok("an engine with no channel configured still answers honestly", "error" in art);
  }

  // The verify causes map to the verify step, the transport causes to the fetch step. A sig-invalid filed under
  // channel-fetch would send support to the customer's egress for a key-pinning fault.
  ok("sig-invalid is a VERIFY fault", channelFaultStep("sig-invalid") === "channel-verify");
  ok("json-parse (a truncated CDN object that VERIFIED) is a VERIFY fault, not a signature problem", channelFaultStep("json-parse") === "channel-verify");
  ok("shape-invalid (a producer drift) is a VERIFY fault", channelFaultStep("shape-invalid") === "channel-verify");
  ok("a residual transport fault is a FETCH fault", channelFaultStep("other") === "channel-fetch");
}

async function main(): Promise<void> {
  console.log("DEAD-VOCABULARY PRODUCERS: the update pipeline's channel + digest legs\n");
  await testDigestMismatch();
  await testChannelFaults();
  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exit(1);
}

await main();
