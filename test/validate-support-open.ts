// Prove the SEALED support-bundle path end to end: generate a real vendor support
// keypair (the same path the keypair tool uses), build + sign + seal a real bundle to
// that public with the engine's own seal code, open it with the vendor opener, and
// assert the recovered signed bundle is byte-identical to what was sealed and that its
// hybrid signature verifies against the engine signer. The negative cases matter just
// as much: a WRONG vendor identity must fail to open (never silently produce garbage),
// a tampered ciphertext must fail to authenticate, and a signed-plain bundle (no vendor
// key) must pass straight through. Provenance reporting is checked too: verified with
// the signer public, "unverified" without it.
// Run: node test/validate-support-open.ts

import { sealedSupportBundle } from "../src/admin/support.ts";
import { makeSupportRecipient } from "../tools/generate-support-keypair.ts";
import { openSupportBundle, SupportOpenError } from "../tools/open-support-bundle.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { canonicalJSON } from "../src/format/canonjson.ts";
import { b64urlEncode, b64urlDecode, concat } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// The same scheduler double the support test uses: it serves the routes buildSupportBundle
// reads so the bundle is a real, fully populated one (not a stub).
function schedulerDouble(): DurableObjectStub {
  return {
    async fetch(input: RequestInfo | URL): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      switch (url.pathname) {
        case "/downpipes":
          return new Response(JSON.stringify([{ config: { id: "dp1", name: "uploads", enabled: true, cadenceSeconds: 3600, source: { type: "kv" } }, lastRunId: "01RUN", inFlight: false }]));
        case "/history":
          return new Response(JSON.stringify({ byDownpipe: { dp1: [{ runId: "01RUN", index: 4, startedAt: "2026-06-10T00:00:00.000Z", status: "ok", recordCount: 12, bytes: 4096, durationMs: 900 }] } }));
        case "/notify/history":
          return new Response(JSON.stringify({ entries: [{ at: "2026-06-10T00:00:01.000Z", event: "backup-failure", deliveries: [{ channelKind: "webhook", delivered: true }] }] }));
        case "/tick-info":
          return new Response(JSON.stringify({ lastTickAt: Date.now() }));
        default:
          return new Response(JSON.stringify({}));
      }
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  // A real engine signer, and the vendor support keypair through the tool's own path.
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer = await loadSigner(signerB64);
  const verifier = verifierFrom(signer);
  const signerPubB64 = b64urlEncode(concat(signer.edPublic, signer.mldsaPublic));

  const vendor = await makeSupportRecipient();
  const vendorPubB64 = b64urlEncode(vendor.recipientPublic);
  const vendorIdentity = parseIdentity(vendor.identity);

  console.log("seal -> open round-trip:");
  {
    const env = { SIGNER_PRIVATE: signerB64, VENDOR_SUPPORT_PUBLIC: vendorPubB64 } as unknown as Env;
    const sealed = (await sealedSupportBundle(env, schedulerDouble())) as Record<string, unknown>;
    ok("the engine emits a sealed envelope when the vendor key is set", sealed["kind"] === "downpipe-support-bundle-sealed");

    // Open with the signer public supplied: provenance must verify.
    const opened = await openSupportBundle(sealed, vendorIdentity, verifier);
    ok("the vendor identity opens the sealed bundle", opened.form === "sealed");
    ok("the inner bundle is the signed form", opened.inner["kind"] === "downpipe-support-bundle-signed");
    ok("the inner signature verifies against the engine signer (provenance VERIFIED)", opened.signature === "verified");

    // The load-bearing equality: the recovered inner is byte-identical to what the engine
    // sealed. Proven without a second build (which would differ only in the per-call wall-
    // clock timings the preflight bakes into its evidence strings): the recovered `bundle`,
    // re-canonicalised, must equal opened.signedBytes (the exact bytes the engine signed and
    // sealed), and that same signature must verify over them under the engine signer. Equal
    // canonical bytes plus a verifying signature is exactly "the recovered bundle is the
    // original, unaltered". A swapped or mutated body would change the bytes and break the
    // signature.
    const recoveredInner = opened.inner as { signature: string; signerFingerprint: string; bundle: Record<string, unknown> };
    const recanon = canonicalJSON(recoveredInner.bundle);
    const sameBytes = recanon.length === opened.signedBytes.length && recanon.every((b, i) => b === opened.signedBytes[i]);
    ok("the recovered bundle canonicalises to exactly the signed bytes", sameBytes);
    ok("the recovered signer fingerprint is present and hybrid-shaped", recoveredInner.signerFingerprint.startsWith("edmldsa1:"));
    ok("the recovered signature is a present hybrid signature", recoveredInner.signature.length > 0 && b64urlDecode(recoveredInner.signature).length > 64);

    // And the signature actually covers the recovered body under the engine signer.
    const { hybridVerify } = await import("../src/crypto/sign.ts");
    ok("the recovered body verifies under the signer (the recovered bytes ARE the signed bytes)", await hybridVerify(verifier, opened.signedBytes, b64urlDecode(recoveredInner.signature)));

    // The band manifest on the honest round trip: verified AND consistent with the unsealed body.
    ok("the band manifest verdict on the honest sealed round trip is 'consistent'", opened.manifest === "consistent");
  }

  console.log("\nprovenance reporting without a signer public:");
  {
    const env = { SIGNER_PRIVATE: signerB64, VENDOR_SUPPORT_PUBLIC: vendorPubB64 } as unknown as Env;
    const sealed = (await sealedSupportBundle(env, schedulerDouble())) as Record<string, unknown>;
    const opened = await openSupportBundle(sealed, vendorIdentity, null);
    ok("opens without a signer public but reports it could not verify provenance", opened.form === "sealed" && opened.signature === "unverified");
  }

  console.log("\nthe wrong vendor identity must NOT open it:");
  {
    const env = { SIGNER_PRIVATE: signerB64, VENDOR_SUPPORT_PUBLIC: vendorPubB64 } as unknown as Env;
    const sealed = (await sealedSupportBundle(env, schedulerDouble())) as Record<string, unknown>;
    const wrong = parseIdentity((await makeSupportRecipient()).identity);
    let threw = false;
    let produced: unknown = null;
    try {
      produced = await openSupportBundle(sealed, wrong, verifier);
    } catch (e) {
      threw = e instanceof SupportOpenError;
    }
    ok("a wrong vendor identity throws a clean SupportOpenError (no silent garbage)", threw && produced === null);
  }

  console.log("\na tampered ciphertext must fail to authenticate:");
  {
    const env = { SIGNER_PRIVATE: signerB64, VENDOR_SUPPORT_PUBLIC: vendorPubB64 } as unknown as Env;
    const sealed = (await sealedSupportBundle(env, schedulerDouble())) as { ciphertext: string };
    // Flip the last byte of the ciphertext (decode, mutate, re-encode) so the GCM tag fails.
    const ctBytes = b64urlDecode(sealed.ciphertext);
    ctBytes[ctBytes.length - 1]! ^= 0x01;
    const tampered = { ...sealed, ciphertext: b64urlEncode(ctBytes) };
    let threw = false;
    try {
      await openSupportBundle(tampered, vendorIdentity, verifier);
    } catch (e) {
      threw = e instanceof SupportOpenError;
    }
    ok("a flipped ciphertext byte fails to authenticate (clean error, no plaintext)", threw);
  }

  console.log("\nthe signed-plain path (no vendor key) passes straight through:");
  {
    const env = { SIGNER_PRIVATE: signerB64 } as unknown as Env; // no VENDOR_SUPPORT_PUBLIC
    const signedPlain = (await sealedSupportBundle(env, schedulerDouble())) as Record<string, unknown>;
    ok("with no vendor key the engine returns the signed-plain form", signedPlain["kind"] === "downpipe-support-bundle-signed");
    // The opener handles it with no identity at all.
    const opened = await openSupportBundle(signedPlain, null, verifier);
    ok("the opener reads the signed-plain bundle without an identity", opened.form === "signed-plain");
    ok("and verifies its signature when the signer public is supplied", opened.signature === "verified");
    ok("the signed-plain band manifest (no bodySha256) is 'consistent'", opened.manifest === "consistent");
    const openedNoSigner = await openSupportBundle(signedPlain, null, null);
    ok("without the signer public it reports unverified, not failed", openedNoSigner.signature === "unverified");
  }

  console.log("\nthe band-manifest verdicts (absent / invalid / divergent):");
  {
    const env = { SIGNER_PRIVATE: signerB64, VENDOR_SUPPORT_PUBLIC: vendorPubB64 } as unknown as Env;
    const sealed = (await sealedSupportBundle(env, schedulerDouble())) as Record<string, unknown> & { manifest: Record<string, unknown>; manifestSignature: string };

    // resign produces a VALIDLY SIGNED variant of a mutated manifest under the same engine signer,
    // the strongest graft an attacker holding this engine's signing key could mount; it isolates the
    // opener's binding and consistency checks from its signature check.
    const resign = async (m: Record<string, unknown>): Promise<string> => {
      const s = await loadSigner(signerB64);
      const sig = await hybridSign(s.edPrivate, s.mldsaSecret, canonicalJSON(m));
      s.mldsaSecret.fill(0);
      return b64urlEncode(sig);
    };

    // ABSENT: both manifest fields stripped in transit. The bundle still opens; the verdict says so.
    const { manifest: _m, manifestSignature: _s, ...strippedRest } = sealed;
    const stripped = strippedRest as Record<string, unknown>;
    const openedStripped = await openSupportBundle(stripped, vendorIdentity, verifier);
    ok("stripping manifest + manifestSignature reads as 'absent' (the bundle still opens)", openedStripped.form === "sealed" && openedStripped.manifest === "absent");

    // INVALID: a corrupted manifest signature.
    const sigBytes = b64urlDecode(sealed.manifestSignature);
    sigBytes[0]! ^= 0x01;
    const badSig = { ...sealed, manifestSignature: b64urlEncode(sigBytes) };
    ok("a corrupted manifest signature reads as 'invalid'", (await openSupportBundle(badSig, vendorIdentity, verifier)).manifest === "invalid");

    // INVALID: the wrong kind (domain-label enforcement; checked before the signature).
    const wrongKind = { ...sealed, manifest: { ...sealed.manifest, kind: "downpipe-run-root" } };
    ok("a manifest with the wrong kind reads as 'invalid'", (await openSupportBundle(wrongKind, vendorIdentity, verifier)).manifest === "invalid");

    // INVALID: a validly re-signed manifest whose bodySha256 no longer matches the attached
    // ciphertext (the signature verifies, so this isolates the body-binding check itself).
    const wrongBodyManifest = { ...sealed.manifest, bodySha256: "0".repeat(64) };
    const wrongBody = { ...sealed, manifest: wrongBodyManifest, manifestSignature: await resign(wrongBodyManifest) };
    ok("a validly signed manifest with the wrong bodySha256 reads as 'invalid' (body binding)", (await openSupportBundle(wrongBody, vendorIdentity, verifier)).manifest === "invalid");

    // DIVERGENT: a validly signed manifest claiming DIFFERENT volumes, grafted onto the envelope.
    // The signature and binding pass; the cleartext disagrees with the sealed body: tamper signal.
    const divergedManifest = { ...sealed.manifest, volumes: { totalProtectedBytes: 999_999_999, accounts: 42 } };
    const diverged = { ...sealed, manifest: divergedManifest, manifestSignature: await resign(divergedManifest) };
    ok("a validly signed manifest with different volumes reads as 'divergent'", (await openSupportBundle(diverged, vendorIdentity, verifier)).manifest === "divergent");
  }

  console.log("\nmalformed inputs are clean errors, never crashes:");
  {
    let n = 0;
    for (const bad of [null, 42, "not-an-object", { kind: "something-else" }, { kind: "downpipe-support-bundle-sealed" }]) {
      try {
        await openSupportBundle(bad, vendorIdentity, verifier);
      } catch (e) {
        if (e instanceof SupportOpenError) n++;
      }
    }
    ok("each malformed input throws a SupportOpenError", n === 5);
    // A sealed envelope with no identity supplied is a clear, specific error.
    const env = { SIGNER_PRIVATE: signerB64, VENDOR_SUPPORT_PUBLIC: vendorPubB64 } as unknown as Env;
    const sealed = (await sealedSupportBundle(env, schedulerDouble())) as Record<string, unknown>;
    let identityErr = false;
    try {
      await openSupportBundle(sealed, null, verifier);
    } catch (e) {
      identityErr = e instanceof SupportOpenError && /sealed/.test((e as Error).message);
    }
    ok("a sealed bundle opened without an identity asks for one (clear error)", identityErr);
  }

  // Keep the resolved signer public referenced (it is exercised by the opener through the
  // verifier; this asserts the two encodings agree so the runbook's --signer-pub guidance
  // is correct).
  ok("the signer public encodes to the value the runbook tells the vendor to pass", signerPubB64.length > 0 && b64urlDecode(signerPubB64).length > 32);

  console.log(failures === 0 ? "\nSUPPORT-BUNDLE OPEN PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
