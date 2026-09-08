// Validates the sealed control-plane export (src/admin/control-plane-seal.ts): the seal -> open round-trip to
// each recipient, the two-recipient posture, a non-recipient identity failing, body tamper failing, the
// detached-signature verify (+ wrong signer + tampered header), and the no-custody guard. Pure in-memory; no
// DO, no network, no bucket. Run: node test/validate-control-plane-seal.ts

import {
  sealControlPlaneExport,
  openSealedControlPlaneExport,
  signSealedControlPlaneExport,
  verifySealedControlPlaneSignature,
  verifySealedControlPlaneSignatureDetailed,
  isSealedControlPlaneExport,
  serialiseSealedControlPlaneExport,
  buildControlPlaneArtefactToWrite,
  sealedArtefactKey,
  unsealAndResignForAutoHeal,
} from "../src/admin/control-plane-seal.ts";
import { readFileSync } from "node:fs";
import { serialiseControlPlaneExport, verifyControlPlaneSignature, type ControlPlaneExport } from "../src/admin/control-plane.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { concat, b64urlEncode, hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import type { HybridRecipientPrivate } from "../src/crypto/kem.ts";
import type { RecipientEntry } from "../src/format/writer-root.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}
async function throwsAsync(label: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    ok(label, false);
  } catch {
    ok(label, true);
  }
}

// The payload nonce is STREAM_NONCE_SIZE (16 bytes), the size sealStream prepends and openStream reads back.
const nonceFor = (): Uint8Array => crypto.getRandomValues(new Uint8Array(16));

// makeRecipient generates one hybrid recipient (x25519 scalar(32) + ML-KEM seed(64) private; x25519 pub(32) +
// ML-KEM ek(1568) public), exactly as the key ceremony does, and returns the private identity + a RecipientEntry.
function makeRecipient(role: string): { priv: HybridRecipientPrivate; entry: RecipientEntry } {
  const x25519Scalar = crypto.getRandomValues(new Uint8Array(32));
  const mlkemSeed = crypto.getRandomValues(new Uint8Array(64));
  const priv = parseIdentity(concat(x25519Scalar, mlkemSeed));
  const pub = { x25519: x25519PublicFromScalar(x25519Scalar), mlkemEk: mlkemKeygen(mlkemSeed).encapKey };
  return { priv, entry: { role, pub } };
}

function makeExport(): ControlPlaneExport {
  return {
    v: 1,
    exportedAt: "2026-07-05T00:00:00.000Z",
    configVersion: 7,
    configContentHash: "sha384:abc",
    engineAccountId: "acct-source",
    priorAuditHead: { headSeq: 3, headHash: "sha384:head" },
    downpipes: [{ id: "dp-1", name: "prod-kv" }],
    destinations: [{ id: "d1", label: "R2", secret: { reestablish: true } }],
    defaultDestinationId: "d1",
    roles: [{ subject: "oidc:sub", email: "owner@example.com", role: "owner", grantedBy: "boot", grantedAt: "2026-07-05T00:00:00.000Z" }],
    groupRoles: [],
    customRoles: [],
    idpConnections: [{ id: "okta", kind: "oidc", label: "Okta", presetId: "okta", enabled: true, identity: "https://okta.example", clientId: "c1", secretReestablish: true }],
    notifyChannels: [],
    notifyRules: [],
    discovery: null,
    orgPolicy: { requireConfigApproval: false },
    reestablish: ["destination-credentials", "idp-secrets", "session-keys", "passkeys"],
  } as unknown as ControlPlaneExport;
}

function sameExport(a: ControlPlaneExport, b: ControlPlaneExport): boolean {
  return b64urlEncode(serialiseControlPlaneExport(a)) === b64urlEncode(serialiseControlPlaneExport(b));
}

async function main(): Promise<void> {
  const exp = makeExport();
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const other = makeRecipient("break-glass"); // a DIFFERENT identity, not in any seal below

  console.log("control-plane-seal: single-recipient round-trip");
  const sealedBg = await sealControlPlaneExport(exp, [bg.entry], nonceFor);
  ok("seal: v is the sealed layout version", sealedBg.v === 1);
  ok("seal: the header carries exportedAt/configVersion/engineAccountId in plaintext", sealedBg.exportedAt === exp.exportedAt && sealedBg.configVersion === 7 && sealedBg.engineAccountId === "acct-source");
  ok("seal: one recipient descriptor + one capsule wrap", sealedBg.recipients.length === 1 && sealedBg.capsule.length === 1 && sealedBg.recipients[0]!.role === "break-glass");
  // The SEALED BODY (and capsule) must not contain the plaintext of any inner field: prove a distinctive inner
  // value (the downpipe name) is absent from the serialised sealed artefact.
  ok("seal: the sealed artefact does not contain the inner plaintext (downpipe name)", !JSON.stringify(sealedBg).includes("prod-kv") && !JSON.stringify(sealedBg).includes("owner@example.com") && !JSON.stringify(sealedBg).includes("okta.example"));
  const openedBg = await openSealedControlPlaneExport(sealedBg, bg.priv);
  ok("open: the break-glass identity recovers the EXACT inner export", sameExport(openedBg, exp));

  console.log("control-plane-seal: the CONFIG recipient opens the export, and opens nothing else");
  {
    // The point of the config recipient: an engine can recover its own configuration after a Durable Object
    // wipe without holding a key that opens customer archives.
    const cfg = makeRecipient("config");
    const sealedCfg = await sealControlPlaneExport(exp, [bg.entry, cfg.entry], nonceFor);
    ok("the config recipient opens the export", sameExport(await openSealedControlPlaneExport(sealedCfg, cfg.priv), exp));

    // Break-glass stays recipient #0 in every posture, so the offline reader's unseal-export is unaffected
    // and a customer holding only their offline key still recovers their configuration.
    ok("break-glass is still recipient #0 and still opens it", sealedCfg.recipients[0]!.role === "break-glass" && sameExport(await openSealedControlPlaneExport(sealedCfg, bg.priv), exp));

    // The containment that makes this worth doing rather than renaming the problem: a key sealed ONLY to the
    // config recipient must not open an artefact sealed to the operational one. If it did, the "opens its
    // own configuration and nothing else" claim would be false.
    const sealedOpOnly = await sealControlPlaneExport(exp, [op.entry], nonceFor);
    let refused = false;
    try {
      await openSealedControlPlaneExport(sealedOpOnly, cfg.priv);
    } catch {
      refused = true;
    }
    ok("the config key does NOT open an export it is not a recipient of", refused);
  }

  console.log("control-plane-seal: two-recipient posture (break-glass + operational)");
  const sealed2 = await sealControlPlaneExport(exp, [bg.entry, op.entry], nonceFor);
  ok("seal: two recipients, two wraps, roles preserved in order", sealed2.recipients.length === 2 && sealed2.capsule.length === 2 && sealed2.recipients[0]!.role === "break-glass" && sealed2.recipients[1]!.role === "operational");
  ok("open: the break-glass identity opens the two-recipient seal", sameExport(await openSealedControlPlaneExport(sealed2, bg.priv), exp));
  ok("open: the operational identity ALSO opens the two-recipient seal", sameExport(await openSealedControlPlaneExport(sealed2, op.priv), exp));

  console.log("control-plane-seal: a non-recipient identity cannot open");
  await throwsAsync("open: an identity that is not a recipient is refused (no wrap matches)", async () => openSealedControlPlaneExport(sealedBg, other.priv));
  await throwsAsync("open: the operational identity cannot open a break-glass-only seal", async () => openSealedControlPlaneExport(sealedBg, op.priv));

  console.log("control-plane-seal: tamper detection");
  // Flip a character in the sealed body -> the GCM tag fails on open.
  const bodyBytes = [...sealedBg.body];
  bodyBytes[10] = bodyBytes[10] === "A" ? "B" : "A";
  const tamperedBody = { ...sealedBg, body: bodyBytes.join("") };
  await throwsAsync("open: a tampered sealed body is rejected (GCM tag)", async () => openSealedControlPlaneExport(tamperedBody, bg.priv));

  console.log("control-plane-seal: detached signature (verify precedes decrypt)");
  const { b64: signerB64 } = { b64: b64urlEncode(crypto.getRandomValues(new Uint8Array(64))) };
  const signer = await loadSigner(signerB64);
  const verifier = verifierFrom(signer);
  const sig = await signSealedControlPlaneExport(signer, sealedBg);
  ok("sign/verify: a correctly-signed sealed export verifies", await verifySealedControlPlaneSignature(sealedBg, sig, verifier));
  const otherSigner = await loadSigner(b64urlEncode(crypto.getRandomValues(new Uint8Array(64))));
  ok("sign/verify: the WRONG signer fails verification", !(await verifySealedControlPlaneSignature(sealedBg, sig, verifierFrom(otherSigner))));
  const tamperedHeader = { ...sealedBg, configVersion: sealedBg.configVersion + 1 };
  ok("sign/verify: a tampered header fails verification (signature covers the whole object)", !(await verifySealedControlPlaneSignature(tamperedHeader, sig, verifier)));
  ok("sign/verify: the canonical bytes are stable (re-serialise equals)", b64urlEncode(serialiseSealedControlPlaneExport(sealedBg)) === b64urlEncode(serialiseSealedControlPlaneExport(sealedBg)));

  console.log("control-plane-seal: no-custody guard + shape gate");
  // Sealing an export that carries a PLAINTEXT secret must throw (defence in depth), never seal it.
  const leaky = makeExport();
  (leaky.destinations as unknown as Array<Record<string, unknown>>)[0]!.secret = "AKIA-plaintext-should-never-seal";
  await throwsAsync("seal: an export carrying a plaintext secret is REFUSED (no-custody)", async () => sealControlPlaneExport(leaky, [bg.entry], nonceFor));
  await throwsAsync("seal: zero recipients is refused", async () => sealControlPlaneExport(exp, [], nonceFor));
  ok("shape: a real sealed export passes isSealedControlPlaneExport", isSealedControlPlaneExport(sealedBg));
  ok("shape: junk is rejected", !isSealedControlPlaneExport({ v: 1 }) && !isSealedControlPlaneExport(null) && !isSealedControlPlaneExport({ ...sealedBg, capsule: [] }));

  console.log("control-plane-seal: buildControlPlaneArtefactToWrite (the cron's seal-or-plaintext choice)");
  // Sealing OFF (recipients undefined): the SIGNED PLAINTEXT, byte-identical to serialiseControlPlaneExport,
  // and its sig is a plaintext-export signature (verifies via verifyControlPlaneSignature).
  const plain = await buildControlPlaneArtefactToWrite(exp, signer, undefined, nonceFor);
  ok("artefact(off): sealed is false", plain.sealed === false);
  ok("artefact(off): body is the canonical plaintext export (byte-identical)", b64urlEncode(plain.bodyBytes) === b64urlEncode(serialiseControlPlaneExport(exp)));
  ok("artefact(off): the sig verifies as a plaintext-export signature", await verifyControlPlaneSignature(exp, plain.sigText, verifier));
  // The PLAINTEXT branch is the exact bytes control-plane-pass.ts writes UNENCRYPTED to the customer's
  // own destination bucket whenever sealing is off (the default state for a new customer). It must refuse
  // a leaky export exactly as the sealed branch does.
  await throwsAsync(
    "artefact(off): a leaky export is ALSO refused on the PLAINTEXT branch (no-custody)",
    async () => buildControlPlaneArtefactToWrite(leaky, signer, undefined, nonceFor),
  );
  // Parity check: the SEALED branch of this SAME function refuses the same leaky export too (it already did,
  // via sealControlPlaneExport's own internal assertion, but proven here through buildControlPlaneArtefactToWrite
  // itself so both branches of the one decision point are exercised the same way).
  await throwsAsync(
    "artefact(on): a leaky export is refused on the SEALED branch too (parity with the plaintext branch)",
    async () => buildControlPlaneArtefactToWrite(leaky, signer, [bg.entry], nonceFor),
  );
  // Sealing ON (recipients = [break-glass]): the SEALED artefact; its body parses as a sealed export, the sig
  // verifies via the sealed verifier, and opening it recovers the exact inner export.
  const sealedArt = await buildControlPlaneArtefactToWrite(exp, signer, [bg.entry], nonceFor);
  ok("artefact(on): sealed is true", sealedArt.sealed === true);
  const parsedSealed = JSON.parse(new TextDecoder().decode(sealedArt.bodyBytes));
  ok("artefact(on): body parses as a sealed export", isSealedControlPlaneExport(parsedSealed));
  ok("artefact(on): the sig verifies via the SEALED verifier", await verifySealedControlPlaneSignature(parsedSealed, sealedArt.sigText, verifier));
  ok("artefact(on): the sealed body does not leak the inner plaintext", !new TextDecoder().decode(sealedArt.bodyBytes).includes("prod-kv"));
  ok("artefact(on): opening the sealed artefact recovers the exact inner", sameExport(await openSealedControlPlaneExport(parsedSealed, bg.priv), exp));
  ok("key: sealedArtefactKey swaps .json for .sealed.json", sealedArtefactKey("_RECOVERY/CONTROL-PLANE/000000000042-2026-07-05.json") === "_RECOVERY/CONTROL-PLANE/000000000042-2026-07-05.sealed.json");

  console.log("control-plane-seal: the recipient ROLE the CONTROL-PLANE PASS asks for");
  // validate-keys-env.ts proves loadRecipients honours an explicit role. That is only half of it: the helper
  // could be right while the one caller that needs "config" kept using the default. This reads the call site
  // and asserts it asks, which is the half a unit test of the helper cannot reach.
  const passSrc = readFileSync(new URL("../src/cron/control-plane-pass.ts", import.meta.url), "utf8");
  ok(
    "roles: the control-plane pass labels its second recipient CONFIG, not operational",
    /loadRecipients\(\s*env\.BREAK_GLASS_PUBLIC[^)]*env\.CONFIG_RECIPIENT_PUBLIC\s*,\s*"config"\s*\)/.test(passSrc),
  );
  // And the artefact carries whatever role it was given, so the label the pass chooses is the label a
  // holder reads back out of the sealed header without decrypting.
  const cfgOnly = makeRecipient("config");
  const sealedRoles = await sealControlPlaneExport(exp, [bg.entry, cfgOnly.entry], nonceFor);
  ok("roles: the sealed header preserves the roles it was sealed with", sealedRoles.recipients[0]?.role === "break-glass" && sealedRoles.recipients[1]?.role === "config");

  console.log("control-plane-seal: unsealAndResignForAutoHeal (the auto-heal crypto step)");
  // The auto-heal, AFTER verifying the sealed sig, unseals with the CONFIG-RECIPIENT key and re-signs the inner
  // with the engine signer so the DO's plaintext-verify apply-staged accepts it. Prove: the recovered inner
  // matches, AND the re-signed innerSig verifies as a PLAINTEXT-export signature (what the DO re-verifies).
  const seal2 = await sealControlPlaneExport(exp, [bg.entry, op.entry], nonceFor);
  const resolved = await unsealAndResignForAutoHeal(seal2, signer, op.priv);
  ok("autoheal: unseal recovers the exact inner export", sameExport(resolved.exp, exp));
  ok("autoheal: the re-signed innerSig verifies as a PLAINTEXT-export signature (DO-acceptable)", await verifyControlPlaneSignature(resolved.exp, resolved.innerSig, verifier));
  await throwsAsync("autoheal: a non-recipient operational key cannot unseal (throws)", async () => unsealAndResignForAutoHeal(seal2, signer, other.priv));

  console.log("control-plane-seal: bodyHash (the browser-unseal import's cross-check)");
  // bodyHash is sha384:<hex> of the PLAINTEXT bodyBytes, computed BEFORE sealing, riding in the plaintext
  // header so it is covered by the same detached signature as everything else.
  const expectedBodyHash = `sha384:${hexEncode(await sha384(serialiseControlPlaneExport(exp)))}`;
  ok("bodyHash: sealing populates bodyHash with sha384 of the plaintext bodyBytes", sealedBg.bodyHash === expectedBodyHash);
  ok("bodyHash: a DIFFERENT export produces a DIFFERENT bodyHash (it is content-bound, not a constant)", (await sealControlPlaneExport({ ...exp, configVersion: exp.configVersion + 1 }, [bg.entry], nonceFor)).bodyHash !== expectedBodyHash);
  // isSealedControlPlaneExport does NOT require bodyHash (an artefact sealed before this field existed still
  // passes the SHAPE gate); the import-sealed route enforces its presence itself.
  const withoutBodyHash = { ...sealedBg } as Record<string, unknown>;
  delete withoutBodyHash.bodyHash;
  ok("bodyHash: absence does not fail the shape gate (back-compat with older artefacts)", isSealedControlPlaneExport(withoutBodyHash));

  console.log("control-plane-seal: verifySealedControlPlaneSignatureDetailed (the sealed wrapper's split verdict)");
  const sealedSigTxt = await signSealedControlPlaneExport(signer, sealedBg);
  ok("detailed: a genuine sealed signature verifies ok", (await verifySealedControlPlaneSignatureDetailed(sealedBg, sealedSigTxt, verifier)) === "ok");
  ok("detailed: a truncated .sig is sig-decode, not a bare false", (await verifySealedControlPlaneSignatureDetailed(sealedBg, sealedSigTxt.slice(0, 20), verifier)) === "sig-decode");
  const tamperedSealedHeader = { ...sealedBg, exportedAt: "2099-01-01T00:00:00.000Z" };
  ok("detailed: a tampered sealed HEADER fails BOTH halves (signature, the tamper verdict)", (await verifySealedControlPlaneSignatureDetailed(tamperedSealedHeader, sealedSigTxt, verifier)) === "ed25519-mismatch");
  const corruptMldsaVerifier = { ed: verifier.ed, mldsa: (() => { const m = Uint8Array.from(verifier.mldsa); m[5] = m[5]! ^ 0xff; return m; })() };
  ok("detailed: a corrupt ML-DSA half of the verifier is signature-pq, not tamper (the export is intact)", (await verifySealedControlPlaneSignatureDetailed(sealedBg, sealedSigTxt, corruptMldsaVerifier)) === "mldsa-mismatch");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"} validate-control-plane-seal (${failures} failure(s))`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
