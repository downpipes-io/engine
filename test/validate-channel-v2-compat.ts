// P0 SCHEMA-LOCK COMPAT VECTORS for channel schema v2 (multi-component updates). A v2 channel document
// adds a top-level `components` map (per-component release entries: engine, console, ...) while keeping
// `artefacts[]` EXACTLY as today, dual-written with the engine's entry, FOREVER. These vectors prove the
// v2 document is invisible-but-valid to the 0.1.x reading path that every deployed engine runs:
//   (a) verifyChannel / isChannelShape accept a v2 document (unknown top-level fields are ignored);
//   (b) the legacy selection (artefacts.find(a => a.version === recommendedVersion)) still picks the
//       ENGINE artefact from a v2 document;
//   (c) `components` is invisible to the legacy path (no console entry can ever be selected from
//       artefacts[], because console entries are never placed there);
//   (d) the FORBIDDEN pattern is documented executable: a console entry placed INSIDE artefacts[] with
//       the recommended version WOULD be selected by a deployed 0.1.x engine and its console bytes
//       deployed onto the engine script (the sha384 would verify -- it is the console bundle's true
//       hash -- so only the canary would save the customer). artefacts[] is ENGINE-ONLY, FOREVER; the
//       matching invariant comment lives in src/admin/updates.ts.
// Run: node test/validate-channel-v2-compat.ts

import { ed25519 } from "@noble/curves/ed25519.js";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { verifyChannel, checkUpdates, loadVerifiedChannel, type Channel, type Artefact } from "../src/admin/updates.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { concat, utf8, b64urlEncode } from "../src/crypto/bytes.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// legacySelect is the EXACT selection formula the deployed 0.1.x engines run (updates.ts:
// checkUpdates and loadVerifiedChannel both select artefacts.find(a => a.version === recommendedVersion)).
// It is restated here verbatim so these vectors keep proving the LEGACY path's behaviour against a v2
// document even after the shipped resolver learns to prefer `components` (the legacy formula is frozen
// in every already-deployed engine; this file is its executable memory).
function legacySelect(channel: Channel): Artefact | undefined {
  return channel.artefacts?.find((a) => a.version === channel.recommendedVersion);
}

const ENGINE_URL = "https://update.example.com/engine-0.9.0.mjs";
const ENGINE_SHA = "a".repeat(96);
const CONSOLE_URL = "https://update.example.com/console-0.9.0.json";
const CONSOLE_SHA = "b".repeat(96);

async function main(): Promise<void> {
  // The pinned hybrid release signer (same construction as validate-updates.ts).
  const edSeed = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(edSeed);
  const edPrivate = await crypto.subtle.importKey(
    "pkcs8",
    concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), edSeed),
    "Ed25519",
    false,
    ["sign"],
  );
  const mldsa = mldsaKeygen();
  const signer = { ed: edPublic, mldsa: mldsa.publicKey };
  const signerPublic = b64urlEncode(concat(edPublic, new Uint8Array(mldsa.publicKey)));

  // ---- the CANONICAL v2 fixture: components (engine + console) + the artefacts[] engine mirror ----
  const v2Doc = {
    channel: "stable",
    recommendedVersion: "0.9.0",
    sequence: 3,
    issuedAt: "2026-07-01T00:00:00Z",
    // ENGINE ONLY, FOREVER: exactly today's shape, one mirrored engine entry.
    artefacts: [
      { version: "0.9.0", url: ENGINE_URL, sha384: ENGINE_SHA, mainModule: "index.js", riskClass: "routine", notes: "engine mirror" },
    ],
    // NEW in v2: the per-component release map (ignored by 0.1.x engines; proven below).
    components: {
      engine: { kind: "worker-module", version: "0.9.0", url: ENGINE_URL, sha384: ENGINE_SHA, mainModule: "index.js", riskClass: "routine" },
      console: { kind: "static-assets", version: "0.9.0", url: CONSOLE_URL, sha384: CONSOLE_SHA, riskClass: "routine", minEngineVersion: "0.1.0" },
    },
  };
  const v2Bytes = utf8(JSON.stringify(v2Doc));
  const v2Sig = await hybridSign(edPrivate, mldsa.secretKey, v2Bytes);

  // (a) verifyChannel (signature + isChannelShape) accepts the v2 document.
  const parsed = await verifyChannel(v2Bytes, v2Sig, signer);
  ok("(a) verifyChannel accepts a v2 document (components is a tolerated top-level field)", parsed !== null);
  ok("(a) the v2 document parses with the existing channel/recommendedVersion contract", parsed?.channel === "stable" && parsed?.recommendedVersion === "0.9.0");

  // (b) the legacy selection formula picks the ENGINE artefact from the v2 document.
  const legacyPick = parsed ? legacySelect(parsed) : undefined;
  ok("(b) legacy artefacts.find selects the ENGINE mirror (url is the engine bundle)", legacyPick?.url === ENGINE_URL && legacyPick?.sha384 === ENGINE_SHA);
  ok("(b) the legacy pick carries the engine mainModule, never a console field", legacyPick?.mainModule === "index.js");

  // (c) components is INVISIBLE to the legacy path: the console entry exists only in `components`,
  // so no formula over artefacts[] can ever return console bytes.
  ok("(c) no artefacts[] entry carries the console url (console rides only in components)", (parsed?.artefacts ?? []).every((a) => a.url !== CONSOLE_URL));
  const fetchV2 = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(v2Sig) + "\n") : v2Bytes);
  const env = { UPDATE_CHANNEL_URL: "https://example.com/stable.json", UPDATE_SIGNER_PUBLIC: signerPublic } as never;
  const status = await checkUpdates(env, fetchV2);
  ok("(c) checkUpdates verifies the v2 document and reports the release version", status.verified === true && status.recommendedVersion === "0.9.0");
  const resolved = await loadVerifiedChannel(env, fetchV2);
  ok("(c) loadVerifiedChannel resolves the ENGINE artefact from the v2 document (url + sha are the engine's)", !("error" in resolved) && resolved.artefact.url === ENGINE_URL && resolved.artefact.sha384 === ENGINE_SHA);
  ok("(c) the v2 freshness fields still ride through (sequence + issuedAt echoed)", !("error" in resolved) && resolved.sequence === 3 && resolved.issuedAt === "2026-07-01T00:00:00Z");

  // ---- (d) THE FORBIDDEN PATTERN, demonstrated so it stays refused at publish time ----------------
  // A console entry placed INSIDE artefacts[] with version === recommendedVersion. A deployed 0.1.x
  // engine would SELECT it (same version string), download the console bundle, verify its sha384 (which
  // matches -- it is the console file's true hash) and deploy console bytes onto the ENGINE script; only
  // the canary would then save the customer. This vector EXECUTES the hazard so the invariant is not a
  // comment but a proof: artefacts[] is engine-only, forever; console artefacts ride ONLY in components.
  const forbiddenDoc = {
    channel: "stable",
    recommendedVersion: "0.9.0",
    artefacts: [
      // WRONG: a console entry in artefacts[] (never publish this shape).
      { version: "0.9.0", url: CONSOLE_URL, sha384: CONSOLE_SHA, notes: "console bundle -- FORBIDDEN placement" },
    ],
  };
  const forbiddenBytes = utf8(JSON.stringify(forbiddenDoc));
  const forbiddenSig = await hybridSign(edPrivate, mldsa.secretKey, forbiddenBytes);
  const forbiddenParsed = await verifyChannel(forbiddenBytes, forbiddenSig, signer);
  const forbiddenPick = forbiddenParsed ? legacySelect(forbiddenParsed) : undefined;
  ok("(d) FORBIDDEN pattern demonstrated: a console entry in artefacts[] WOULD be selected by 0.1.x (the hazard is real, so the placement rule is load-bearing)", forbiddenPick?.url === CONSOLE_URL);

  // ---- fail-safe: a MALFORMED components map must not break engine-only reading -------------------
  // (components: a non-object, or entries that are not objects). The v2 shape rule treats a malformed
  // map as ABSENT (with a logged warning), so the engine path below must still verify + resolve the
  // engine artefact from artefacts[]. This holds for 0.1.x (which never reads components) AND for the
  // new resolver (which sanitises it to absent).
  for (const [label, badComponents] of [
    ["components is a string", "not-a-map"],
    ["components is an array", [1, 2, 3]],
    ["a component entry is not an object", { engine: "nope" }],
    ["a component entry has no version", { engine: { kind: "worker-module", url: ENGINE_URL } }],
  ] as const) {
    const badDoc = { channel: "stable", recommendedVersion: "0.9.0", artefacts: v2Doc.artefacts, components: badComponents };
    const badBytes = utf8(JSON.stringify(badDoc));
    const badSig = await hybridSign(edPrivate, mldsa.secretKey, badBytes);
    const badFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(badSig) + "\n") : badBytes);
    const badParsed = await verifyChannel(badBytes, badSig, signer);
    ok(`(fail-safe) ${label}: the document still verifies + parses`, badParsed !== null);
    const badResolved = await loadVerifiedChannel(env, badFetch);
    ok(`(fail-safe) ${label}: the engine artefact still resolves from artefacts[]`, !("error" in badResolved) && badResolved.artefact.url === ENGINE_URL);
    const badStatus = await checkUpdates(env, badFetch);
    ok(`(fail-safe) ${label}: checkUpdates still verifies (engine-only reading unbroken)`, badStatus.verified === true && badStatus.recommendedVersion === "0.9.0");
  }

  // ---- an OLD (v1) document with no components keeps working through the same paths ----------------
  const v1Doc = { channel: "stable", recommendedVersion: "0.9.0", artefacts: v2Doc.artefacts };
  const v1Bytes = utf8(JSON.stringify(v1Doc));
  const v1Sig = await hybridSign(edPrivate, mldsa.secretKey, v1Bytes);
  const v1Fetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(v1Sig) + "\n") : v1Bytes);
  const v1Resolved = await loadVerifiedChannel(env, v1Fetch);
  ok("(v1 fallback) a components-less document resolves the engine artefact exactly as today", !("error" in v1Resolved) && v1Resolved.artefact.url === ENGINE_URL);

  console.log(failures === 0 ? "\nCHANNEL V2 COMPAT VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
