// Validate the update channel verification: a channel signed by the pinned release signer
// parses, and a tampered channel or a wrong-signer signature is rejected. Also validates
// that checkUpdates rejects a non-https UPDATE_CHANNEL_URL before fetching, and that it
// does not follow HTTP redirects. Run: node test/validate-updates.ts

import { ed25519 } from "@noble/curves/ed25519.js";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { verifyChannel, checkUpdates, normaliseRiskClass, compareSemver, isEngineCompatible, checkChannelFreshness, loadVerifiedChannel } from "../src/admin/updates.ts";
import { ENGINE_VERSION } from "../src/format/version.ts";
import { hybridSign } from "../src/crypto/sign.ts";
import { concat, utf8, b64urlEncode } from "../src/crypto/bytes.ts";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// CANONICAL_UPDATE_HOST is the ONE host the engine fetches its signed version channel from. The engine
// trusts the PINNED SIGNATURE, not the host (see wrangler.toml "O-1: singular"), and every engine config
// file (wrangler.toml, wrangler.demo.toml) and the deploy ceremony comments use the singular spelling.
// The plural "updates.downpipes.io" once drifted into the external publish tool + design doc; pin the
// singular here so any reintroduction of a divergent host into the engine's own config FAILS the gate
// before a deploy could point UPDATE_CHANNEL_URL at a host the channel is not served on (R3-3).
const CANONICAL_UPDATE_HOST = "update.downpipes.io";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
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

  const channel = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.2.0", artefacts: [{ version: "0.2.0", notes: "perf + fixes" }] }));
  const sig = await hybridSign(edPrivate, mldsa.secretKey, channel);

  const good = await verifyChannel(channel, sig, signer);
  ok("signed channel parses", good !== null && good.recommendedVersion === "0.2.0");

  const tampered = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "9.9.9-evil", artefacts: [] }));
  ok("tampered channel rejected", (await verifyChannel(tampered, sig, signer)) === null);

  const otherMldsa = mldsaKeygen();
  const wrongSigner = { ed: ed25519.getPublicKey(crypto.getRandomValues(new Uint8Array(32))), mldsa: otherMldsa.publicKey };
  ok("wrong-signer rejected", (await verifyChannel(channel, sig, wrongSigner)) === null);

  // Build a minimal env for checkUpdates. The signer public key is ed(32) || mldsa-pub(2592).
  const signerPublicBytes = concat(edPublic, new Uint8Array(mldsa.publicKey));
  const validSignerPublic = b64urlEncode(signerPublicBytes);

  // A fetch stub that always succeeds with a valid signed channel + sig pair.
  const sigB64 = b64urlEncode(sig) + "\n";
  const goodFetch = async (_u: string): Promise<Uint8Array | null> => {
    if (_u.endsWith(".sig")) return utf8(sigB64);
    return channel;
  };

  // V12.3.1 / V1.3.6 -- non-https URLs must be rejected before any network call is made.
  // The fetch stub must not be invoked; the function must return configured:false with a
  // reason that mentions https.
  let fetchCalledHttp = false;
  const rejectingFetch = async (_u: string): Promise<Uint8Array | null> => {
    fetchCalledHttp = true;
    return null;
  };
  const httpResult = await checkUpdates(
    { UPDATE_CHANNEL_URL: "http://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never,
    rejectingFetch,
  );
  ok("http URL rejected (configured:false)", httpResult.configured === false);
  ok("http URL rejected (reason mentions https)", typeof httpResult.reason === "string" && httpResult.reason.includes("https"));
  ok("http URL rejected (fetch not called)", !fetchCalledHttp);

  // Also confirm that an invalid / unparseable URL is rejected cleanly.
  const badUrlResult = await checkUpdates(
    { UPDATE_CHANNEL_URL: "not-a-url", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never,
    rejectingFetch,
  );
  ok("invalid URL rejected (configured:false)", badUrlResult.configured === false);

  // V15.3.2 -- the signed-update fetch must not follow redirects. defaultFetch passes
  // redirect:"manual" to the runtime, which surfaces a 3xx as a non-ok (opaque) response.
  // checkUpdates's injectable fetchUrl lets us simulate that behaviour: the stub returns null
  // (as a 3xx opaque response would via the !r.ok path in defaultFetch), and checkUpdates
  // must surface this as an unfetchable channel, not silently succeed.
  let redirectFetchCalled = false;
  const redirectFetch = async (u: string): Promise<Uint8Array | null> => {
    redirectFetchCalled = true;
    // A real 3xx opaque response is non-ok; defaultFetch returns null for it. Simulate that.
    if (!u.endsWith(".sig")) return null;
    return null;
  };
  const redirectResult = await checkUpdates(
    { UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never,
    redirectFetch,
  );
  ok("redirect-simulated fetch: configured:true (URL was valid https)", redirectResult.configured === true);
  ok("redirect-simulated fetch: verified:false (null body treated as unfetchable)", redirectResult.verified === false);
  ok("redirect-simulated fetch: reason indicates unfetchable channel", typeof redirectResult.reason === "string" && redirectResult.reason.includes("could not fetch"));
  ok("redirect-simulated fetch: stub was actually invoked", redirectFetchCalled);

  // Confirm a valid https URL with a good channel resolves correctly end-to-end.
  const goodResult = await checkUpdates(
    { UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never,
    goodFetch,
  );
  ok("https + valid channel: configured:true", goodResult.configured === true);
  ok("https + valid channel: verified:true", goodResult.verified === true);
  ok("https + valid channel: recommendedVersion matches", goodResult.recommendedVersion === "0.2.0");

  // DP-A follow-up: the LEGACY artefacts[] path hands richMetadataView the raw parse (only the v2
  // components map goes through sanitiseChannelComponents), so the provenance block is sanitised there
  // too. A signed-but-garbled block degrades to ABSENT while the release entry stands; well-typed
  // strings survive; and channelBase resolves to the channel URL's directory.
  const garbledProv = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.3.0", artefacts: [{ version: "0.3.0", provenance: { commit: 42, attestations: [1, 2] } }] }));
  const garbledSig = await hybridSign(edPrivate, mldsa.secretKey, garbledProv);
  const garbledFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(garbledSig) + "\n") : garbledProv);
  const garbledResult = await checkUpdates({ UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never, garbledFetch);
  ok("a garbled legacy provenance block degrades to absent (the entry stands)", garbledResult.verified === true && garbledResult.provenance === undefined && garbledResult.recommendedVersion === "0.3.0");
  const legacyProvChannel = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.3.1", artefacts: [{ version: "0.3.1", provenance: { commit: "c".repeat(40), runId: "77", attestations: { intoto: "provenance/0.3.1/engine.intoto.jsonl" } } }] }));
  const legacyProvSig = await hybridSign(edPrivate, mldsa.secretKey, legacyProvChannel);
  const legacyProvFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(legacyProvSig) + "\n") : legacyProvChannel);
  const legacyProvResult = await checkUpdates({ UPDATE_CHANNEL_URL: "https://example.com/dir/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never, legacyProvFetch);
  ok("a well-typed legacy provenance block survives sanitising", legacyProvResult.provenance?.commit === "c".repeat(40) && legacyProvResult.provenance?.attestations?.intoto === "provenance/0.3.1/engine.intoto.jsonl");
  ok("channelBase is the channel URL's directory", legacyProvResult.channelBase === "https://example.com/dir/");

  // W2: rich SIGNED release metadata. The whole channel is signed (detached hybrid sig), so every new
  // field below inherits that signature and is tamper-evident for free. These prove: a good rich manifest
  // verifies + surfaces the structured metadata; an OLD manifest (no new fields) still parses; riskClass
  // defaults to the safest interpretation; the minEngineVersion compat verdict is computed honestly; and a
  // signature over a DIFFERENT body does not verify the rich channel (tamper still caught).
  // =====================================================================================================

  // ---- compareSemver (the conservative inline util) ----
  ok("semver 0.2.0 > 0.1.0", compareSemver("0.2.0", "0.1.0") === 1);
  ok("semver 0.1.0 < 0.2.0", compareSemver("0.1.0", "0.2.0") === -1);
  ok("semver 0.2 == 0.2.0 (missing component is 0)", compareSemver("0.2", "0.2.0") === 0);
  ok("semver 1.0.0 > 0.9.9", compareSemver("1.0.0", "0.9.9") === 1);
  ok("semver pre-release suffix ignored for ordering", compareSemver("0.2.0-rc.1", "0.2.0") === 0);
  ok("semver non-numeric component => null (uncomparable)", compareSemver("0.x.0", "0.2.0") === null);
  ok("semver too-many-components => null", compareSemver("0.2.0.1", "0.2.0") === null);

  // ---- isEngineCompatible (running >= floor; unparseable => refuse) ----
  ok("compatible: no floor => true", isEngineCompatible("0.1.0", undefined) === true);
  ok("compatible: empty floor => true", isEngineCompatible("0.1.0", "") === true);
  ok("compatible: running == floor => true", isEngineCompatible("0.2.0", "0.2.0") === true);
  ok("compatible: running newer than floor => true", isEngineCompatible("0.3.0", "0.2.0") === true);
  ok("INCOMPATIBLE: running older than floor => false", isEngineCompatible("0.1.0", "0.2.0") === false);
  ok("INCOMPATIBLE: unparseable floor => false (refuse, never allow blind)", isEngineCompatible("0.1.0", "two-point-oh") === false);

  // ---- normaliseRiskClass (safest default; migration is never routine) ----
  ok("riskClass routine honoured", normaliseRiskClass("routine", false) === "routine");
  ok("riskClass migration honoured", normaliseRiskClass("migration", false) === "migration");
  ok("riskClass breaking honoured", normaliseRiskClass("breaking", false) === "breaking");
  ok("riskClass ABSENT => migration (safe default, NOT routine)", normaliseRiskClass(undefined, false) === "migration");
  ok("riskClass unknown string => migration (safe default)", normaliseRiskClass("totally-fine", false) === "migration");
  ok("riskClass routine + requiresMigration => upgraded to migration", normaliseRiskClass("routine", true) === "migration");
  ok("riskClass breaking + requiresMigration stays breaking (no downgrade)", normaliseRiskClass("breaking", true) === "breaking");

  // ---- a GOOD rich manifest verifies + surfaces the structured metadata ----
  const richArtefact = {
    version: "0.2.0",
    url: "https://updates.example.com/engine-0.2.0.mjs",
    sha384: "a".repeat(96),
    riskClass: "migration",
    minEngineVersion: "0.1.0",
    compat: "needs the 0.2 config schema",
    releasedAt: "2026-06-20T00:00:00Z",
    changelog: [{ type: "fix", text: "tighten the seal" }, { type: "security", text: "rotate the canary key" }],
    impact: ["Brief admin blip during promote (seconds).", "No change to backups or restore."],
    requiredSteps: [{ text: "Re-pin LICENCE_SIGNER_PUBLIC after this release.", blocking: true }],
    notes: "freeform fallback",
  };
  const richChannel = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.2.0", artefacts: [richArtefact] }));
  const richSig = await hybridSign(edPrivate, mldsa.secretKey, richChannel);
  const richSigB64 = b64urlEncode(richSig) + "\n";
  const richFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(richSigB64) : richChannel);
  const richResult = await checkUpdates(
    { UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never,
    richFetch,
  );
  ok("rich manifest verifies", richResult.verified === true && richResult.recommendedVersion === "0.2.0");
  ok("rich manifest surfaces riskClass", richResult.riskClass === "migration");
  ok("rich manifest surfaces changelog (2 entries)", Array.isArray(richResult.changelog) && richResult.changelog.length === 2);
  ok("rich manifest surfaces impact", Array.isArray(richResult.impact) && richResult.impact.length === 2);
  ok("rich manifest surfaces requiredSteps (blocking)", Array.isArray(richResult.requiredSteps) && richResult.requiredSteps[0]?.blocking === true);
  ok("rich manifest surfaces minEngineVersion + compat + releasedAt", richResult.minEngineVersion === "0.1.0" && richResult.compat === "needs the 0.2 config schema" && richResult.releasedAt === "2026-06-20T00:00:00Z");
  // The fixture's floor is 0.1.0 and the engine is at or above it, so compatible. Stated from
  // ENGINE_VERSION rather than a typed-in number: this line read "ENGINE_VERSION is 0.1.0" long after the
  // engine had moved to 0.1.9, which is the same hand-typed-and-tied-to-nothing shape that
  // test/validate-version-constants-parity.ts now gates in src/format/version.ts.
  ok(`rich manifest compatible:true (engine ${ENGINE_VERSION} >= floor 0.1.0)`, richResult.compatible === true);

  // ---- a manifest whose minEngineVersion is NEWER than the running engine: compatible:false ----
  const overArtefact = { ...richArtefact, minEngineVersion: "9.9.9" };
  const overChannel = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.2.0", artefacts: [overArtefact] }));
  const overSig = await hybridSign(edPrivate, mldsa.secretKey, overChannel);
  const overFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(overSig) + "\n") : overChannel);
  const overResult = await checkUpdates(
    { UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never,
    overFetch,
  );
  ok("over-minEngineVersion manifest verifies but compatible:false (apply would refuse)", overResult.verified === true && overResult.compatible === false);

  // ---- BACKWARD-COMPATIBLE PARSE: an OLD manifest (no new fields) still parses + verifies ----
  const oldArtefact = { version: "0.2.0", url: "https://x/e.mjs", sha384: "b".repeat(96), notes: "old-style" };
  const oldChannel = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.2.0", artefacts: [oldArtefact] }));
  const oldSig = await hybridSign(edPrivate, mldsa.secretKey, oldChannel);
  const oldFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(oldSig) + "\n") : oldChannel);
  const oldResult = await checkUpdates(
    { UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never,
    oldFetch,
  );
  ok("OLD manifest (no new fields) still parses + verifies", oldResult.verified === true && oldResult.recommendedVersion === "0.2.0");
  ok("OLD manifest keeps notes (lowest-common-denominator)", oldResult.notes === "old-style");
  ok("OLD manifest riskClass defaults to safest (migration), never silently routine", oldResult.riskClass === "migration");
  ok("OLD manifest with no floor is compatible", oldResult.compatible === true);

  // ---- TAMPER: the rich sig over a DIFFERENT body does not verify (rich metadata is signature-covered) ----
  const tamperedRich = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.2.0", artefacts: [{ ...richArtefact, riskClass: "routine" }] }));
  ok("tampering a signed field (riskClass) breaks the signature", (await verifyChannel(tamperedRich, richSig, signer)) === null);

  // ---- CONFIG CONSISTENCY: the update-channel host is the same canonical singular host everywhere ----
  // R3-3: the engine fetches a static signed channel from the host in UPDATE_CHANNEL_URL. wrangler.toml and
  // every other deploy config this tree carries set that var; assert each one uses the canonical singular
  // "update.downpipes.io", and that no plural "updates.downpipes.io" has crept into the engine's own config
  // (the external publish tool + design doc must align to this host, not the other way round). A deploy
  // config this specific tree does not carry (an operator-only environment config kept out of a given
  // clone) is skipped rather than failed: it cannot drift if it is not there to drift.
  const here = fileURLToPath(new URL(".", import.meta.url));
  const readIfPresent = (relPath: string): string | null => {
    try {
      return readFileSync(`${here}../${relPath}`, "utf8");
    } catch {
      return null;
    }
  };
  const channelUrlFrom = (tomlPath: string): string | null => {
    const text = readIfPresent(tomlPath);
    if (text === null) return null;
    const m = text.match(/^\s*UPDATE_CHANNEL_URL\s*=\s*"([^"]+)"/m);
    return m && m[1] !== undefined ? m[1] : null;
  };
  const prodUrl = channelUrlFrom("wrangler.toml");
  ok("wrangler.toml sets UPDATE_CHANNEL_URL", prodUrl !== null);
  const prodHost = prodUrl ? new URL(prodUrl).host : "";
  ok(`prod channel host is the canonical "${CANONICAL_UPDATE_HOST}"`, prodHost === CANONICAL_UPDATE_HOST);
  const otherEnvConfigs = ["wrangler.demo.toml", "wrangler.chaos.toml", "wrangler.internal.toml", "wrangler.uat.toml"];
  for (const envToml of otherEnvConfigs) {
    const envUrl = channelUrlFrom(envToml);
    if (envUrl === null) continue; // not present in this tree; nothing to check for drift
    const envHost = new URL(envUrl).host;
    ok(`${envToml} channel host is the canonical "${CANONICAL_UPDATE_HOST}"`, envHost === CANONICAL_UPDATE_HOST);
    ok(`${envToml} and wrangler.toml update hosts agree (no drift)`, envHost === prodHost);
  }
  // The plural check covers the PUBLISH TOOL as well as the engine's own config: the external publish
  // tool and design doc must align to this host, not the other way round, so the check must cover
  // tools/publish-channel.mjs and not merely the deploy configs. A publish tool documenting the plural
  // host (including in the --url example an operator copies) would let an operator publish a channel
  // whose artefact url points at a host that does not resolve, and every engine applying that update
  // would fail to download the bundle.
  for (const hostFile of ["wrangler.toml", ...otherEnvConfigs, "tools/publish-channel.mjs"]) {
    const text = readIfPresent(hostFile);
    if (text === null) continue; // not present in this tree
    ok(`${hostFile} contains no plural "updates.downpipes.io" host drift`, !/updates\.downpipes\.io/.test(text));
    ok(`${hostFile} names the canonical "${CANONICAL_UPDATE_HOST}"`, text.includes(CANONICAL_UPDATE_HOST));
  }

  // ===================================================================================================
  // R9 -- channel freshness / replay protection (checkChannelFreshness is pure + total). `now` is fixed.
  // ===================================================================================================
  const NOW = Date.parse("2026-06-30T00:00:00Z");
  // No claim at all + no prior state -> ok, no warning (backward-compatible with a freshness-less channel).
  ok("absent claim + no prior state -> ok (no warning)", (() => { const v = checkChannelFreshness({}, {}, NOW); return v.ok === true && v.warn === undefined; })());
  // sequence regresses below the last-seen one -> REJECT (a replay).
  ok("sequence regresses below last-seen -> reject", checkChannelFreshness({ sequence: 4 }, { lastSeq: 5 }, NOW).ok === false);
  // sequence forward -> ok; sequence EQUAL (a same-descriptor retry) -> ok (equal is not a regression).
  ok("sequence forward -> ok", checkChannelFreshness({ sequence: 6 }, { lastSeq: 5 }, NOW).ok === true);
  ok("sequence equal (retry) -> ok (not a regression)", checkChannelFreshness({ sequence: 5 }, { lastSeq: 5 }, NOW).ok === true);
  // sequence present, no prior -> ok (first ever, nothing to compare).
  ok("sequence present, no prior -> ok", checkChannelFreshness({ sequence: 1 }, {}, NOW).ok === true);
  // sequence absent but one was seen before -> ok WITH a weaker-protection warning (never a hard failure).
  {
    const v = checkChannelFreshness({}, { lastSeq: 5 }, NOW);
    ok("sequence absent though seen before -> ok + warning (backward-tolerant)", v.ok === true && /weaker/.test((v as { warn?: string }).warn ?? ""));
  }
  // issuedAt older than the last applied -> REJECT (a replay).
  ok("issuedAt older than last-applied -> reject", checkChannelFreshness({ issuedAt: "2026-05-01T00:00:00Z" }, { lastIssuedAt: "2026-06-01T00:00:00Z" }, NOW).ok === false);
  // issuedAt newer / equal -> ok.
  ok("issuedAt newer than last-applied -> ok", checkChannelFreshness({ issuedAt: "2026-06-15T00:00:00Z" }, { lastIssuedAt: "2026-06-01T00:00:00Z" }, NOW).ok === true);
  ok("issuedAt equal to last-applied -> ok", checkChannelFreshness({ issuedAt: "2026-06-01T00:00:00Z" }, { lastIssuedAt: "2026-06-01T00:00:00Z" }, NOW).ok === true);
  // issuedAt unparseable -> ok WITH a warning (treated as no usable claim, not a hard failure).
  {
    const v = checkChannelFreshness({ issuedAt: "not-a-date" }, { lastIssuedAt: "2026-06-01T00:00:00Z" }, NOW);
    ok("unparseable issuedAt -> ok + warning (ignored, not fatal)", v.ok === true && /unparseable/.test((v as { warn?: string }).warn ?? ""));
  }
  // issuedAt absent though one was seen before -> ok + warning.
  ok("issuedAt absent though seen before -> ok + warning", (() => { const v = checkChannelFreshness({}, { lastIssuedAt: "2026-06-01T00:00:00Z" }, NOW); return v.ok === true && (v as { warn?: string }).warn !== undefined; })());
  // OPT-IN max-age: an issuedAt older than maxAgeMs before now -> REJECT; within the window -> ok; OFF (no
  // maxAgeMs) -> the same old issuedAt is accepted (so it can never false-positive on a dormant channel).
  ok("max-age on: issuedAt older than the window -> reject", checkChannelFreshness({ issuedAt: "2026-01-01T00:00:00Z" }, { maxAgeMs: 30 * 86_400_000 }, NOW).ok === false);
  ok("max-age on: issuedAt within the window -> ok", checkChannelFreshness({ issuedAt: "2026-06-25T00:00:00Z" }, { maxAgeMs: 30 * 86_400_000 }, NOW).ok === true);
  ok("max-age OFF (default): an old issuedAt is accepted (no false-positive on a dormant channel)", checkChannelFreshness({ issuedAt: "2020-01-01T00:00:00Z" }, {}, NOW).ok === true);

  // loadVerifiedChannel ECHOES the (signed) channel freshness claim so the route can enforce + advance it.
  {
    const freshBody = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.2.0", sequence: 9, issuedAt: "2026-06-20T00:00:00Z", artefacts: [{ version: "0.2.0", url: "https://example.com/a.mjs", sha384: "abc123" }] }));
    const freshSig = await hybridSign(edPrivate, mldsa.secretKey, freshBody);
    const freshFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(freshSig) + "\n") : freshBody);
    const resolved = await loadVerifiedChannel({ UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never, freshFetch);
    ok("loadVerifiedChannel echoes the signed sequence + issuedAt", !("error" in resolved) && resolved.sequence === 9 && resolved.issuedAt === "2026-06-20T00:00:00Z");
  }
  // A channel WITHOUT freshness fields still resolves (absent -> echoed as undefined, backward-compatible).
  {
    const plainBody = utf8(JSON.stringify({ channel: "stable", recommendedVersion: "0.2.0", artefacts: [{ version: "0.2.0", url: "https://example.com/a.mjs", sha384: "abc123" }] }));
    const plainSig = await hybridSign(edPrivate, mldsa.secretKey, plainBody);
    const plainFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(plainSig) + "\n") : plainBody);
    const resolved = await loadVerifiedChannel({ UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never, plainFetch);
    ok("loadVerifiedChannel on a freshness-less channel -> resolves, claim absent", !("error" in resolved) && resolved.sequence === undefined && resolved.issuedAt === undefined);
  }

  // ===================================================================================================
  // Multi-component updates (channel schema v2): UpdateStatus.components is the additive per-component
  // status view. Non-secret metadata ONLY (never a url or hash, the richMetadataView discipline);
  // updateAvailable is computed for the ENGINE row only (the engine cannot know the console's running
  // version -- the console SPA compares its own baked version client-side); a malformed components map
  // never breaks engine-only reading. Compat vectors live in validate-channel-v2-compat.ts; these cover
  // the status projection.
  // ===================================================================================================
  {
    const v2 = {
      channel: "stable",
      recommendedVersion: "0.9.0",
      artefacts: [{ version: "0.9.0", url: "https://x/e.mjs", sha384: "c".repeat(96), riskClass: "routine", notes: "engine mirror" }],
      components: {
        engine: { kind: "worker-module", version: "0.9.0", url: "https://x/e.mjs", sha384: "c".repeat(96), riskClass: "routine" },
        console: { kind: "static-assets", version: "0.4.0", url: "https://x/c.json", sha384: "d".repeat(96), minEngineVersion: "0.9.0", compat: "needs the 0.9 engine API", notes: "console fixes", changelog: [{ type: "fix", text: "sharper tables" }] },
      },
    };
    const v2Bytes = utf8(JSON.stringify(v2));
    const v2Sig = await hybridSign(edPrivate, mldsa.secretKey, v2Bytes);
    const v2Fetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(v2Sig) + "\n") : v2Bytes);
    const v2Env = { UPDATE_CHANNEL_URL: "https://example.com/channel.json", UPDATE_SIGNER_PUBLIC: validSignerPublic } as never;
    const s = await checkUpdates(v2Env, v2Fetch);
    ok("a v2 channel verifies and surfaces the components view", s.verified === true && s.components !== undefined);
    const engineRow = s.components?.engine;
    const consoleRow = s.components?.console;
    ok("the engine row carries kind + its own version + updateAvailable (engine knows itself)", engineRow?.kind === "worker-module" && engineRow?.recommendedVersion === "0.9.0" && engineRow?.updateAvailable === true);
    ok("the console row NEVER carries updateAvailable (the engine cannot know the console's running version)", consoleRow !== undefined && !("updateAvailable" in consoleRow));
    ok("the console row surfaces the non-secret metadata (minEngineVersion/compat/notes/changelog)", consoleRow?.minEngineVersion === "0.9.0" && consoleRow?.compat === "needs the 0.9 engine API" && consoleRow?.notes === "console fixes" && Array.isArray(consoleRow?.changelog));
    ok("a component without a riskClass reads as the SAFEST class, never silently routine", consoleRow?.riskClass === "migration");
    const serialised = JSON.stringify(s.components);
    ok("the status view leaks NO url and NO hash (richMetadataView's discipline)", !serialised.includes("url") && !serialised.includes("sha384") && !serialised.includes("https://x/"));
    // The safe-apply resolver: the SAME verified document resolves the engine artefact (prefer
    // components.engine) AND offers the console component with its url + sha for the apply path only.
    const resolved = await loadVerifiedChannel(v2Env, v2Fetch);
    ok("loadVerifiedChannel resolves the console component (url + sha ride on the APPLY path only)", !("error" in resolved) && resolved.console?.version === "0.4.0" && resolved.console?.sha384 === "d".repeat(96));
    // An engine row that matches the RUNNING engine reads updateAvailable:false.
    const currentDoc = { ...v2, components: { ...v2.components, engine: { kind: "worker-module", version: ENGINE_VERSION, url: "https://x/e.mjs", sha384: "c".repeat(96) } } };
    const curBytes = utf8(JSON.stringify(currentDoc));
    const curSig = await hybridSign(edPrivate, mldsa.secretKey, curBytes);
    const curFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(curSig) + "\n") : curBytes);
    const curStatus = await checkUpdates(v2Env, curFetch);
    ok("an engine row at the running version reads updateAvailable:false", curStatus.components?.engine?.updateAvailable === false);
    // A console entry of the WRONG kind is never offered for apply, with the honest issue.
    const wrongKind = { ...v2, components: { ...v2.components, console: { kind: "worker-module", version: "0.4.0", url: "https://x/c.json", sha384: "d".repeat(96) } } };
    const wkBytes = utf8(JSON.stringify(wrongKind));
    const wkSig = await hybridSign(edPrivate, mldsa.secretKey, wkBytes);
    const wkFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(wkSig) + "\n") : wkBytes);
    const wkResolved = await loadVerifiedChannel(v2Env, wkFetch);
    ok("a wrong-kind console entry resolves consoleIssue, never a deployable component", !("error" in wkResolved) && wkResolved.console === undefined && /kind/.test(wkResolved.consoleIssue ?? ""));
    // A MALFORMED components map is treated as absent: status stays verified with no components view.
    const malformed = { channel: "stable", recommendedVersion: "0.9.0", artefacts: v2.artefacts, components: "garbage" };
    const mBytes = utf8(JSON.stringify(malformed));
    const mSig = await hybridSign(edPrivate, mldsa.secretKey, mBytes);
    const mFetch = async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? utf8(b64urlEncode(mSig) + "\n") : mBytes);
    const mStatus = await checkUpdates(v2Env, mFetch);
    ok("a malformed components map reads as absent (verified engine-only status, nothing broken)", mStatus.verified === true && mStatus.components === undefined && mStatus.recommendedVersion === "0.9.0");
  }

  console.log(failures === 0 ? "\nUPDATE CHANNEL VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
