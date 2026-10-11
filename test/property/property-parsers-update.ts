// Fuzz and property tests for the update channel reader and the config import readers: the pinned
// signer key, the channel document before and after its signature check, the version and freshness helpers,
// the control-plane export shape gates, the no-custody walk, the artefact key parsers, the export signature
// check, the sealed export opener, the key file parsers and the config snapshot decoder.
// Run through: node test/property/property-parsers.ts
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ed25519 } from "@noble/curves/ed25519.js";
import fc from "fast-check";
import { assertNoPlaintextSecretInExport, controlPlaneArtefactKey, isControlPlaneExport, parseControlPlaneArtefactVersion, parseControlPlaneSealedArtefactVersion, scanControlPlaneCandidates, selectLatestControlPlaneExport, selectLatestSealedControlPlaneExport, signControlPlaneExport, verifyControlPlaneSignatureDetailed, type ControlPlaneExport } from "../../src/admin/control-plane.ts";
import { isSealedControlPlaneExport, openSealedControlPlaneExport, type SealedControlPlaneExport } from "../../src/admin/control-plane-seal.ts";
import { decodeConfigSnapshot } from "../../src/admin/restore-cfconfig.ts";
import { UPDATE_CHANNEL_FAULTS, checkUpdates, compareSemver, isEngineCompatible, loadVerifiedChannel, sanitiseChannelComponents, verifyChannelDetailed, versionSkew, type Channel } from "../../src/admin/updates.ts";
import { checkChannelFreshness } from "../../src/admin/update-freshness.ts";
import { parsePinnedUpdateSigner } from "../../src/admin/update-signer-pin.ts";
import { UPDATE_CAUSE_CLASSES } from "../../src/admin/diag-records.ts";
import type { Env } from "../../src/env.d.ts";
import { b64urlDecode, b64urlEncode, concat } from "../../src/crypto/bytes.ts";
import { LABEL_SIGNER_PUBLIC, parseIdentity, parseKeyFile, parseVerifier } from "../../src/crypto/keys.ts";
import { mldsaKeygen } from "../../src/crypto/pq.ts";
import { hybridSign } from "../../src/crypto/sign.ts";
import { assertSafe, assertTotal, jsonValue, mutationOf, prop, quiet, runs, text, utf8 } from "./parser-fuzz-lib.ts";

const here = dirname(fileURLToPath(import.meta.url));
const bytes = fc.uint8Array({ minLength: 0, maxLength: 300 });
const anyString = fc.oneof(fc.string({ maxLength: 60 }), fc.string({ unit: "binary", maxLength: 40 }));
const isErr = (e: Error): boolean => e instanceof Error;

async function signerKeys(): Promise<{ edPrivate: CryptoKey; mldsaSecret: Uint8Array; verifier: { ed: Uint8Array; mldsa: Uint8Array }; pub: string }> {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const edPublic = ed25519.getPublicKey(seed);
  const edPrivate = await crypto.subtle.importKey("pkcs8", concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), seed) as BufferSource, "Ed25519", false, ["sign"]);
  const ml = mldsaKeygen();
  return { edPrivate, mldsaSecret: ml.secretKey, verifier: { ed: edPublic, mldsa: ml.publicKey }, pub: b64urlEncode(concat(edPublic, new Uint8Array(ml.publicKey))) };
}

const GOOD_CHANNEL = { channel: "stable", recommendedVersion: "9.9.9", artefacts: [{ version: "9.9.9", url: "https://update.downpipes.io/engine-9.9.9.mjs", sha384: "a".repeat(96) }] };
// Documents that pass the channel shape gate with every optional field filled by arbitrary JSON.
const hostileChannel = fc.record(
  { artefacts: fc.array(fc.dictionary(fc.constantFrom("version", "url", "sha384", "riskClass", "changelog", "impact", "requiredSteps", "minEngineVersion", "provenance", "notes"), jsonValue), { maxLength: 3 }), components: jsonValue, releases: jsonValue, sequence: jsonValue, issuedAt: jsonValue, extra: jsonValue },
  { requiredKeys: [] },
).map((o) => ({ channel: "stable", recommendedVersion: "9.9.9", ...o }));
const artefactNullish = fc.oneof(fc.constant(null), fc.constant(7), fc.constant("s"));

export async function runUpdateProperties(): Promise<void> {
  const k = await signerKeys();
  const sign = async (b: Uint8Array): Promise<Uint8Array> => hybridSign(k.edPrivate, k.mldsaSecret, b);
  const goodBytes = utf8(JSON.stringify(GOOD_CHANNEL));
  const goodSig = await sign(goodBytes);
  const env = { UPDATE_CHANNEL_URL: "https://update.downpipes.io/channel.json", UPDATE_SIGNER_PUBLIC: k.pub } as unknown as Env;
  const fetcher = (ch: Uint8Array, sigText: Uint8Array) => async (u: string): Promise<Uint8Array | null> => (u.endsWith(".sig") ? sigText : ch);
  const causeSet = new Set<string>(UPDATE_CAUSE_CLASSES);

  console.log("update channel parsers");
  await prop("parsePinnedUpdateSigner: arbitrary text refuses with an Error, and a real key parses", async () => {
    parsePinnedUpdateSigner(k.pub);
    await fc.assert(fc.asyncProperty(anyString, async (s) => void (await assertSafe("parsePinnedUpdateSigner", () => parsePinnedUpdateSigner(s), isErr))), runs(300));
  });
  await prop("verifyChannelDetailed: the good channel verifies; arbitrary bytes and signatures are sig-invalid", async () => {
    const good = await verifyChannelDetailed(goodBytes, goodSig, k.verifier);
    if (!good.ok) throw new Error("the signed good channel did not verify");
    await fc.assert(
      fc.asyncProperty(bytes, bytes, async (b, s) => {
        const r = await assertSafe("verifyChannelDetailed", () => verifyChannelDetailed(b, s, k.verifier));
        if (r.kind === "ok" && (r.value.ok || r.value.cause !== "sig-invalid")) throw new Error("unsigned bytes did not report sig-invalid");
      }),
      runs(60),
    );
  });
  await prop("verifyChannelDetailed: any mutation of the signed bytes or the signature is sig-invalid", async () => {
    await fc.assert(
      fc.asyncProperty(mutationOf(goodBytes), mutationOf(goodSig), fc.boolean(), async (b, s, which) => {
        const changed = which ? Buffer.compare(b, goodBytes) !== 0 : Buffer.compare(s, goodSig) !== 0;
        const r = await assertSafe("verifyChannelDetailed", () => verifyChannelDetailed(which ? b : goodBytes, which ? goodSig : s, k.verifier));
        if (changed && r.kind === "ok" && r.value.ok) throw new Error("a mutated channel or signature verified");
      }),
      runs(40),
    );
  });
  await prop("verifyChannelDetailed: a validly signed document ends in ok, json-parse or shape-invalid, matching its content", async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(bytes, fc.json().map(utf8), jsonValue.map((v) => utf8(JSON.stringify(v))), hostileChannel.map((c) => utf8(JSON.stringify(c)))), async (b) => {
        const r = await assertSafe("verifyChannelDetailed", async () => verifyChannelDetailed(b, await sign(b), k.verifier));
        if (r.kind !== "ok") return;
        let parsed: unknown;
        try {
          parsed = JSON.parse(text(b));
        } catch {
          if (r.value.ok || r.value.cause !== "json-parse") throw new Error("unparseable bytes were not json-parse");
          return;
        }
        const o = parsed as Record<string, unknown> | null;
        const shaped = typeof o === "object" && o !== null && typeof o.channel === "string" && typeof o.recommendedVersion === "string" && o.recommendedVersion !== "" && (o.artefacts === undefined || Array.isArray(o.artefacts));
        if (shaped !== r.value.ok) throw new Error("shape verdict disagrees with the document");
        if (!r.value.ok && r.value.cause !== "shape-invalid") throw new Error("shape failure had the wrong cause");
      }),
      runs(40),
    );
  });
  await prop("checkUpdates: arbitrary channel bytes with a well-formed signature give a closed fault", async () => {
    await fc.assert(
      fc.asyncProperty(bytes, bytes, async (b, s) => {
        const r = await assertSafe("checkUpdates", () => checkUpdates(env, fetcher(b, utf8(b64urlEncode(s)))));
        if (r.kind !== "ok") return;
        if (r.value.verified) throw new Error("an unsigned channel verified");
        if (r.value.channelFault !== undefined && !(UPDATE_CHANNEL_FAULTS as readonly string[]).includes(r.value.channelFault)) throw new Error("fault outside the closed set");
      }),
      runs(40),
    );
  });
  await prop("checkUpdates: a signature file that is not base64url gives sig-invalid, not a thrown Error", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom("!", "not base64url", "a", "abcde", "=", "éééé"), async (sigText) => {
        const r = await assertTotal("checkUpdates", () => checkUpdates(env, fetcher(goodBytes, utf8(sigText))));
        if (r.verified) throw new Error("verified with a garbage signature");
      }),
      runs(10),
    );
  });
  await prop("loadVerifiedChannel: a signature file that is not base64url gives a closed cause, not a thrown Error", async () => {
    await assertTotal("loadVerifiedChannel", () => loadVerifiedChannel(env, fetcher(goodBytes, utf8("not base64url!"))));
  });
  await prop("checkUpdates: a signed good channel reports verified", async () => {
    const r = await checkUpdates(env, fetcher(goodBytes, utf8(b64urlEncode(goodSig))));
    if (!r.verified || r.recommendedVersion !== "9.9.9") throw new Error("the good channel was not reported verified");
  });
  await prop("checkUpdates and loadVerifiedChannel: signed documents with arbitrary optional fields never crash", async () => {
    await quiet(() =>
      fc.assert(
        fc.asyncProperty(hostileChannel, async (c) => {
          const b = utf8(JSON.stringify(c));
          const f = fetcher(b, utf8(b64urlEncode(await sign(b))));
          await assertTotal("checkUpdates", () => checkUpdates(env, f));
          const l = await assertTotal("loadVerifiedChannel", () => loadVerifiedChannel(env, f));
          if ("ok" in l && !l.ok && !causeSet.has(String((l as { cause?: string }).cause ?? "sig-invalid"))) throw new Error("cause outside the closed set");
        }),
        runs(60),
      ),
    );
  });
  await prop("checkUpdates: a signed channel whose artefacts list holds a null or scalar entry reads as a channel, not a crash", async () => {
    await quiet(() =>
      fc.assert(
        fc.asyncProperty(artefactNullish, async (bad) => {
          const b = utf8(JSON.stringify({ ...GOOD_CHANNEL, artefacts: [bad, ...GOOD_CHANNEL.artefacts] }));
          const f = fetcher(b, utf8(b64urlEncode(await sign(b))));
          await assertTotal("checkUpdates", () => checkUpdates(env, f));
        }),
        runs(6),
      ),
    );
  });
  await prop("sanitiseChannelComponents: arbitrary components never throw and keep only well-typed entries", async () => {
    await quiet(() =>
      fc.assert(
        fc.asyncProperty(jsonValue, async (comp) => {
          const r = await assertSafe("sanitiseChannelComponents", () => sanitiseChannelComponents({ ...GOOD_CHANNEL, components: comp } as unknown as Channel), isErr);
          if (r.kind === "ok" && r.value !== undefined) for (const [id, c] of Object.entries(r.value)) if (typeof c.version !== "string" || c.version === "") throw new Error(`entry ${id} kept without a version`);
        }),
        runs(200),
      ),
    );
  });
  await prop("compareSemver, versionSkew and isEngineCompatible: total, antisymmetric and reflexive", async () => {
    const ver = fc.oneof(anyString, fc.tuple(fc.nat(30), fc.nat(30), fc.nat(30)).map((t) => t.join(".")));
    await fc.assert(
      fc.asyncProperty(ver, ver, async (a, b) => {
        const ab = compareSemver(a, b);
        const ba = compareSemver(b, a);
        if ((ab === null) !== (ba === null)) throw new Error("comparable one way only");
        if (ab !== null && ba !== null && ab !== -ba) throw new Error("not antisymmetric");
        if (compareSemver(a, a) !== null && compareSemver(a, a) !== 0) throw new Error("not reflexive");
        versionSkew(a, b);
        isEngineCompatible(a, b);
      }),
      runs(500),
    );
  });
  await prop("checkChannelFreshness: arbitrary claims and states give a closed verdict, and a regression is refused", async () => {
    const num = fc.oneof(fc.integer(), fc.double(), fc.constant(undefined), fc.constant(Number.NaN));
    const iso = fc.oneof(fc.constant(undefined), anyString, fc.date({ min: new Date(0), max: new Date(4e12), noInvalidDate: true }).map((d) => d.toISOString()));
    await fc.assert(
      fc.asyncProperty(num, iso, num, iso, num, async (seq, at, lastSeq, lastAt, maxAge) => {
        const r = await assertSafe("checkChannelFreshness", () => checkChannelFreshness({ sequence: seq as number, ...(at !== undefined ? { issuedAt: at } : {}) }, { lastSeq: lastSeq as number, ...(lastAt !== undefined ? { lastIssuedAt: lastAt } : {}), maxAgeMs: maxAge as number }, 1_800_000_000_000), isErr);
        if (r.kind === "ok" && typeof r.value.ok !== "boolean") throw new Error("verdict is not boolean");
      }),
      runs(500),
    );
    const reg = checkChannelFreshness({ sequence: 4 }, { lastSeq: 9 }, 1_800_000_000_000);
    if (reg.ok) throw new Error("a regressed sequence was accepted");
  });

  console.log("config import parsers");
  const exp = { v: 1, exportedAt: "2026-01-01T00:00:00.000Z", configContentHash: "h", configVersion: 3, downpipes: [], destinations: [], roles: [], priorAuditHead: { seq: 1 } } as unknown as ControlPlaneExport;
  await prop("isControlPlaneExport and isSealedControlPlaneExport: total over arbitrary JSON, and the real shape passes", async () => {
    if (!isControlPlaneExport(exp)) throw new Error("the minimal export failed its own shape gate");
    await fc.assert(
      fc.asyncProperty(jsonValue, async (v) => {
        await assertSafe("isControlPlaneExport", () => isControlPlaneExport(v), isErr);
        await assertSafe("isSealedControlPlaneExport", () => isSealedControlPlaneExport(v), isErr);
      }),
      runs(300),
    );
  });
  await prop("assertNoPlaintextSecretInExport: arbitrary JSON refuses with an Error, and a planted plaintext secret is always refused", async () => {
    const names = ["token", "secretAccessKey", "secret", "externalId", "clientSecret", "routingKey", "sessionKey", "signingKey", "privateKey", "recoveryCode"];
    await fc.assert(
      fc.asyncProperty(jsonValue, fc.constantFrom(...names), fc.string({ minLength: 1, maxLength: 12 }), fc.nat(3), async (v, name, secret, depth) => {
        await assertSafe("assertNoPlaintextSecretInExport", () => assertNoPlaintextSecretInExport(v), isErr);
        let planted: unknown = { [name]: secret };
        for (let i = 0; i < depth; i++) planted = i % 2 === 0 ? { inner: planted, other: v } : [planted, v];
        const r = await assertSafe("assertNoPlaintextSecretInExport", () => assertNoPlaintextSecretInExport(planted), isErr);
        if (r.kind === "ok") throw new Error(`a plaintext ${name} was accepted at depth ${depth}`);
      }),
      runs(300),
    );
  });
  await prop("assertNoPlaintextSecretInExport: a deeply nested export is refused with a domain error, not a stack overflow", async () => {
    let deep: unknown = { token: "" };
    for (let i = 0; i < 200_000; i++) deep = [deep];
    await assertSafe("assertNoPlaintextSecretInExport", () => assertNoPlaintextSecretInExport(deep), isErr);
  });
  await prop("control-plane artefact keys: the builder and both parsers round-trip, and arbitrary key lists are total", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 0, max: 999_999_999_999 }), fc.date({ min: new Date(0), max: new Date(4e12), noInvalidDate: true }), fc.array(fc.oneof(anyString, fc.constantFrom("_RECOVERY/CONTROL-PLANE/000000000001-x.json", "_RECOVERY/CONTROL-PLANE/000000000001-x.json.sig", "_RECOVERY/CONTROL-PLANE/000000000002-y.sealed.json", "_RECOVERY/CONTROL-PLANE/000000000002-y.sealed.json.sig")), { maxLength: 8 }), async (ver, d, keys) => {
        const key = controlPlaneArtefactKey(ver, d.toISOString());
        if (parseControlPlaneArtefactVersion(key) !== ver) throw new Error("plaintext key did not round-trip");
        if (parseControlPlaneSealedArtefactVersion(key.replace(/\.json$/, ".sealed.json")) !== ver) throw new Error("sealed key did not round-trip");
        await assertSafe("selectLatestControlPlaneExport", () => selectLatestControlPlaneExport(keys), isErr);
        await assertSafe("selectLatestSealedControlPlaneExport", () => selectLatestSealedControlPlaneExport(keys), isErr);
        await assertSafe("scanControlPlaneCandidates", () => scanControlPlaneCandidates(keys), isErr);
      }),
      runs(300),
    );
  });
  await prop("verifyControlPlaneSignatureDetailed: the real signature is ok and every changed signature string is a closed non-ok verdict", async () => {
    const sig = await signControlPlaneExport({ edPrivate: k.edPrivate, mldsaSecret: k.mldsaSecret } as never, exp);
    if ((await verifyControlPlaneSignatureDetailed(exp, sig, k.verifier)) !== "ok") throw new Error("the real export signature did not verify");
    const closed = new Set(["ok", "sig-decode", "verifier-invalid", "ed25519-mismatch", "ed25519-only-mismatch", "mldsa-mismatch"]);
    await fc.assert(
      fc.asyncProperty(fc.oneof(anyString, mutationOf(utf8(sig)).map(text)), async (s) => {
        const r = await assertSafe("verifyControlPlaneSignatureDetailed", () => verifyControlPlaneSignatureDetailed(exp, s, k.verifier), isErr);
        if (r.kind === "ok" && (!closed.has(r.value) || (r.value === "ok" && s !== sig))) throw new Error(`unexpected verdict ${String(r.value)}`);
      }),
      runs(60),
    );
  });
  const identity = parseIdentity(b64urlDecode(text(readFileSync(join(here, "..", "vectors", "gzip-codec", "identity.key"))).trim()));
  await prop("openSealedControlPlaneExport: shape-valid sealed exports with arbitrary members refuse with an Error", async () => {
    await fc.assert(
      fc.asyncProperty(fc.array(fc.record({ fingerprint: fc.string({ maxLength: 20 }), kemCiphertext: fc.string({ maxLength: 20 }), sealed: fc.string({ maxLength: 20 }) }), { minLength: 1, maxLength: 2 }), fc.string({ minLength: 1, maxLength: 40 }), async (capsule, body) => {
        const sealed = { v: 1, exportedAt: "x", configVersion: 1, recipients: [], capsule, body } as unknown as SealedControlPlaneExport;
        await assertSafe("openSealedControlPlaneExport", () => openSealedControlPlaneExport(sealed, identity), isErr);
      }),
      runs(200),
    );
  });
  await prop("openSealedControlPlaneExport: a capsule member with missing or non-object fields refuses with a domain error", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom<unknown>([null], [{}], [[]], [{ fingerprint: "f" }], [7]), async (capsule) => {
        const sealed = { v: 1, exportedAt: "x", configVersion: 1, recipients: [], capsule, body: " " } as unknown as SealedControlPlaneExport;
        await assertSafe("openSealedControlPlaneExport", () => openSealedControlPlaneExport(sealed, identity), isErr);
      }),
      runs(10),
    );
  });
  await prop("parseKeyFile and parseVerifier: arbitrary text refuses with an Error", async () => {
    await fc.assert(
      fc.asyncProperty(anyString, bytes, async (s, b) => {
        await assertSafe("parseKeyFile", () => parseKeyFile(s, LABEL_SIGNER_PUBLIC), isErr);
        await assertSafe("parseKeyFile", () => parseKeyFile(`${LABEL_SIGNER_PUBLIC} ${s}`, LABEL_SIGNER_PUBLIC), isErr);
        await assertSafe("parseVerifier", () => parseVerifier(b), isErr);
        await assertSafe("b64urlDecode", () => b64urlDecode(s), isErr);
      }),
      runs(300),
    );
  });
  await prop("decodeConfigSnapshot: JSON text decodes or refuses with an Error, and incomplete markers are refused", async () => {
    await fc.assert(
      fc.asyncProperty(jsonValue, async (v) => {
        const r = await assertSafe("decodeConfigSnapshot", () => decodeConfigSnapshot(utf8(JSON.stringify(v))), isErr);
        const marked = typeof v === "object" && v !== null && !Array.isArray(v) && ("_truncated" in v || "_unavailable" in v);
        if (marked !== (r.kind === "refused")) throw new Error("incomplete-marker check disagrees with the document");
      }),
      runs(300),
    );
  });
  await prop("decodeConfigSnapshot: bytes that are not JSON refuse with a domain error, not a SyntaxError", async () => {
    await fc.assert(fc.asyncProperty(fc.constantFrom("", "{", "not json", "\u0000", "{'a':1}"), async (t) => void (await assertSafe("decodeConfigSnapshot", () => decodeConfigSnapshot(utf8(t)), isErr))), runs(10));
  });
}
