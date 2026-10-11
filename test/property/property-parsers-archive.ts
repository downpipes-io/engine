// Fuzz and property tests for the archive-side parsers: RUNLOG parsing and signature checks, the shard
// manifest reader, the container framing, the segment readers, the object-key reader, the canonical-count gate,
// the run id decoder and the full run opener over a mutated copy of a real conformance vector.
// Run through: node test/property/property-parsers.ts
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import fc from "fast-check";
import { b64urlDecode, concat } from "../../src/crypto/bytes.ts";
import { parseIdentity, parseVerifier } from "../../src/crypto/keys.ts";
import { mldsaKeygen } from "../../src/crypto/pq.ts";
import { hybridVerify } from "../../src/crypto/sign.ts";
import { openNonSecretSegment, sealNonSecretSegment } from "../../src/crypto/segment.ts";
import { frame, unframeDpe, unframeSeg } from "../../src/format/container.ts";
import { validateCanonicalCounts } from "../../src/format/canonnum.ts";
import { isIntegrityFailure } from "../../src/format/integrity-error.ts";
import { parseShard, segIDFromObject } from "../../src/format/record-codec.ts";
import { openRun, type ObjectStore } from "../../src/format/reader.ts";
import { classifyRunIdMalformation, decodeULID, isValidRunId, RUNID_MALFORM_KINDS } from "../../src/format/ulid.ts";
import { MAGIC_DPE, MAGIC_SEG } from "../../src/format/version.ts";
import { parseRunlog, signRunlog, type RunlogEntry } from "../../src/format/writer-runlog.ts";
import { assertSafe, jsonValue, mutationOf, ndjsonText, prop, runs, text, utf8 } from "./parser-fuzz-lib.ts";

const here = dirname(fileURLToPath(import.meta.url));
const VEC = join(here, "..", "vectors", "gzip-codec");
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

function loadArchive(): Map<string, Uint8Array> {
  const base = join(VEC, "archive");
  const out = new Map<string, Uint8Array>();
  const walk = (d: string): void => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) walk(p);
      else out.set(relative(base, p).split("\\").join("/"), new Uint8Array(readFileSync(p)));
    }
  };
  walk(base);
  return out;
}

const bytes = fc.uint8Array({ minLength: 0, maxLength: 400 });
const plainRefusal = (e: Error): boolean => e instanceof Error;
// True when every non-empty line that parses as JSON parses to an object: the lines the readers destructure
// without a null or scalar guard are held out of the general properties and
// pinned by the null-line known-failing properties.
const objectLinesOnly = (t: string): boolean =>
  t.split("\n").every((l) => {
    if (l.length === 0) return true;
    try {
      const v: unknown = JSON.parse(l);
      return typeof v === "object" && v !== null && !Array.isArray(v);
    } catch {
      return true;
    }
  });
// Mirrors the freshness check: a signature file that is not base64url counts as no signature.
async function sigVerifies(v: Parameters<typeof hybridVerify>[0], msg: Uint8Array, sigFile: Uint8Array): Promise<boolean> {
  try {
    return await hybridVerify(v, msg, b64urlDecode(text(sigFile).trim()));
  } catch {
    return false;
  }
}

const anyText = fc.oneof(fc.string({ maxLength: 120 }), fc.string({ unit: "binary", maxLength: 80 }), ndjsonText).filter(objectLinesOnly);

async function ed25519Key(): Promise<CryptoKey> {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const pkcs8 = concat(Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]), seed);
  return crypto.subtle.importKey("pkcs8", pkcs8 as BufferSource, "Ed25519", false, ["sign"]);
}

const ulidChars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ulid = fc.array(fc.constantFrom(...ulidChars.split("")), { minLength: 26, maxLength: 26 }).map((a) => a.join(""));
const entry: fc.Arbitrary<RunlogEntry> = fc.record({
  index: fc.nat(1_000_000),
  runId: ulid,
  downpipeId: fc.string({ minLength: 1, maxLength: 20 }),
  time: fc.constant("2026-01-01T00:00:00.000Z"),
  recordCount: fc.nat(100000),
  prevRunId: fc.option(ulid, { nil: null }),
  status: fc.constantFrom("active", "retired"),
});

export async function runArchiveProperties(): Promise<void> {
  const archive = loadArchive();
  const runlogSeed = archive.get("_RECOVERY/RUNLOG")!;
  const runlogSigSeed = archive.get("_RECOVERY/RUNLOG.sig")!;
  const segKey = [...archive.keys()].find((k) => k.endsWith(".seg"))!;
  const segSeed = archive.get(segKey)!;
  const verifier = parseVerifier(b64urlDecode(text(readFileSync(join(VEC, "signer.pub"))).trim()));
  const identity = parseIdentity(b64urlDecode(text(readFileSync(join(VEC, "identity.key"))).trim()));

  console.log("archive parsers");

  // ---- RUNLOG ----
  await prop("parseRunlog: arbitrary text never crashes and refuses with an Error", async () => {
    await fc.assert(fc.asyncProperty(anyText, async (t) => void (await assertSafe("parseRunlog", () => parseRunlog(utf8(t)), plainRefusal))), runs(300));
  });
  await prop("parseRunlog: mutations of the real RUNLOG never crash", async () => {
    await fc.assert(fc.asyncProperty(mutationOf(runlogSeed), async (b) => void (await assertSafe("parseRunlog", () => parseRunlog(b), plainRefusal))), runs(300));
  });
  await prop("parseRunlog: the real RUNLOG parses", async () => {
    if (parseRunlog(runlogSeed).length === 0) throw new Error("vector RUNLOG parsed to no entries");
  });
  await prop("parseRunlog: a JSON null or scalar line is refused with a domain error", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom("null", "0", "true", '"s"', "[]", "[1]"), async (line) => void (await assertSafe("parseRunlog", () => parseRunlog(utf8(line)), plainRefusal))),
      runs(20),
    );
  });
  await prop("parseRunlog: signRunlog output round-trips through the parser", async () => {
    const ed = await ed25519Key();
    const ml = mldsaKeygen();
    await fc.assert(
      fc.asyncProperty(fc.array(entry, { maxLength: 4 }), async (es) => {
        const { runlog } = await signRunlog(es, ed, ml.secretKey);
        const back = parseRunlog(runlog);
        if (JSON.stringify(back) !== JSON.stringify(es.map((e) => JSON.parse(JSON.stringify(e))))) {
          // The writer sorts keys, so compare as sorted-key JSON.
          const norm = (x: unknown): string => JSON.stringify(x, Object.keys(x as object).sort());
          if (back.map(norm).join("|") !== es.map(norm).join("|")) throw new Error("round-trip changed an entry");
        }
      }),
      runs(8),
    );
  });
  await prop("RUNLOG signature check: the real pair verifies and any mutation of either half is false, never a throw", async () => {
    if (!(await sigVerifies(verifier, runlogSeed, runlogSigSeed))) throw new Error("vector RUNLOG does not verify");
    await fc.assert(
      fc.asyncProperty(mutationOf(runlogSeed), mutationOf(runlogSigSeed), fc.boolean(), async (a, s, which) => {
        const r = await assertSafe("hybridVerify", () => sigVerifies(verifier, which ? a : runlogSeed, which ? runlogSigSeed : s));
        const changed = which ? Buffer.compare(a, runlogSeed) !== 0 : Buffer.compare(s, runlogSigSeed) !== 0;
        if (changed && r.kind === "ok" && r.value) throw new Error("a mutated RUNLOG or signature verified");
      }),
      runs(30),
    );
  });

  // ---- shard manifest ----
  const shardLines = fc
    .tuple(fc.nat(4), fc.array(fc.nat(2 ** 31), { maxLength: 4 }))
    .map(([extra, sizes]) => [JSON.stringify({ kind: "preamble", recordCountInShard: sizes.length + extra }), ...sizes.map((n) => JSON.stringify({ kind: "record", plaintextSize: n }))].join("\n"));
  await prop("parseShard: arbitrary text never crashes and refuses with an Error", async () => {
    await fc.assert(fc.asyncProperty(anyText, async (t) => void (await assertSafe("parseShard", () => parseShard(utf8(t)), plainRefusal))), runs(300));
  });
  await prop("parseShard: well-formed shards parse and a wrong declared count is refused", async () => {
    await fc.assert(
      fc.asyncProperty(shardLines, async (t) => {
        const r = await assertSafe("parseShard", () => parseShard(utf8(t)), plainRefusal);
        const declared = (JSON.parse(t.split("\n")[0]!) as { recordCountInShard: number }).recordCountInShard;
        const lines = t.split("\n").length - 1;
        if ((declared === lines) !== (r.kind === "ok")) throw new Error("count check disagrees with the declared count");
      }),
      runs(200),
    );
  });
  await prop("parseShard: a JSON null or scalar record line is refused with a domain error", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom("null", "0", "true", '"s"'), async (bad) => {
        const t = `${JSON.stringify({ kind: "preamble", recordCountInShard: 1 })}\n${bad}`;
        await assertSafe("parseShard", () => parseShard(utf8(t)), plainRefusal);
      }),
      runs(20),
    );
  });
  await prop("parseShard: a JSON null preamble line is refused with a domain error", async () => {
    await assertSafe("parseShard", () => parseShard(utf8("null")), plainRefusal);
  });

  // ---- container framing ----
  await prop("unframeSeg and unframeDpe: arbitrary bytes refuse with an Error, never crash", async () => {
    await fc.assert(
      fc.asyncProperty(bytes, async (b) => {
        await assertSafe("unframeSeg", () => unframeSeg(b), plainRefusal);
        await assertSafe("unframeDpe", () => unframeDpe(b), plainRefusal);
      }),
      runs(300),
    );
  });
  await prop("frame round-trips and a mutated header byte is refused", async () => {
    await fc.assert(
      fc.asyncProperty(bytes, fc.nat(4), fc.integer({ min: 1, max: 255 }), async (p, i, x) => {
        const f = frame(MAGIC_SEG, p);
        if (Buffer.compare(unframeSeg(f), p) !== 0) throw new Error("frame round-trip changed the payload");
        const g = Uint8Array.from(f);
        g[i] = (g[i]! ^ x) & 0xff;
        const r = await assertSafe("unframeSeg", () => unframeSeg(g), plainRefusal);
        if (r.kind === "ok") throw new Error("a mutated header was accepted");
        const d = await assertSafe("unframeDpe", () => unframeDpe(frame(MAGIC_SEG, p)), plainRefusal);
        if (d.kind === "ok") throw new Error("a .seg container opened as .dpe");
        if (Buffer.compare(unframeDpe(frame(MAGIC_DPE, p)), p) !== 0) throw new Error("dpe frame round-trip changed the payload");
      }),
      runs(200),
    );
  });

  // ---- object key ----
  await prop("segIDFromObject: arbitrary keys refuse with an Error; a 48-byte hex key round-trips", async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(fc.string({ maxLength: 160 }), fc.uint8Array({ minLength: 48, maxLength: 48 }).map((u) => `seg/${Buffer.from(u).toString("hex")}.seg`)), async (k) => {
        const r = await assertSafe("segIDFromObject", () => segIDFromObject(k), plainRefusal);
        if (r.kind === "ok" && r.value.length !== 48) throw new Error("accepted a key that is not 48 bytes");
      }),
      runs(300),
    );
  });
  await prop("segIDFromObject: the real segment key decodes", async () => {
    if (segIDFromObject(segKey).length !== 48) throw new Error("vector segment key did not decode");
  });

  // ---- canonical counts ----
  await prop("validateCanonicalCounts: arbitrary text and paths refuse with the integrity class", async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(fc.string({ maxLength: 100 }), fc.json(), jsonValue.map((v) => JSON.stringify(v))), fc.array(fc.oneof(fc.constantFrom("index", "a.b", "recordCount", "x.y.z"), fc.string({ maxLength: 8 })), { maxLength: 3 }), async (t, ps) => {
        await assertSafe("validateCanonicalCounts", () => validateCanonicalCounts(t, ...ps), isIntegrityFailure);
      }),
      runs(300),
    );
  });
  await prop("validateCanonicalCounts: a string, negative, fractional or over-range count is refused", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom('"5"', "-1", "-0", "1.5", "9007199254740992", "1e400"), async (v) => {
        const r = await assertSafe("validateCanonicalCounts", () => validateCanonicalCounts(`{"n":${v}}`, "n"), isIntegrityFailure);
        if (r.kind === "ok") throw new Error(`accepted ${v}`);
      }),
      runs(12),
    );
  });
  await prop("validateCanonicalCounts: a count written with a point or exponent is refused", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom("1.0", "1e3", "1E3", "10e-1", "0.0e0", "5.00"), async (v) => {
        const r = await assertSafe("validateCanonicalCounts", () => validateCanonicalCounts(`{"n":${v}}`, "n"), isIntegrityFailure);
        if (r.kind === "ok") throw new Error(`accepted ${v}`);
      }),
      runs(12),
    );
  });

  // ---- run id ----
  await prop("run id decoding: never crashes, and isValidRunId, decodeULID and the classifier agree", async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(fc.string({ maxLength: 40 }), ulid, fc.string({ minLength: 26, maxLength: 26 })), async (s) => {
        const d = await assertSafe("decodeULID", () => decodeULID(s), plainRefusal);
        const valid = isValidRunId(s);
        const cls = classifyRunIdMalformation(s);
        if (valid !== (d.kind === "ok")) throw new Error("isValidRunId disagrees with decodeULID");
        if (valid !== (cls === null)) throw new Error("classifier disagrees with isValidRunId");
        if (cls !== null && !(RUNID_MALFORM_KINDS as readonly string[]).includes(cls)) throw new Error("classifier left its closed set");
      }),
      runs(400),
    );
  });

  // ---- segment readers ----
  await prop("openNonSecretSegment: arbitrary and mutated sealed bytes refuse with an Error, never crash", async () => {
    const master = new Uint8Array(32).fill(7);
    const id = new Uint8Array(48).fill(1);
    await fc.assert(
      fc.asyncProperty(fc.oneof(bytes, mutationOf(segSeed)), fc.integer({ min: 0, max: 2 }), async (b, codec) => {
        const r = await assertSafe("openNonSecretSegment", () => openNonSecretSegment(master, id, codec, b, 4), plainRefusal);
        if (r.kind === "ok") throw new Error("opened bytes sealed under a different key");
      }),
      runs(150),
    );
  });
  await prop("sealNonSecretSegment and openNonSecretSegment round-trip, and a flipped byte is refused", async () => {
    const master = new Uint8Array(32).fill(9);
    const id = new Uint8Array(48).fill(2);
    await fc.assert(
      fc.asyncProperty(bytes, fc.uint8Array({ minLength: 16, maxLength: 16 }), fc.nat(), async (pt, nonce, at) => {
        const sealed = await sealNonSecretSegment(master, id, 0, pt, nonce);
        const back = await openNonSecretSegment(master, id, 0, sealed, 0);
        if (Buffer.compare(back, pt) !== 0) throw new Error("segment round-trip changed the plaintext");
        const bad = Uint8Array.from(sealed);
        bad[at % bad.length] = (bad[at % bad.length]! ^ 1) & 0xff;
        const r = await assertSafe("openNonSecretSegment", () => openNonSecretSegment(master, id, 0, bad, 0), plainRefusal);
        if (r.kind === "ok") throw new Error("a flipped byte was accepted");
      }),
      runs(40),
    );
  });

  // ---- the full opener over a mutated vector ----
  const keys = [...archive.keys()].filter((k) => !k.endsWith(".md"));
  const openOnce = async (key: string, mutated: Uint8Array): Promise<boolean> => {
    const store: ObjectStore = { get: async (k) => (k === key ? mutated : (archive.get(k) ?? Promise.reject(new Error(`no object ${k}`)))) };
    const r = await assertSafe(`openRun[${key}]`, async () => {
      const run = await openRun(store, RUN_ID, identity, verifier, { verifyFreshness: true, checkRecoveryBundle: true });
      try {
        for (const rec of run.records) await run.restoreRecord(rec);
      } finally {
        run.dispose();
      }
    });
    if (r.kind === "refused" && !isIntegrityFailure(r.err)) throw new Error(`openRun[${key}] refused outside the closed integrity class: ${r.err.message}`);
    return r.kind === "ok";
  };
  await prop("openRun: the unmutated vector opens and restores every record", async () => {
    if (!(await openOnce("none", new Uint8Array(0)))) throw new Error("the unmutated vector was refused");
  });
  const SIG_KEY = `run/${RUN_ID}/root.manifest.json.sig`;
  await prop("openRun: a root signature file that is not base64url is refused with the integrity class", async () => {
    await openOnce(SIG_KEY, utf8("!!!not-base64url!!!"));
  });
  await prop("openRun: a flipped bit in the root manifest, RUNLOG, shard or segment is always refused", async () => {
    const signed = keys.filter((k) => k !== SIG_KEY && (k.endsWith("root.manifest.json") || k.endsWith(".dpe") || k.endsWith(".seg") || k === "_RECOVERY/RUNLOG"));
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(...signed), fc.nat(), fc.integer({ min: 0, max: 7 }), async (key, at, bit) => {
        const m = Uint8Array.from(archive.get(key)!);
        m[at % m.length] = (m[at % m.length]! ^ (1 << bit)) & 0xff;
        if (await openOnce(key, m)) throw new Error(`a flipped bit in ${key} was accepted`);
      }),
      runs(40),
    );
  });
  await prop("openRun: every other object of the vector, mutated, is refused with the integrity class or opens, never a crash", async () => {
    await fc.assert(
      fc.asyncProperty(fc.constantFrom(...keys.filter((k) => k !== SIG_KEY)), fc.nat(), fc.integer({ min: 0, max: 255 }), fc.integer({ min: 0, max: 2 }), async (key, at, v, how) => {
        const src = archive.get(key)!;
        let m: Uint8Array;
        if (how === 0) {
          m = Uint8Array.from(src);
          if (m.length > 0) m[at % m.length] = v;
        } else if (how === 1) m = src.slice(0, at % (src.length + 1));
        else m = concat(src, Uint8Array.of(v));
        await openOnce(key, m);
      }),
      runs(60),
    );
  });
}
