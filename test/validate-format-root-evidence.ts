// VALIDATOR: the FORMAT + ROOT fault evidence the support pack could not see.
//
// Four gaps in the pack's diagnostic coverage, and why each matters:
//
//   ROLLBACK DETECTION. The engine detects a possible ROLLBACK ATTACK -- a rewritten, forked or
//        duplicated RUNLOG chain, a replay of an older validly-signed document, a corrupt line -- and records
//        NOTHING about it by default. The only thing it produces is a reason string that interpolates the
//        customer's run and downpipe ids, so it can never be carried. Support therefore cannot separate a
//        TAMPER from a destination-side bit-flip, which are opposite tickets. The forensic row (closed kind,
//        the two DISAGREEING indices, the unparseable line ordinal, the chain length, a one-way digest of the
//        RUNLOG bytes the customer can reproduce from their own object) is recorded at the detection site.
//
//   WRITER REFUSALS. The writer's three loud refusals collapse into a generic "run failed". source-enumerated-
//        zero is a CUSTOMER fault the pack could not name (an emptied KV namespace, a de-scoped token); the two
//        stream-wiring invariants are ENGINE faults. Telling them apart IS the diagnosis.
//
//   ATTESTATION COVERAGE. A very large run attested against a store with no list() silently SKIPS the
//        per-shard presence pass, so complete:true is an OVERCLAIM (a durably missing shard outside the
//        strided sample reads as complete) and nothing said so. The coverage mode is a closed enum on the
//        attestation AND a row in the run's integrity evidence -- the one piece of evidence that rides an
//        otherwise CLEAN verdict.
//
//   MALFORMED runId. "Our integration script keeps getting invalid runId 400s": nothing was persisted
//        server-side, so support could not say whether the ids arrive truncated, case-mangled or out of range
//        (three different customer-side fixes). The closed KIND is counted at the four rejecting routes.
//
// It proves three things:
//   1. RECORDED ON THE REAL FAULT PATH -- each site is driven through the production function (a signed but
//      forked RUNLOG through checkRunlogFreshness, a zero-record run through buildArchive, a list()-less store
//      through attestKeyless, a malformed runId through the production handleRestore route), never by calling
//      a note function directly.
//   2. THE VOCABULARIES ARE PINNED -- admin/diag-records.ts is a LEAF and re-declares the closed sets; a drift
//      would make the DO applier DROP every posted row and the pack would go quietly empty during the exact
//      incident it exists to explain.
//   3. REDACTION (binding, no-custody) -- a customer email, bucket, object key and live secret are planted AT
//      each fault site (as the downpipe id, the record name, the rejected runId), and NOT ONE BYTE of them may
//      appear in the record on either side of the wire. The DO applier is then attacked with a hostile body.
//
// Run: node test/validate-format-root-evidence.ts

import { strict as assert } from "node:assert";

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { buildArchive, signRunlog, parseRunlog, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { checkRunlogFreshness } from "../src/format/freshness.ts";
import { attestKeyless } from "../src/format/keyless.ts";
import { classifyRunIdMalformation, RUNID_MALFORM_KINDS } from "../src/format/ulid.ts";
import {
  drainIntegrityFaultLedger,
  resetIntegrityFaultLedger,
  KEYLESS_COVERAGE_MODES,
  RUNLOG_ANOMALY_KINDS,
  WRITER_REFUSAL_KINDS,
  type IntegrityFaultSnapshot,
} from "../src/format/integrity-fault-ledger.ts";
import {
  ADMIN_COUNTER_NAMES,
  applyAdminCounters,
  applyIntegrityFaults,
  KEYLESS_COVERAGE_NAMES,
  RUNLOG_ANOMALY_KIND_NAMES,
  WRITER_REFUSAL_KIND_NAMES,
} from "../src/admin/diag-records.ts";
import { noteInvalidRunId } from "../src/admin/diag-counters.ts";
import { handleRestore } from "../src/admin/router-restore.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import type { RootManifest } from "../src/format/manifest.ts";
import type { Destination } from "../src/dest/types.ts";

let failures = 0;
function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  return (async (): Promise<void> => {
    try {
      await fn();
      console.log(`  ok   ${name}`);
    } catch (e) {
      failures++;
      console.error(`  FAIL ${name}: ${(e as Error).message}`);
    }
  })();
}

// ---------------------------------------------------------------------------------------------------------
// THE SENTINELS. Every one is a value the pack must NEVER carry. They are planted AT the fault sites (as the
// downpipe id in the RUNLOG, as the record name the writer refuses, as the rejected runId) and hunted for.
// ---------------------------------------------------------------------------------------------------------
const SENTINEL_EMAIL = "cfo@acme-payroll.example";
const SENTINEL_BUCKET = "acme-prod-payroll-backups";
const SENTINEL_KEY = "kv/tenants/acme/salaries-2026.json";
const SENTINEL_SECRET = "sk_live_51H8xQzAcmeSuperSecretTokenValue";
const SENTINELS = [SENTINEL_EMAIL, SENTINEL_BUCKET, SENTINEL_KEY, SENTINEL_SECRET];

function assertRedacted(what: string, record: unknown): void {
  const json = JSON.stringify(record);
  for (const s of SENTINELS) {
    assert.ok(!json.includes(s), `${what} LEAKED a customer sentinel (${s.slice(0, 16)}...): ${json.slice(0, 400)}`);
  }
  for (const marker of ["Error:", "at Object.", "\n    at ", "AccessDenied</Code>", "Bearer "]) {
    assert.ok(!json.includes(marker), `${what} LEAKED raw error/stack text (${marker}): ${json.slice(0, 400)}`);
  }
}

// drainAfter resets the isolate-local ledger, drives the real fault path (which THROWS at several of these
// sites, by design: the note rides alongside the throw, it never replaces it) and returns the snapshot.
async function drainAfter(body: () => Promise<void> | void): Promise<IntegrityFaultSnapshot> {
  resetIntegrityFaultLedger();
  try {
    await body();
  } catch {
    /* the throw is the production behaviour; the evidence must survive it */
  }
  return drainIntegrityFaultLedger();
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---- the RUNLOG fixtures (G102) --------------------------------------------------------------------------
// The downpipe id in every entry is a customer SENTINEL: the anomaly reason string the detector returns
// interpolates it (and the test asserts it does, so the site genuinely has the value in hand), while the
// recorded row must not carry one byte of it.
const RUN_A = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const RUN_B = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
const RUN_C = "01ARZ3NDEKTSV4RRFFQ69G5FC1";

interface SignerCtx {
  edPrivate: CryptoKey;
  mldsaSecret: Uint8Array;
  verifier: HybridVerifier;
}

async function makeRunlogSigner(): Promise<SignerCtx> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, mldsaSecret: mldsa.secretKey, verifier: { ed: edPublic, mldsa: mldsa.publicKey } };
}

function entry(index: number, runId: string, prevRunId: string | null): RunlogEntry {
  return { index, runId, downpipeId: SENTINEL_BUCKET, time: `t${index}`, recordCount: 1, prevRunId, status: "active" };
}

// storeFor serves a genuinely SIGNED RUNLOG exactly as the destination would, so the production signature gate
// passes and the chain / parse checks are what actually fire.
async function storeFor(signer: SignerCtx, entries: RunlogEntry[]): Promise<ObjectStore> {
  const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
  return storeOfBytes(runlog, sig);
}

function storeOfBytes(runlog: Uint8Array, sig: Uint8Array): ObjectStore {
  const objects = new Map<string, Uint8Array>([
    ["_RECOVERY/RUNLOG", runlog],
    ["_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig))],
  ]);
  return {
    get: async (k: string): Promise<Uint8Array> => {
      const v = objects.get(k);
      if (!v) throw new Error(`missing ${k}`);
      return v;
    },
  };
}

function rootFor(index: number, prevRunId: string | null): RootManifest {
  return { downpipeId: SENTINEL_BUCKET, freshness: { runlogIndex: index, prevRunId } } as unknown as RootManifest;
}

// ---- the archive fixture (G166 / G320) -------------------------------------------------------------------
function makeRecipient(role: string): RecipientEntry {
  const xk = x25519.keygen();
  return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(rand(64)).encapKey } };
}

async function makeSigner(): Promise<Signer> {
  return loadSigner(b64urlEncode(rand(64)));
}

function writeParams(signer: Signer, records: Parameters<typeof buildArchive>[0]["records"]): Parameters<typeof buildArchive>[0] {
  return {
    downpipeId: "dp_evidence",
    downpipeName: "evidence",
    cadence: "daily",
    runId: RUN_A,
    master: rand(32),
    recipients: [makeRecipient("break-glass"), makeRecipient("operational")],
    signer,
    records,
    windowStart: "2026-07-10T00:00:00Z",
    windowEnd: "2026-07-10T01:00:00Z",
    createdAt: "2026-07-10T01:00:00Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  };
}

async function main(): Promise<void> {
  console.log("validate-format-root-evidence");

  // -------------------------------------------------------------------------------------------------------
  // 1. THE VOCABULARIES ARE PINNED to the DO's re-declared sets (diag-records.ts is a LEAF and imports
  //    nothing). A drift silently DROPS every posted row on the DO side: the pack would show NO rollback
  //    forensics during the one incident they exist for.
  // -------------------------------------------------------------------------------------------------------
  await check("vocabulary: RUNLOG_ANOMALY_KINDS (G102) is pinned to the DO's re-declared set", () => {
    assert.deepEqual([...RUNLOG_ANOMALY_KINDS], [...RUNLOG_ANOMALY_KIND_NAMES]);
  });
  await check("vocabulary: WRITER_REFUSAL_KINDS (G166) is pinned to the DO's re-declared set", () => {
    assert.deepEqual([...WRITER_REFUSAL_KINDS], [...WRITER_REFUSAL_KIND_NAMES]);
  });
  await check("vocabulary: KEYLESS_COVERAGE_MODES (G320) is pinned to the DO's re-declared set", () => {
    assert.deepEqual([...KEYLESS_COVERAGE_MODES], [...KEYLESS_COVERAGE_NAMES]);
  });
  await check("vocabulary: every runId malformation kind (G321) has an admin counter name", () => {
    for (const kind of RUNID_MALFORM_KINDS) {
      assert.ok((ADMIN_COUNTER_NAMES as readonly string[]).includes(`invalid-runid-${kind}`), `invalid-runid-${kind} is missing from ADMIN_COUNTER_NAMES`);
    }
  });

  // -------------------------------------------------------------------------------------------------------
  // THE ANTI-ROLLBACK FORENSICS. Every case below drives the PRODUCTION checkRunlogFreshness with a
  // genuinely signed RUNLOG, so the signature gate passes and the real detector fires.
  // -------------------------------------------------------------------------------------------------------
  const signer = await makeRunlogSigner();

  await check("a DUPLICATE index records the kind, the disagreeing index pair, the chain length and the RUNLOG digest", async () => {
    const entries = [entry(1, RUN_A, null), entry(1, RUN_B, RUN_A)];
    const store = await storeFor(signer, entries);
    let reason = "";
    const snap = await drainAfter(async () => {
      const r = await checkRunlogFreshness(store, RUN_A, rootFor(1, null), signer.verifier, { allowStale: true });
      assert.equal(r.rollbackDetected, true, "a duplicated index must still be an unconditional rollback signal");
      reason = r.reason ?? "";
    });
    // The SITE has the customer's downpipe id in hand (the reason string proves it) ...
    assert.ok(reason.includes("appears twice"), `the operator-facing reason is unchanged: ${reason}`);
    const a = snap.runlogAnomalies[0];
    assert.ok(a !== undefined, "a rollbackDetected with NO forensic row is the gap itself");
    assert.equal(a.kind, "duplicate-index");
    assert.equal(a.indexA, 1);
    assert.equal(a.indexB, 1);
    assert.equal(a.entryCount, 2, "the chain length separates a one-line slip from a wholesale rewrite");
    assert.match(a.digest ?? "", /^[0-9a-f]{12}$/, "the RUNLOG digest is the customer-reproducible join key");
    // ... and the RECORD carries none of it.
    assertRedacted("runlogAnomalies (G102 duplicate-index)", snap);
  });

  await check("a FORKED prevRunId records forked-prev with both entries' indices", async () => {
    const entries = [entry(1, RUN_A, null), entry(2, RUN_B, RUN_A), entry(3, RUN_C, RUN_A)];
    const store = await storeFor(signer, entries);
    const snap = await drainAfter(async () => {
      const r = await checkRunlogFreshness(store, RUN_A, rootFor(1, null), signer.verifier, { allowStale: true });
      assert.equal(r.rollbackDetected, true);
    });
    const a = snap.runlogAnomalies[0];
    assert.ok(a !== undefined && (a.kind === "forked-prev" || a.kind === "chain-break"), `a forked chain must be recorded, got ${a?.kind}`);
    assert.ok(typeof a.indexA === "number" && typeof a.indexB === "number", "the two disagreeing entries must both be located");
    assertRedacted("runlogAnomalies (G102 forked-prev)", snap);
  });

  await check("a DANGLING prevRunId records dangling-prev with the offending entry's index", async () => {
    const entries = [entry(4, RUN_B, RUN_C)]; // RUN_C is carried by no entry at all
    const store = await storeFor(signer, entries);
    const snap = await drainAfter(async () => {
      const r = await checkRunlogFreshness(store, RUN_B, rootFor(4, RUN_C), signer.verifier, { allowStale: true });
      assert.equal(r.rollbackDetected, true);
    });
    const a = snap.runlogAnomalies[0];
    assert.ok(a !== undefined);
    assert.equal(a.kind, "dangling-prev");
    assert.equal(a.indexA, 4);
    assertRedacted("runlogAnomalies (G102 dangling-prev)", snap);
  });

  await check("a whole-document REPLAY under the min-index pin records index-regression with observed-vs-pinned", async () => {
    const entries = [entry(1, RUN_A, null), entry(2, RUN_B, RUN_A)];
    const store = await storeFor(signer, entries);
    const snap = await drainAfter(async () => {
      // The pin is the account-global high-water mark held OUT OF BAND: an internally-consistent, validly
      // signed OLDER document trips no chain anomaly and must still be caught.
      const r = await checkRunlogFreshness(store, RUN_B, rootFor(2, RUN_A), signer.verifier, { allowStale: true, minRunlogIndex: 57 });
      assert.equal(r.rollbackDetected, true, "a clean replay under the pin is a rollback");
    });
    const a = snap.runlogAnomalies[0];
    assert.ok(a !== undefined);
    assert.equal(a.kind, "index-regression");
    assert.equal(a.indexA, 2, "indexA is the max the replayed document carries");
    assert.equal(a.indexB, 57, "indexB is the out-of-band pin it fell below: 55 runs of history rolled back");
    assertRedacted("runlogAnomalies (G102 index-regression)", snap);
  });

  await check("a RUNLOG signature that will not verify records sig-invalid with the document digest", async () => {
    const { runlog } = await signRunlog([entry(1, RUN_A, null)], signer.edPrivate, signer.mldsaSecret);
    // A signature over DIFFERENT bytes: the tamper / bit-flip case.
    const { sig: wrongSig } = await signRunlog([entry(2, RUN_B, RUN_A)], signer.edPrivate, signer.mldsaSecret);
    const store = storeOfBytes(runlog, wrongSig);
    const snap = await drainAfter(async () => {
      const r = await checkRunlogFreshness(store, RUN_A, rootFor(1, null), signer.verifier, { allowStale: true });
      assert.equal(r.reason, "RUNLOG signature did not verify");
    });
    const a = snap.runlogAnomalies[0];
    assert.ok(a !== undefined);
    assert.equal(a.kind, "sig-invalid");
    assert.match(a.digest ?? "", /^[0-9a-f]{12}$/, "the digest is what proves a bit-flip (bytes changed) from a re-signed forgery (they did not)");
    assert.equal(snap.failStages["freshness-signature"], 1);
    assertRedacted("runlogAnomalies (G102 sig-invalid)", snap);
  });

  await check("a CORRUPT RUNLOG line records parse-field with the line ordinal, the line count and the digest", async () => {
    // A destination-side bit-flip: line 1 is valid, line 2 has lost its runId. The document is VALIDLY SIGNED
    // over the corrupt bytes (the signature is computed here over exactly what the store serves), so the parse
    // gate is what fires -- the same shape as a signed-then-corrupted object read back from a damaged bucket.
    const good = JSON.stringify({ index: 1, runId: RUN_A, downpipeId: SENTINEL_BUCKET, time: "t1", recordCount: 1, prevRunId: null, status: "active" });
    const bad = JSON.stringify({ index: 2, runId: "", downpipeId: SENTINEL_BUCKET, time: "t2", recordCount: 1, prevRunId: RUN_A, status: "active" });
    const bytes = utf8(`${good}\n${bad}\n`);
    const { sig } = await signRunlog([], signer.edPrivate, signer.mldsaSecret); // placeholder, replaced below
    void sig;
    const { hybridSign } = await import("../src/crypto/sign.ts");
    const realSig = await hybridSign(signer.edPrivate, signer.mldsaSecret, bytes);
    const store = storeOfBytes(bytes, realSig);
    let threw = false;
    const snap = await drainAfter(async () => {
      try {
        await checkRunlogFreshness(store, RUN_A, rootFor(1, null), signer.verifier, { allowStale: true });
      } catch {
        threw = true; // the parse throw is production behaviour and must be UNCHANGED
        throw new Error("rethrown");
      }
    });
    assert.equal(threw, true, "the corrupt-line throw must still happen: the note rides alongside it");
    const withOrdinal = snap.runlogAnomalies.find((a) => a.lineOrdinal !== undefined);
    const withDigest = snap.runlogAnomalies.find((a) => a.digest !== undefined);
    assert.ok(withOrdinal !== undefined, "WHICH line failed the shape check is the whole locus");
    assert.equal(withOrdinal.kind, "parse-field");
    assert.equal(withOrdinal.lineOrdinal, 1, "the second line (ordinal 1) is the corrupt one");
    assert.equal(withOrdinal.entryCount, 2);
    assert.ok(withDigest !== undefined, "the document digest must ride so the customer can compare their own object");
    assertRedacted("runlogAnomalies (G102 parse-field)", snap);
  });

  await check("parseRunlog notes the ordinal at the SHAPE gate itself (a non-canonical index)", async () => {
    const bad = '{"index":1.5,"runId":"' + RUN_A + '","downpipeId":"' + SENTINEL_BUCKET + '","time":"t","recordCount":1,"prevRunId":null,"status":"active"}';
    const snap = await drainAfter(() => {
      parseRunlog(utf8(`${bad}\n`));
    });
    const a = snap.runlogAnomalies[0];
    assert.ok(a !== undefined, "a non-canonical index is the anti-rollback min-pin bypass attempt and must be recorded");
    assert.equal(a.kind, "parse-field");
    assert.equal(a.lineOrdinal, 0);
    assertRedacted("runlogAnomalies (G102 canonical-number gate)", snap);
  });

  await check("a CLEAN chain records nothing at all (silence is the healthy steady state)", async () => {
    const entries = [entry(1, RUN_A, null), entry(2, RUN_B, RUN_A)];
    const store = await storeFor(signer, entries);
    const snap = await drainAfter(async () => {
      const r = await checkRunlogFreshness(store, RUN_B, rootFor(2, RUN_A), signer.verifier, {});
      assert.equal(r.ok, true);
      assert.equal(r.rollbackDetected, false);
    });
    assert.equal(snap.runlogAnomalies.length, 0, "a healthy fleet must post NOTHING");
  });

  // -------------------------------------------------------------------------------------------------------
  // THE WRITER'S LOUD REFUSALS. Driven through the production buildArchive, with the record NAME set to
  // a customer object key (the value the throw message interpolates and the record must never carry).
  // -------------------------------------------------------------------------------------------------------
  const archiveSigner = await makeSigner();

  await check("a source that enumerated ZERO records is recorded as source-enumerated-zero, not a generic run failure", async () => {
    let threw = false;
    const snap = await drainAfter(async () => {
      try {
        await buildArchive(writeParams(archiveSigner, []));
      } catch {
        threw = true;
        throw new Error("rethrown");
      }
    });
    assert.equal(threw, true, "the refusal must still throw: the note never replaces the control flow");
    assert.equal(snap.writerRefusals["source-enumerated-zero"], 1, "'your source produced zero records' is a CUSTOMER fault the pack could not name");
    assertRedacted("writerRefusals (G166 zero records)", snap);
  });

  await check("a streamed record with NO destination is recorded as stream-no-destination (the record name never rides)", async () => {
    const snap = await drainAfter(async () => {
      await buildArchive(
        writeParams(archiveSigner, [{ sourceType: "r2", name: SENTINEL_KEY, stream: { open: () => new ReadableStream<Uint8Array>(), size: 1 } as never }]),
        {}, // no dest: the wiring invariant
      );
    });
    assert.equal(snap.writerRefusals["stream-no-destination"], 1);
    assertRedacted("writerRefusals (G166 stream-no-destination)", snap);
  });

  await check("a SECRET handed in as a stream is recorded as secrets-streamed", async () => {
    const snap = await drainAfter(async () => {
      await buildArchive(writeParams(archiveSigner, [{ sourceType: "secrets", name: SENTINEL_SECRET, stream: { open: () => new ReadableStream<Uint8Array>(), size: 1 } as never }]), {
        dest: {} as unknown as Destination,
      });
    });
    assert.equal(snap.writerRefusals["secrets-streamed"], 1);
    assertRedacted("writerRefusals (G166 secrets-streamed)", snap);
  });

  await check("a healthy run records NO refusal", async () => {
    const snap = await drainAfter(async () => {
      await buildArchive(writeParams(archiveSigner, [{ sourceType: "kv", name: "k1", value: utf8("v1") }]));
    });
    assert.equal(Object.keys(snap.writerRefusals).length, 0);
  });

  // -------------------------------------------------------------------------------------------------------
  // THE DEGRADED ATTESTATION COVERAGE MODE. A real signed archive is attested through the production
  // attestKeyless with the bounded shardCheck the at-seal caller uses, against a store that CANNOT list().
  // The verdict is complete:true either way -- which is exactly the overclaim -- so the coverage enum is the
  // only thing that can ever tell the two apart.
  // -------------------------------------------------------------------------------------------------------
  const archive = await buildArchive(writeParams(archiveSigner, [{ sourceType: "kv", name: "k1", value: utf8("v1") }]));
  const verifier = verifierFrom(archiveSigner);
  const getFrom = async (k: string): Promise<Uint8Array> => {
    const v = archive.get(k);
    if (!v) throw new Error(`missing ${k}`);
    return v;
  };
  const listing = (prefix: string): string[] => [...archive.keys()].filter((k) => k.startsWith(prefix));

  await check("a sampled attestation against a store with NO list() records sampled-no-presence behind complete:true", async () => {
    const snap = await drainAfter(async () => {
      const att = await attestKeyless({ get: getFrom }, RUN_A, verifier, { shardCheck: { sampleAbove: 0, sample: 1 } });
      assert.equal(att.complete, true, "the verdict still says complete -- that is the overclaim the mode qualifies");
      assert.equal(att.coverage, "sampled-no-presence", "the presence pass was SKIPPED and the attestation must say so");
    });
    assert.equal(snap.attestCoverage, "sampled-no-presence", "the degraded mode must ride the run's integrity evidence, not just the return value");
    assertRedacted("attestCoverage (G320 no-presence)", snap);
  });

  await check("the same run against a store that CAN list() records the stronger sampled mode", async () => {
    const snap = await drainAfter(async () => {
      const att = await attestKeyless({ get: getFrom, list: async (p: string) => listing(p) }, RUN_A, verifier, { shardCheck: { sampleAbove: 0, sample: 1 } });
      assert.equal(att.complete, true);
      assert.equal(att.coverage, "sampled", "with the presence pass, a missing shard outside the sample is still caught");
    });
    assert.equal(snap.attestCoverage, "sampled");
  });

  await check("a FULL attestation qualifies its verdict as full and records nothing", async () => {
    const snap = await drainAfter(async () => {
      const att = await attestKeyless({ get: getFrom }, RUN_A, verifier, {});
      assert.equal(att.coverage, "full");
    });
    assert.equal(snap.attestCoverage, "", "a full read-back is the healthy steady state and must stay silent");
  });

  // -------------------------------------------------------------------------------------------------------
  // THE REJECTED runId. Driven through the PRODUCTION handleRestore route, with the malformed candidate
  // carrying every sentinel at once -- because that field is the one an integration script (or an attacker)
  // can fill with anything at all, which is precisely why only its closed KIND may be recorded.
  // -------------------------------------------------------------------------------------------------------
  await check("the malformation classifier returns a closed kind and never the candidate", () => {
    assert.equal(classifyRunIdMalformation("01ARZ3NDEKTSV4RRFFQ69G5FA"), "length", "a 25-char truncation is the classic script bug");
    assert.equal(classifyRunIdMalformation("01arz3ndektsv4rrffq69g5fav"), "charset", "a lower-cased id is a different fix from a truncated one");
    assert.equal(classifyRunIdMalformation("ZZARZ3NDEKTSV4RRFFQ69G5FAV"), "overflow", "a home-made generator emitting out-of-range ids");
    assert.equal(classifyRunIdMalformation(RUN_A), null, "a canonical ULID records nothing");
    assert.equal(classifyRunIdMalformation(undefined), "length");
    for (const s of SENTINELS) {
      const kind = classifyRunIdMalformation(s);
      assert.ok(kind !== null && (RUNID_MALFORM_KINDS as readonly string[]).includes(kind), "a hostile candidate still yields only a closed member");
    }
  });

  await check("POST /restore with a malformed runId 400s AND counts the closed kind, carrying no byte of the candidate", async () => {
    const posted: string[] = [];
    const scheduler = {
      fetch: async (_url: string, init?: { body?: string }): Promise<Response> => {
        if (init?.body !== undefined) posted.push(init.body);
        return new Response("{}", { status: 200 });
      },
    } as unknown as DurableObjectStub;
    // The candidate is a full customer payload: an email, a bucket, an object key and a live secret.
    const candidate = `${SENTINEL_EMAIL}/${SENTINEL_BUCKET}/${SENTINEL_KEY}?token=${SENTINEL_SECRET}`;
    const req = new Request("https://engine.example/admin/restore", { method: "POST", body: JSON.stringify({ runId: candidate }) });
    const resp = await handleRestore({
      req,
      env: {} as never,
      url: new URL("https://engine.example/admin/restore"),
      scheduler,
      caller: { role: "owner" } as never,
      sub: "/restore",
      sourceIp: null,
      runtime: undefined,
    } as never);
    assert.equal(resp?.status, 400, "the refusal itself is unchanged");
    // The counter write is fire-and-forget (it must never add latency to the refusal): let it settle.
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(posted.length, 1, "the rejection must reach the DO: a 400 nobody records is the gap");
    const body = JSON.parse(posted[0]!) as { bumps: Record<string, number> };
    // A payload of that length is a LENGTH rejection: the counter says "your script is not sending a 26-char
    // ULID at all", which is the actionable half. Nothing about WHAT it sent may be recorded.
    assert.equal(body.bumps["invalid-runid-length"], 1);
    assertRedacted("the /diag/admin-counters body (G321)", body);

    // The DO-side applier is the chokepoint: it folds the closed name and drops anything else.
    const rec = applyAdminCounters(undefined, body.bumps, "2026-07-10T00:00:00.000Z");
    assert.equal(rec["invalid-runid-length"]?.count, 1);
    assertRedacted("adminCounters record (G321)", rec);

    // The other two kinds reach the DO under their own names from the same route sink.
    posted.length = 0;
    await noteInvalidRunId(scheduler, "01arz3ndektsv4rrffq69g5fav");
    assert.equal((JSON.parse(posted[0]!) as { bumps: Record<string, number> }).bumps["invalid-runid-charset"], 1);
    posted.length = 0;
    await noteInvalidRunId(scheduler, "ZZARZ3NDEKTSV4RRFFQ69G5FAV");
    assert.equal((JSON.parse(posted[0]!) as { bumps: Record<string, number> }).bumps["invalid-runid-overflow"], 1);
  });

  await check("a WELL-FORMED runId records nothing (no counter, no DO write)", async () => {
    const posted: string[] = [];
    const scheduler = {
      fetch: async (_url: string, init?: { body?: string }): Promise<Response> => {
        if (init?.body !== undefined) posted.push(init.body);
        return new Response("{}", { status: 200 });
      },
    } as unknown as DurableObjectStub;
    await noteInvalidRunId(scheduler, RUN_A);
    assert.equal(posted.length, 0);
  });

  // -------------------------------------------------------------------------------------------------------
  // THE DO-SIDE CHOKEPOINT. applyIntegrityFaults re-gates every field. Attack it directly with a body that a
  // drifted (or compromised) caller might post: a raw exception message as the kind, a stack, a bucket in the
  // digest, a NaN index, an out-of-vocabulary refusal kind, a bogus coverage mode.
  // -------------------------------------------------------------------------------------------------------
  await check("DO chokepoint: a hostile integrity body cannot land one byte of a sentinel", () => {
    const hostile = {
      runlogAnomalies: [
        { kind: `Error: RUNLOG at ${SENTINEL_BUCKET}/${SENTINEL_KEY} is forked`, indexA: 1, digest: SENTINEL_SECRET },
        { kind: "duplicate-index", indexA: Number.NaN, indexB: -5, lineOrdinal: Infinity, entryCount: 3, digest: SENTINEL_KEY },
      ],
      writerRefusals: { [`drop table ${SENTINEL_BUCKET}`]: 9, "source-enumerated-zero": 2 },
      attestCoverage: `sampled-no-presence ${SENTINEL_EMAIL}`,
    };
    const rec = applyIntegrityFaults(undefined, "dp_hostile", hostile, 1_800_000_000_000);
    const row = rec.dp_hostile!;
    assert.equal(row.runlogAnomalies.length, 1, "the out-of-vocabulary kind (a raw exception message) must be DROPPED");
    assert.equal(row.runlogAnomalies[0]!.kind, "duplicate-index");
    assert.equal(row.runlogAnomalies[0]!.indexA, undefined, "NaN is dropped, never coerced");
    assert.equal(row.runlogAnomalies[0]!.indexB, undefined, "a negative index is dropped");
    assert.equal(row.runlogAnomalies[0]!.digest, undefined, "an object key in the digest field fails the 12-hex shape gate");
    assert.equal(row.runlogAnomalies[0]!.entryCount, 3);
    assert.equal(row.writerRefusals["source-enumerated-zero"], 2);
    assert.equal(Object.keys(row.writerRefusals).length, 1, "a caller-authored refusal kind must never become a storage key");
    assert.equal(row.attestCoverage, undefined, "a coverage mode outside the closed set is dropped");
    assertRedacted("applyIntegrityFaults (hostile body)", rec);
  });

  await check("DO chokepoint: the WEAKER coverage claim wins across folds (a later clean run cannot erase it)", () => {
    let rec = applyIntegrityFaults(undefined, "dp1", { attestCoverage: "sampled-no-presence" }, 1);
    rec = applyIntegrityFaults(rec, "dp1", { attestCoverage: "sampled" }, 2);
    assert.equal(rec.dp1!.attestCoverage, "sampled-no-presence", "the overclaiming run is the finding and must not be overwritten");
    // "full" is never posted, and would be ignored if it were.
    rec = applyIntegrityFaults(rec, "dp1", { attestCoverage: "full" }, 3);
    assert.equal(rec.dp1!.attestCoverage, "sampled-no-presence");
  });

  await check("DO chokepoint: a real drained snapshot folds whole (the round trip the pack actually makes)", async () => {
    const entries = [entry(1, RUN_A, null), entry(1, RUN_B, RUN_A)];
    const store = await storeFor(signer, entries);
    const snap = await drainAfter(async () => {
      await checkRunlogFreshness(store, RUN_A, rootFor(1, null), signer.verifier, { allowStale: true });
    });
    const rec = applyIntegrityFaults(undefined, "dp_real", JSON.parse(JSON.stringify(snap)), 1_800_000_000_000);
    const row = rec.dp_real!;
    assert.equal(row.runlogAnomalies[0]!.kind, "duplicate-index", "the forensic row must survive the wire and the applier");
    assert.match(row.runlogAnomalies[0]!.digest ?? "", /^[0-9a-f]{12}$/);
    assertRedacted("applyIntegrityFaults (real snapshot)", rec);
  });

  console.log(failures === 0 ? "validate-format-root-evidence: PASS" : `validate-format-root-evidence: ${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
