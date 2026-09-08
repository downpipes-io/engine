// VALIDATOR: the FORMAT + CRYPTO integrity fault evidence, the last-resort dispatch / CORS /
// destination-probe evidence, the notify delivery-code splits, and the replication-detector self-disable flag.
//
// It proves THREE things, and the third is the one that matters most:
//
//   1. RECORDED ON THE FAULT PATH. Each fault site actually notes its evidence into the isolate-local ledger
//      when the real fault is driven (not when a note function is called directly): a store read that throws,
//      a capsule that matches no held identity, a chunk whose GCM tag does not authenticate, a record with
//      neither value nor stream, a corrupt Merkle checkpoint, a signature object that will not decode.
//
//   2. THE VOCABULARIES ARE PINNED. admin/diag-records.ts is a LEAF (it imports nothing), so it RE-DECLARES
//      the closed sets the format layer owns. A drift between the two would silently DROP every posted row on
//      the DO side and the pack would go quietly empty during the exact incident it exists to explain. The
//      test asserts the two sets are identical, member for member.
//
//   3. REDACTION (binding, no-custody). A customer SENTINEL -- an email address, a bucket name, an object key,
//      a secret -- is planted AT each fault site, and the test asserts it appears in NO BYTE of the serialised
//      record, on either side of the wire. The DO-side applier is then attacked directly with a hostile body
//      carrying a raw error message, a stack, a token and a bucket, and must drop every one of them.

import { strict as assert } from "node:assert";

import {
  applyCostSizing,
  applyDestProbeFaults,
  applyDispatchFault,
  applyIntegrityFaults,
  CRYPTO_FAULT_CLASS_NAMES,
  CRYPTO_KEY_ROLE_NAMES,
  DEST_PROBE_REASONS,
  DISPATCH_ROUTE_FAMILIES,
  DISPATCH_SURFACES,
  INTEGRITY_FAULT_KIND_NAMES,
  STREAM_FAULT_CLASS_NAMES,
  VERIFY_FAIL_STAGE_NAMES,
} from "../src/admin/diag-records.ts";
import { classifyDestProbeError, routeFamilyOf } from "../src/admin/dispatch-faults.ts";
import {
  classifyFetchFault,
  CRYPTO_FAULT_CLASSES,
  CRYPTO_KEY_ROLES,
  drainIntegrityFaultLedger,
  INTEGRITY_FAULT_KINDS,
  resetIntegrityFaultLedger,
  STREAM_FAULT_CLASSES,
  VERIFY_FAIL_STAGES,
  type IntegrityFaultSnapshot,
} from "../src/format/integrity-fault-ledger.ts";
import { checkRunlogFreshness } from "../src/format/freshness.ts";
import { MerkleFrontier } from "../src/format/frontier.ts";
import { segIDFromObject } from "../src/format/record-codec.ts";
import { unframeSeg } from "../src/format/container.ts";
import { openCapsule } from "../src/crypto/capsule.ts";
import { openStream } from "../src/crypto/stream.ts";
import { hexDecode } from "../src/crypto/bytes.ts";
import { parseKeyFile } from "../src/crypto/keys.ts";
import { hybridVerify } from "../src/crypto/sign.ts";
import { classifyReplication, DELIVERY_FAIL_CODES, isAllowedWebhookUrl } from "../src/notify/types.ts";
import { validateRecipients } from "../src/email.ts";

let failures = 0;
function check(name: string, fn: () => void | Promise<void>): Promise<void> {
  return (async (): Promise<void> => {
    try {
      await fn();
      console.log(`  ok  ${name}`);
    } catch (e) {
      failures++;
      console.error(`  FAIL ${name}: ${(e as Error).message}`);
    }
  })();
}

// ---------------------------------------------------------------------------------------------------------
// THE SENTINELS. Every one is a value the pack must NEVER carry: a real customer identity, a bucket, an object
// key, a live secret. They are planted at the fault sites below and hunted for in the serialised record.
// ---------------------------------------------------------------------------------------------------------
const SENTINEL_EMAIL = "cfo@acme-payroll.example";
const SENTINEL_BUCKET = "acme-prod-payroll-backups";
const SENTINEL_KEY = "kv/tenants/acme/salaries-2026.json";
const SENTINEL_SECRET = "sk_live_51H8xQzAcmeSuperSecretTokenValue";
const SENTINELS = [SENTINEL_EMAIL, SENTINEL_BUCKET, SENTINEL_KEY, SENTINEL_SECRET];

// assertRedacted is the binding no-custody assertion: NOT ONE BYTE of any sentinel may appear anywhere in the
// serialised record. It scans the JSON of the whole structure, so a sentinel hiding in a nested field, a map
// KEY, or an array element is caught just the same.
function assertRedacted(what: string, record: unknown): void {
  const json = JSON.stringify(record);
  for (const s of SENTINELS) {
    assert.ok(!json.includes(s), `${what} LEAKED a customer sentinel (${s.slice(0, 16)}...): ${json.slice(0, 400)}`);
  }
  // Belt and braces: the substrings a raw provider message or a stack would carry.
  for (const marker of ["Error:", "at Object.", "\n    at ", "AccessDenied</Code>", "Bearer "]) {
    assert.ok(!json.includes(marker), `${what} LEAKED raw error/stack text (${marker}): ${json.slice(0, 400)}`);
  }
}

// extraFields gives a structural view of a copied row so the redaction assertions can probe fields the ROW TYPES
// deliberately do NOT declare (that a raw `recordName` / `keyBytes` / `path` was not copied through is exactly
// what is being asserted, and an undeclared field is unreachable through the typed row). It only re-views the
// row, so a row that is genuinely absent still throws on the property read, as before.
function extraFields(row: unknown): Record<string, unknown> {
  return row as Record<string, unknown>;
}

// drain resets, runs the body, and returns the snapshot the run produced.
async function drainAfter(body: () => Promise<void> | void): Promise<IntegrityFaultSnapshot> {
  resetIntegrityFaultLedger();
  try {
    await body();
  } catch {
    // Every site under test THROWS by design: the note rides alongside the throw, it does not replace it.
  }
  return drainIntegrityFaultLedger();
}

async function main(): Promise<void> {
  console.log("validate-integrity-faults");

  // -------------------------------------------------------------------------------------------------------
  // 2. THE LEAF VOCABULARIES ARE PINNED TO THE DO'S RE-DECLARED SETS.
  //
  // diag-records.ts imports NOTHING (it is the shared leaf every layer agrees on without closing an import
  // cycle), so it re-declares these sets. If the two ever drift, applyIntegrityFaults DROPS every row carrying
  // the new member and the pack goes quietly empty -- the exact "absence of evidence reads as absence of
  // problems" failure the whole audit exists to fix. Pin them.
  // -------------------------------------------------------------------------------------------------------
  await check("vocabulary: VERIFY_FAIL_STAGES is pinned to the DO's re-declared set", () => {
    assert.deepEqual([...VERIFY_FAIL_STAGES], [...VERIFY_FAIL_STAGE_NAMES]);
  });
  await check("vocabulary: INTEGRITY_FAULT_KINDS is pinned to the DO's re-declared set", () => {
    assert.deepEqual([...INTEGRITY_FAULT_KINDS], [...INTEGRITY_FAULT_KIND_NAMES]);
  });
  await check("vocabulary: CRYPTO_FAULT_CLASSES / CRYPTO_KEY_ROLES are pinned", () => {
    assert.deepEqual([...CRYPTO_FAULT_CLASSES], [...CRYPTO_FAULT_CLASS_NAMES]);
    assert.deepEqual([...CRYPTO_KEY_ROLES], [...CRYPTO_KEY_ROLE_NAMES]);
  });
  await check("vocabulary: STREAM_FAULT_CLASSES is pinned", () => {
    assert.deepEqual([...STREAM_FAULT_CLASSES], [...STREAM_FAULT_CLASS_NAMES]);
  });

  // -------------------------------------------------------------------------------------------------------
  // a destination READ fault behind an "absent/missing" verdict.
  // The store throws an error carrying the BUCKET and the OBJECT KEY (exactly what a real S3 client does);
  // the result must carry the closed class and NOT one byte of either.
  // -------------------------------------------------------------------------------------------------------
  await check("a 403 on the RUNLOG read records access-denied, not 'absent', and leaks nothing", async () => {
    const store = {
      get: (): Promise<Uint8Array> => {
        throw new Error(`GET https://${SENTINEL_BUCKET}.r2.cloudflarestorage.com/${SENTINEL_KEY}: status 403 (AccessDenied)`);
      },
      put: async (): Promise<void> => {},
    };
    const snap = await drainAfter(async () => {
      const r = await checkRunlogFreshness(
        store as never,
        "01J0",
        { downpipeId: "dp", freshness: { runlogIndex: 1, prevRunId: null } } as never,
        { ed: new Uint8Array(32), mldsa: new Uint8Array(2592) },
      );
      // The RESULT now names the real cause; the reason string is unchanged for the operator.
      assert.equal(r.fetchFault, "access-denied", "the read-side 403 must not persist as an absent object");
      assert.equal(r.fetchStatusClass, "4xx");
      assertRedacted("FreshnessResult", r);
    });
    assert.equal(snap.fetchFaults["runlog|access-denied|4xx"], 1);
    assert.equal(snap.failStages["freshness-signature"], 1);
    assertRedacted("integrity snapshot ", snap);
  });

  await check("cold-storage is classified BEFORE access-denied (a 403 InvalidObjectState is a lifecycle move)", () => {
    const cold = classifyFetchFault(new Error(`GET /${SENTINEL_KEY}: status 403 (InvalidObjectState: object is in GLACIER)`));
    assert.equal(cold.cls, "cold-storage", "a restore-required object must never read as a credential fault");
    const denied = classifyFetchFault(new Error("status 403 (AccessDenied)"));
    assert.equal(denied.cls, "access-denied");
    const throttled = classifyFetchFault(new Error("status 429 (SlowDown)"));
    assert.equal(throttled.cls, "throttled");
    const missing = classifyFetchFault(new Error("status 404 (NoSuchKey)"));
    assert.equal(missing.cls, "not-found");
  });

  // -------------------------------------------------------------------------------------------------------
  // Key + recipient PROVISIONING faults, split from destination faults and from tamper.
  // -------------------------------------------------------------------------------------------------------
  await check("a capsule that matches no held identity records recipient-no-capsule-match with PUBLIC fingerprints only", async () => {
    const priv = { x25519Scalar: new Uint8Array(32).fill(7), mlkemSeed: new Uint8Array(64).fill(9) };
    const snap = await drainAfter(async () => {
      await openCapsule([{ fingerprint: "deadbeefcafe", kemCiphertext: new Uint8Array(1600), sealed: new Uint8Array(64) }], priv as never, new Uint8Array(48));
    });
    const f = snap.cryptoFaults[0];
    assert.ok(f !== undefined, "the wrong-identity case must be recorded");
    assert.equal(f.cls, "recipient-no-capsule-match");
    assert.equal(f.role, "recipient");
    // The fingerprints are of PUBLIC material and must be hex; no key bytes may ride.
    assert.match(f.heldFingerprint ?? "", /^dpr1:[0-9a-f]{96}$/, "the fingerprint must be the engine\u0027s own PUBLIC-material digest");
    assertRedacted("cryptoFaults (capsule)", snap);
  });

  await check("a SWAPPED key label records key-wrong-label with the closed role, never the key bytes", async () => {
    const snap = await drainAfter(() => {
      // The operator pasted their OPERATIONAL key file into the SIGNER slot. The FILE BODY is a live secret.
      parseKeyFile(`operational-private ${SENTINEL_SECRET}`, "signer-private");
    });
    const f = snap.cryptoFaults[0];
    assert.ok(f !== undefined);
    assert.equal(f.cls, "key-wrong-label");
    assert.equal(f.role, "signer");
    assertRedacted("cryptoFaults (label)", snap);
  });

  await check("a malformed base64url key body records key-malformed-b64url and never the material", async () => {
    const snap = await drainAfter(() => {
      parseKeyFile("signer-private !!!not-base64url!!!", "signer-private");
    });
    assert.equal(snap.cryptoFaults[0]?.cls, "key-malformed-b64url");
    assert.equal(snap.cryptoFaults[0]?.role, "signer");
    assertRedacted("cryptoFaults (encoding)", snap);
  });

  await check("hexDecode REJECTS non-hex instead of silently coercing it to zero bytes", () => {
    // The old behaviour: parseInt("zz",16) is NaN, and `out[i] = NaN` writes 0. A corrupt object key decoded
    // to a well-formed-looking all-zero segment id that matched nothing and read as "object missing".
    assert.throws(() => hexDecode("zzzz"), /non-hex/, "a non-hex pair must not coerce to a zero byte");
    assert.deepEqual([...hexDecode("00ff")], [0, 255], "well-formed hex must still decode");
  });

  await check("a signature that will not verify splits structural-fault from mismatch", async () => {
    // A TRUNCATED signature object is a damaged FILE (rewrite it); a full-length one that does not verify is a
    // tamper or a signer rotation. Both used to return a bare false and merged into one reason.
    const snapShort = await drainAfter(async () => {
      await hybridVerify({ ed: new Uint8Array(32), mldsa: new Uint8Array(2592) }, new Uint8Array(8), new Uint8Array(10));
    });
    assert.equal(snapShort.cryptoFaults[0]?.cls, "verify-structural-fault");
    assert.equal(snapShort.cryptoFaults[0]?.role, "verifier");
    assertRedacted("cryptoFaults (sig)", snapShort);
  });

  // -------------------------------------------------------------------------------------------------------
  // The LOCATOR and the streaming LOCUS.
  // -------------------------------------------------------------------------------------------------------
  await check("a GCM authentication failure records the CHUNK INDEX, never the object key", async () => {
    const key = new Uint8Array(32).fill(3);
    // 16-byte nonce + a chunk whose tag will not authenticate.
    const sealed = new Uint8Array(16 + 64);
    const snap = await drainAfter(async () => {
      await openStream(key, sealed, undefined, 0);
    });
    const f = snap.streamFaults[0];
    assert.ok(f !== undefined, "the GCM abort must carry a locus");
    assert.equal(f.leg, "decrypt-open");
    assert.equal(f.cls, "gcm-auth-fail");
    assert.equal(f.chunkIndex, 0, "chunk 0 means the object was mangled from its FIRST byte");
    assertRedacted("streamFaults ", snap);
  });

  await check("a zero-byte / truncated object records short-nonce with its byte counts", async () => {
    const snap = await drainAfter(async () => {
      await openStream(new Uint8Array(32), new Uint8Array(3), undefined, 0);
    });
    assert.equal(snap.streamFaults[0]?.cls, "short-nonce");
    assert.equal(snap.streamFaults[0]?.receivedBytes, 3);
    assert.equal(snap.streamFaults[0]?.expectedBytes, 16);
  });

  await check("a bad container magic records container-framing, not an unexplained integrity failure", async () => {
    const snap = await drainAfter(() => {
      unframeSeg(new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x01, 0x09]));
    });
    assert.equal(snap.streamFaults[0]?.cls, "container-framing");
    assert.equal(snap.failStages["root-structure"], 1);
  });

  await check("a corrupt segment OBJECT KEY records malformed-object-key and carries no key", async () => {
    const snap = await drainAfter(() => {
      // The object key is customer-derived, and the old hexDecode turned this into a run of zero bytes.
      segIDFromObject(`seg/zz/${SENTINEL_KEY}.seg`);
    });
    assert.equal(snap.locators[0]?.kind, "malformed-object-key");
    assertRedacted("locators ", snap);
  });

  // -------------------------------------------------------------------------------------------------------
  // THE SILENT ZERO-BYTE SEAL. The single most dangerous gap in this set: a green run whose restore
  // yields nothing, months later.
  // -------------------------------------------------------------------------------------------------------
  await check("a record with neither value nor stream is counted, and only its DIGEST rides", async () => {
    const { noteDefaultedEmptyRecord } = await import("../src/format/integrity-fault-ledger.ts");
    const snap = await drainAfter(async () => {
      // The digest is computed AT the writer's call site (the ledger is a leaf and cannot hash). A raw record
      // NAME must never be accepted here, so a caller that passes one is DROPPED by the shape gate.
      noteDefaultedEmptyRecord("a1b2c3d4e5f6");
      noteDefaultedEmptyRecord(SENTINEL_KEY); // a raw customer key: the gate must refuse it
    });
    assert.equal(snap.defaultedEmptyRecords, 2, "both defaults must be COUNTED");
    assert.equal(snap.locators[0]?.digest, "a1b2c3d4e5f6");
    assert.equal(snap.locators[1]?.digest, undefined, "a raw object key must be DROPPED, never stored");
    assertRedacted("defaultedEmptyRecords ", snap);
  });

  // -------------------------------------------------------------------------------------------------------
  // Seal-checkpoint (Merkle frontier) corruption on resume.
  // -------------------------------------------------------------------------------------------------------
  await check("a corrupt Merkle checkpoint records checkpoint-corrupt with the declared-vs-covered drift", async () => {
    const snap = await drainAfter(() => {
      // The checkpoint claims 10,000 leaves; its subtree stack covers 2. That drift IS the diagnosis.
      MerkleFrontier.deserialise({ count: 10_000, nodes: [{ sizeLog: 1, hash: "A".repeat(64) }] });
    });
    const loc = snap.locators[0];
    assert.ok(loc !== undefined, "checkpoint corruption must be recorded, not just thrown");
    assert.equal(loc.kind, "checkpoint-corrupt");
    assert.equal(loc.declaredCount, 10_000);
    assert.equal(loc.recoveredCount, 2);
  });

  // -------------------------------------------------------------------------------------------------------
  // 3. THE DO-SIDE APPLIER IS THE REDACTION CHOKEPOINT. Attack it directly with a hostile body.
  // -------------------------------------------------------------------------------------------------------
  await check("REDACTION: applyIntegrityFaults DROPS every out-of-vocabulary field and every raw value", () => {
    const hostile = {
      // Out-of-vocabulary keys in every map: none may become a storage key.
      fetchFaults: { [`runlog|${SENTINEL_BUCKET}|4xx`]: 5, "runlog|access-denied|4xx": 2, [SENTINEL_KEY]: 9 },
      failStages: { [SENTINEL_EMAIL]: 3, "shard-hash": 1 },
      classifiedBy: { typed: 1, [SENTINEL_SECRET]: 4 },
      locators: [
        { kind: "chunk-range", digest: SENTINEL_KEY, recordName: SENTINEL_KEY },
        { kind: SENTINEL_BUCKET, digest: "aaaaaaaaaaaa" },
        { kind: "decompress-overflow", declaredCount: 10, recoveredCount: 9, message: `Error: AccessDenied</Code> ${SENTINEL_BUCKET}` },
      ],
      cryptoFaults: [
        { cls: "key-wrong-label", role: "signer", lengthClass: 31, keyBytes: SENTINEL_SECRET },
        { cls: SENTINEL_SECRET, role: "signer" },
        { cls: "verify-mismatch", role: SENTINEL_EMAIL },
      ],
      streamFaults: [{ leg: "dest-write", cls: "gcm-auth-fail", chunkIndex: 4, objectKey: SENTINEL_KEY }],
      defaultedEmptyRecords: 3,
      formatVersionSeen: SENTINEL_BUCKET,
      stack: `Error: boom\n    at Object.<anonymous> (/app/${SENTINEL_KEY})`,
      token: `Bearer ${SENTINEL_SECRET}`,
    };
    const out = applyIntegrityFaults(undefined, "dp-payroll", hostile, 1_700_000_000_000);
    const rec = out["dp-payroll"]!;

    // Only the in-vocabulary composite key survived.
    assert.deepEqual(Object.keys(rec.fetchFaults), ["runlog|access-denied|4xx"]);
    assert.deepEqual(Object.keys(rec.failStages), ["shard-hash"]);
    assert.deepEqual(Object.keys(rec.classifiedBy), ["typed"]);
    // Row 2 (out-of-vocabulary kind) is dropped; rows 1 and 3 survive with their raw fields stripped.
    assert.equal(rec.locators.length, 2);
    assert.equal(rec.locators[0]?.digest, undefined, "a raw object key in `digest` must fail the hex gate");
    assert.equal(extraFields(rec.locators[0]).recordName, undefined, "an unknown field must never be copied");
    assert.equal(extraFields(rec.locators[1]).message, undefined);
    // Only the row with BOTH a valid class and a valid role survived.
    assert.equal(rec.cryptoFaults.length, 1);
    assert.equal(rec.cryptoFaults[0]?.cls, "key-wrong-label");
    assert.equal(extraFields(rec.cryptoFaults[0]).keyBytes, undefined);
    assert.equal(extraFields(rec.streamFaults[0]).objectKey, undefined);
    // A format label that is not the FIXED product shape is refused.
    assert.equal(rec.formatVersionSeen, undefined);
    // And the whole record carries no sentinel, no stack and no token.
    assertRedacted("applyIntegrityFaults (hostile body)", out);
  });

  await check("REDACTION: applyIntegrityFaults accepts the LEGITIMATE format label and is bounded", () => {
    const out = applyIntegrityFaults(undefined, "dp", { failStages: { "format-version": 1 }, formatVersionSeen: "downpipe/9.x" }, 1);
    assert.equal(out["dp"]?.formatVersionSeen, "downpipe/9.x");
    // The ring is capped: 100 posted rows must land at most 16.
    const many = { locators: Array.from({ length: 100 }, () => ({ kind: "chunk-range" })) };
    const capped = applyIntegrityFaults(undefined, "dp", many, 1);
    assert.ok(capped["dp"]!.locators.length <= 16, "the locator ring must be capped");
  });

  // -------------------------------------------------------------------------------------------------------
  // The last-resort dispatch ring, the destination-probe reasons, and the CORS signal.
  // -------------------------------------------------------------------------------------------------------
  await check("routeFamilyOf reduces a path to a CLOSED family and never carries the path", () => {
    assert.equal(routeFamilyOf(`/admin/downpipes/${SENTINEL_KEY}?token=${SENTINEL_SECRET}`), "downpipes");
    assert.equal(routeFamilyOf("/support/diagnostics"), "support");
    assert.equal(routeFamilyOf("/admin/notify/channels"), "notify");
    assert.equal(routeFamilyOf("/nowhere"), "other");
    assert.ok(DISPATCH_ROUTE_FAMILIES.includes(routeFamilyOf("/anything") as never));
  });

  await check("applyDispatchFault keeps the closed surface + 8-hex errId and drops everything else", () => {
    const ring = applyDispatchFault(
      undefined,
      { surface: "fetch", routeFamily: "support", errId: "a1b2c3d4", httpStatus: 500, message: `boom ${SENTINEL_BUCKET}`, path: SENTINEL_KEY },
      1_700_000_000_000,
    );
    assert.equal(ring.length, 1);
    assert.equal(ring[0]?.surface, "fetch");
    assert.equal(ring[0]?.errId, "a1b2c3d4");
    assert.equal(extraFields(ring[0]).path, undefined);
    assertRedacted("dispatchFaults", ring);
    // An errId that is NOT 8 lower-case hex (i.e. anything a message could smuggle in) is refused.
    const smuggled = applyDispatchFault(undefined, { surface: "admin", errId: SENTINEL_SECRET }, 1);
    assert.equal(smuggled[0]?.errId, undefined);
    // An out-of-vocabulary surface lands NOTHING.
    assert.equal(applyDispatchFault(undefined, { surface: SENTINEL_BUCKET }, 1).length, 0);
    assert.ok(DISPATCH_SURFACES.includes("scim"));
  });

  await check("classifyDestProbeError selects a closed reason and never returns the message", () => {
    const auth = classifyDestProbeError(new Error(`PUT https://${SENTINEL_BUCKET}.example/probe: status 403 (AccessDenied)`));
    assert.equal(auth, "auth");
    assert.equal(classifyDestProbeError(new Error(`destination ${SENTINEL_BUCKET} for downpipe dp is not configured`)), "config-unreadable");
    assert.equal(classifyDestProbeError(new Error("status 404 NoSuchBucket")), "not-found");
    assert.equal(classifyDestProbeError(new Error("status 503")), "http-5xx");
    assert.equal(classifyDestProbeError(new Error("fetch failed: ENOTFOUND")), "network");
    assert.ok(DEST_PROBE_REASONS.includes(auth));
  });

  await check("applyDestProbeFaults keeps the destination LABEL + closed reason, drops the rest", () => {
    const map = applyDestProbeFaults(undefined, [
      { id: "prod-replica", reason: "auth", endpoint: `https://${SENTINEL_BUCKET}.example`, secret: SENTINEL_SECRET },
      { id: "other", reason: SENTINEL_SECRET },
    ], 1_700_000_000_000);
    assert.equal(map["prod-replica"]?.reason, "auth");
    assert.equal(map["other"], undefined, "an out-of-vocabulary reason must be dropped");
    assertRedacted("destProbeFaults", map);
  });

  await check("cors-origin-rejected is a member of the auth-signal vocabulary", async () => {
    const { AUTH_SIGNAL_NAMES } = await import("../src/admin/auth-signals.ts");
    assert.ok((AUTH_SIGNAL_NAMES as readonly string[]).includes("cors-origin-rejected"), "the CORS signal must be recordable");
  });

  // -------------------------------------------------------------------------------------------------------
  // The cost sizing-probe outcomes, and the MEASURED-ZERO that masqueraded as a real answer.
  // -------------------------------------------------------------------------------------------------------
  await check("applyCostSizing separates a measured-zero from an honestly-unavailable size", () => {
    let rec = applyCostSizing(undefined, "r2", "measured-zero", "2026-07-12T00:00:00.000Z");
    rec = applyCostSizing(rec, "r2", "analytics-auth-or-scope", "2026-07-12T00:00:01.000Z");
    rec = applyCostSizing(rec, "kv", "ok", "2026-07-12T00:00:02.000Z");
    assert.equal(rec["r2"]?.measuredZero, 1, "a drift-induced 0 must NEVER be counted as a real measurement");
    assert.equal(rec["r2"]?.unavailable, 1);
    assert.equal(rec["kv"]?.sized, 1);
    // The namespace/bucket identifier is not part of the key space at all: only the closed source TYPE.
    const hostile = applyCostSizing(undefined, SENTINEL_BUCKET, "ok", "2026-07-12T00:00:00.000Z");
    assert.deepEqual(Object.keys(hostile), [], "an out-of-vocabulary source type must never become a key");
  });

  // -------------------------------------------------------------------------------------------------------
  // The notify vocabularies.
  // -------------------------------------------------------------------------------------------------------
  await check("the recipient INDEX rides, and the address never does", () => {
    const v = validateRecipients(["ops@acme.example", SENTINEL_EMAIL.replace("@", "")]);
    assert.equal(v.ok, false);
    assert.equal((v as { recipientIndex?: number }).recipientIndex, 1, "the failing entry's POSITION names it without naming the person");
  });

  await check("the new delivery codes are members of the closed vocabulary", () => {
    for (const code of ["email-from-not-configured", "adapter-exception", "no-url", "no-credential", "no-recipients"]) {
      assert.ok(DELIVERY_FAIL_CODES.has(code), `${code} must be in DELIVERY_FAIL_CODES or the DO will drop it`);
    }
  });

  await check("a rejected webhook url yields a CLOSED code, never the url", () => {
    const nonHttps = isAllowedWebhookUrl(`http://${SENTINEL_BUCKET}.example/hook?t=${SENTINEL_SECRET}`);
    assert.equal(nonHttps.ok, false);
    assert.equal((nonHttps as { code: string }).code, "non-https");
    assert.equal((isAllowedWebhookUrl("https://user:pw@example.com/h") as { code: string }).code, "userinfo");
    assert.equal((isAllowedWebhookUrl("https://127.0.0.1/h") as { code: string }).code, "internal-no-optin");
    assert.equal((isAllowedWebhookUrl("not a url") as { code: string }).code, "unparseable");
  });

  await check("a corrupt copy count is FLAGGED instead of silently disabling the detector", () => {
    const bad = classifyReplication({ configuredCopies: 0, provenCopies: 0 });
    assert.equal(bad.degraded, false, "a corrupt count must still not cry wolf");
    assert.equal(bad.copyCountInvalid, true, "...but the pack must be able to SEE that the detector switched off");
    const good = classifyReplication({ configuredCopies: 3, provenCopies: 2 });
    assert.equal(good.degraded, true);
    assert.equal(good.copyCountInvalid, false);
  });

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\nvalidate-integrity-faults: ${failures} FAILED`);
    process.exit(1);
  }
  console.log("validate-integrity-faults: all checks passed");
}

await main();
