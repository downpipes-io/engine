// The integrity-vs-availability classifier on the restore / 3-2-1 fallback path must be ROBUST, not a
// brittle keyword regex over the raw reader message. The DR guarantee is: INTEGRITY is NOT availability. A
// tamper / completeness / structural / signature / freshness failure must surface IMMEDIATELY and NEVER
// fall through to a 3-2-1 replica (a replica holds the SAME signed run, so reading it only masks the very
// corruption the operator must see). The replica fallback is reserved STRICTLY for true availability faults
// (object-missing / 404, 403, 5xx, network).
//
// The bug this validator guards: several genuine integrity/completeness failures the
// verifying reader throws did NOT match the old per-site regex
//   /signature did not verify|key commitment|hash does not match|Merkle root|failed its plaintext hash/
// and DEFAULTED to "recovery check failed", which IS in the replica-fallback set (isReplicaFallbackReason).
// So a TRUNCATED / INCOMPLETE archive (the reader's "recovered N records, the root declares M" completeness
// error) would be classified as a fallback-eligible reason and could wrongly fall through to a replica
// instead of failing loud. The fix makes the reader raise a STRUCTURED RunIntegrityError and the classifier
// route by TYPE, so ANY integrity/completeness failure is non-fallback by construction.
//
// Proven here, all with REAL crypto + the REAL verifying reader (openRun) + the REAL classifier:
//   1. The reader THROWS the structured RunIntegrityError for a validly-signed-but-incomplete archive (the
//      completeness "recovered N, root declares M" error) -- not a plain Error.
//   2. The OLD regex MIS-ROUTES that completeness error to a fallback-eligible reason (the red case).
//   3. The NEW classifyRestoreFailure routes it to REASON_INTEGRITY, and isReplicaFallbackReason is FALSE:
//      a truncated/incomplete archive does NOT fall back to a replica.
//   4. A GENUINE availability fault (object missing) still classifies to a fallback reason and DOES fall back.
//   5. End to end through runRestore: a truncated primary surfaces "integrity check failed" (non-fallback),
//      while a missing object surfaces a fallback-eligible availability reason.
// In-memory doubles only; no network, no deploy, no cost. Run: node test/validate-restore-integrity-class.ts.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, buildSignedRoot, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, loadIdentity, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { RunIntegrityError, isIntegrityFailure } from "../src/format/integrity-error.ts";
import {
  classifyRestoreFailure,
  isReplicaFallbackReason,
  destRejectionDetail,
  destAccessReason,
  REASON_INTEGRITY,
  REASON_OBJECT_MISSING,
  REASON_DESTINATION_ACCESS,
} from "../src/restore-reasons.ts";
import { runRestore } from "../src/admin/restore.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import type { RestorePlan } from "../src/admin/restore-types.ts";
import type { RootManifest } from "../src/format/manifest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_throwaway";
const KVSET: Record<string, string> = { "a": "alpha-value", "b": "beta-value", "user:42": "gamma-value-longer" };

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// storeFor adapts an in-memory object map to the ObjectStore the reader reads. A missing object throws the
// "is missing" availability error, exactly as the in-account read-back store (restore-open.ts) does.
function storeFor(objs: Map<string, Uint8Array>): ObjectStore {
  return {
    get: async (k: string) => {
      const v = objs.get(k);
      if (!v) throw new Error(`object ${k} is missing`);
      return v;
    },
  };
}

// THE OLD CLASSIFIER (the brittle pre-fix regex), reproduced verbatim so the test proves it MIS-ROUTES the
// completeness error to a fallback-eligible reason. This is the red-before-green control: it must classify
// the truncated archive as the catch-all "recovery check failed", which isReplicaFallbackReason accepts.
function oldRegexClassify(m: string): string {
  if (/signature did not verify|key commitment|hash does not match|Merkle root|failed its plaintext hash/.test(m)) return "integrity check failed";
  if (/is missing|status 404/.test(m)) return "object missing";
  if (/status \d/.test(m)) return "destination access error";
  if (/RUNLOG|freshness|latest run|stale/.test(m)) return "freshness check failed";
  if (/missing required configuration/.test(m)) return "engine not fully configured";
  return "recovery check failed";
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const mldsa = mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  // The parsed in-account read-back identity the verifying reader unwraps the capsule with.
  const opIdentity = loadIdentity(b64urlEncode(op.identity));
  const master = rand(32);

  // Seal a real KV archive (3 records) into an in-memory object map with genuine hybrid signatures.
  const objs = await buildArchive({
    downpipeId: "dp_h2",
    downpipeName: "h2",
    cadence: "3600s",
    runId: RUN_ID,
    master,
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: NS })),
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });

  // Sanity: the intact archive opens clean (the verifying reader recovers all 3 records).
  {
    const run = await openRun(storeFor(objs), RUN_ID, opIdentity, verifier, { verifyFreshness: false, allowStale: true });
    ok("intact archive opens: 3 records recovered", run.records.length === 3);
  }

  // ---- Build a TRUNCATED/INCOMPLETE-but-validly-signed archive ----
  // Re-sign the SAME shards + Merkle root + master + recipients with an INFLATED declaredRecordCount (4 vs
  // the real 3). The signature verifies (we re-signed with the real signer), the capsule unwraps (same
  // master/recipients), so the reader reaches verifyRecords and throws the COMPLETENESS error
  // "recovered 3 records, the root declares 4" -- AFTER the signature, exactly the class the old regex missed.
  const truncated = new Map(objs);
  {
    const rootText = new TextDecoder().decode(objs.get(`run/${RUN_ID}/root.manifest.json`)!);
    const root = JSON.parse(rootText) as RootManifest;
    const { rootBytes, sigBytes } = await buildSignedRoot({
      downpipeId: root.downpipeId,
      runId: RUN_ID,
      createdAt: root.createdAt,
      master,
      recipients: [breakGlass.entry, op.entry],
      signer,
      shards: root.shards.map((s) => ({ id: s.id, object: s.object, sha384: s.sha384 })),
      declaredRecordCount: root.declaredRecordCount + 1, // 4: claims one more record than the shard holds
      merkleRootHex: root.merkleRoot,
      prevRunId: root.freshness.prevRunId ?? null,
      runlogIndex: root.freshness.runlogIndex,
      randomNonce: () => rand(16),
    });
    truncated.set(`run/${RUN_ID}/root.manifest.json`, rootBytes);
    truncated.set(`run/${RUN_ID}/root.manifest.json.sig`, sigBytes);
  }

  console.log("-- 1. the reader raises a STRUCTURED integrity failure for the incomplete archive --");
  let completenessErr: unknown;
  try {
    await openRun(storeFor(truncated), RUN_ID, opIdentity, verifier, { verifyFreshness: false, allowStale: true });
    ok("the incomplete archive is REJECTED by the reader", false);
  } catch (e) {
    completenessErr = e;
    ok("the incomplete archive is REJECTED by the reader", true);
    ok("the rejection is the completeness error (recovered N, root declares M)", /recovered \d+ records, the root declares \d+/.test((e as Error).message));
    ok("the rejection is a structured RunIntegrityError (not a plain Error)", e instanceof RunIntegrityError && isIntegrityFailure(e));
    ok("its structured category is 'integrity'", (e as RunIntegrityError).category === "integrity");
  }

  console.log("-- 2. RED CONTROL: the OLD regex MIS-ROUTES the completeness error to a fallback reason --");
  {
    const oldReason = oldRegexClassify((completenessErr as Error).message);
    ok("old regex classifies the completeness error as 'recovery check failed' (NOT integrity)", oldReason === "recovery check failed");
    ok("old regex's reason IS replica-fallback-eligible (the bug: a corrupt archive would fall back)", isReplicaFallbackReason(oldReason) === true);
  }

  console.log("-- 3. GREEN: the new classifier routes the completeness error to INTEGRITY (non-fallback) --");
  {
    const reason = classifyRestoreFailure(completenessErr);
    ok("new classifier returns REASON_INTEGRITY for the completeness error", reason === REASON_INTEGRITY);
    ok("REASON_INTEGRITY is NOT replica-fallback-eligible (it surfaces loud, never falls back)", isReplicaFallbackReason(reason) === false);
  }

  console.log("-- 4. a genuine AVAILABILITY fault still classifies as fallback-eligible --");
  {
    // The store-level "object ... is missing" is the true availability fault a healthy replica could remedy.
    const availErr = new Error(`object run/${RUN_ID}/manifest/00000.dpe is missing`);
    const reason = classifyRestoreFailure(availErr);
    ok("a missing object classifies to REASON_OBJECT_MISSING", reason === REASON_OBJECT_MISSING);
    ok("REASON_OBJECT_MISSING IS replica-fallback-eligible (a replica can remedy availability)", isReplicaFallbackReason(reason) === true);
    // And the structured-type check never mis-fires on a plain availability Error.
    ok("a plain availability Error is NOT classed as a structured integrity failure", isIntegrityFailure(availErr) === false);
  }

  console.log("-- 5. end to end through runRestore: truncated -> non-fallback integrity; missing -> fallback --");
  {
    const operationalPrivateB64 = b64urlEncode(op.identity);
    // The R2 binding the dest factory reads the archive through (DEST_KIND r2), populated from an object map.
    const r2For = (m: Map<string, Uint8Array>): R2Bucket => ({
      get: async (key: string) => {
        const v = m.get(key);
        if (!v) return null;
        return { arrayBuffer: async () => { const ab = new ArrayBuffer(v.byteLength); new Uint8Array(ab).set(v); return ab; }, etag: `"${key.length}"` };
      },
      head: async (key: string) => (m.has(key) ? { etag: `"${key.length}"` } : null),
    } as unknown as R2Bucket);
    const envFor = (m: Map<string, Uint8Array>): Env => ({
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: r2For(m),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
      [`KV_${NS}`]: { put: async () => {}, get: async () => null } as unknown as KVNamespace,
    } as unknown as Env);

    // Truncated primary: runRestore (dry-run) classifies the completeness failure as the non-fallback
    // integrity reason, so withRunDestFallback would NOT fall through to a replica.
    const truncRes = (await runRestore(envFor(truncated), { runId: RUN_ID, confirm: false })) as RestorePlan;
    ok("runRestore on a truncated archive reports the non-fallback integrity reason", truncRes.ok === false && truncRes.reason === REASON_INTEGRITY);
    ok("that reason does NOT trigger replica fallback", isReplicaFallbackReason(truncRes.reason) === false);

    // Missing object: drop a shard so the reader throws the availability "is missing"; runRestore reports a
    // fallback-eligible reason (so the 3-2-1 chain WOULD try the next destination).
    const holed = new Map(objs);
    holed.delete(`run/${RUN_ID}/manifest/00000.dpe`);
    const missRes = (await runRestore(envFor(holed), { runId: RUN_ID, confirm: false })) as RestorePlan;
    ok("runRestore on a missing object reports a fallback-eligible availability reason", missRes.ok === false && isReplicaFallbackReason(missRes.reason) === true);

    // End to end: delete a `seg/` data object from an otherwise-intact, signed run. restoreRecord
    // reaches the missing segment, restore-open.ts types it as a completeness integrity failure, and
    // runRestore reports the NON-fallback integrity reason -- so withRunDestFallback would NEVER silently
    // mask the deleted segment by reading a 3-2-1 replica.
    const segHoled = new Map(objs);
    const segKey = [...segHoled.keys()].find((k) => k.startsWith("seg/"));
    ok("the sealed archive has at least one content-addressed segment object to delete", segKey !== undefined);
    if (segKey !== undefined) segHoled.delete(segKey);
    const segRes = (await runRestore(envFor(segHoled), { runId: RUN_ID, confirm: false })) as RestorePlan;
    ok("runRestore on a deleted segment reports the non-fallback integrity reason", segRes.ok === false && segRes.reason === REASON_INTEGRITY);
    ok("a deleted segment does NOT trigger replica fallback (integrity != availability)", isReplicaFallbackReason(segRes.reason) === false);
  }

  console.log("-- 6. a deleted SEGMENT is a completeness shortfall (integrity, non-fallback) --");
  {
    // 6a. The classifier: a missing `seg/` object currently classifies as REASON_INTEGRITY (non-fallback),
    // distinct from a missing run-tree object (root/shard) which stays a fallback-eligible availability
    // reason.
    //
    // THIS BLOCK PINS A KNOWN DIVERGENCE, NOT A DESIRED END STATE. The reader classifies a deleted segment
    // as ExitDangling rather than ExitIncomplete, because conflating an absent object with an altered one
    // points an operator away from the replica that would have restored them. See the long note at the
    // matching net in src/restore-reasons.ts for the evidence and for the structural reason the engine cannot
    // follow yet, which is that its restore walk aborts on the FIRST failing record and so cannot compute the
    // reader's dangling-only predicate.
    //
    // The assertions below therefore hold this behaviour STILL, on purpose. Do not relax them to make a
    // reclassification pass: the reclassification is unsafe until the walk aggregates per-record failures,
    // because a run with one absent segment and one altered record would fall back to a replica with the
    // alteration never looked at.
    const segMissingErr = new Error(`object seg/ab/abcdef0123456789.seg is missing`);
    ok("classifier: a missing SEGMENT classifies to REASON_INTEGRITY (completeness shortfall)", classifyRestoreFailure(segMissingErr) === REASON_INTEGRITY);
    ok("classifier: a missing SEGMENT is NOT replica-fallback-eligible (surfaces loud, never falls back)", isReplicaFallbackReason(classifyRestoreFailure(segMissingErr)) === false);
    // Contrast: a missing run-tree (root/shard) object remains the genuine availability / DR case.
    ok("classifier: a missing run-tree object still classifies to REASON_OBJECT_MISSING (fallback)", classifyRestoreFailure(new Error(`object run/${RUN_ID}/manifest/00000.dpe is missing`)) === REASON_OBJECT_MISSING);

    // 6b. The structured RunIntegrityError a deleted segment now raises is recognised as an integrity
    // failure (the type-driven path in restore-open.ts), so the classification is robust to the message.
    const typed = new RunIntegrityError(`object seg/ab/abcdef0123456789.seg is missing`, "integrity");
    ok("a typed segment-missing RunIntegrityError is recognised as a structured integrity failure", isIntegrityFailure(typed) === true);
    ok("the typed segment-missing failure classifies to REASON_INTEGRITY", classifyRestoreFailure(typed) === REASON_INTEGRITY);
    // (The end-to-end deleted-segment-through-runRestore proof lives in block 5, where the env factory is.)
  }

  console.log("-- 7. a PRESENT-but-corrupt SEGMENT is an INTEGRITY fault, distinct from a genuine fetch fault --");
  {
    // 7a. Byte-flip a REAL sealed segment object: it is PRESENT but its AES-256-GCM tag no longer
    // authenticates. openRun still SUCCEEDS (the signed root + shard manifests are intact; segments are verified
    // per-record on READ, not at open). restoreRecord then FETCHES the present segment and fails to decrypt it.
    // Because the bytes WERE fetched, the reader re-labels that decrypt/AEAD failure as a STRUCTURED
    // integrity failure, so classifyRestoreFailure returns the non-fallback REASON_INTEGRITY -- the SAME class
    // the offline Go restore reports for the identical damage, and the same class a MISSING segment already gets.
    // Without this classification, the raw AES-GCM OperationError is a plain Error matching no integrity
    // keyword, so classifyRestoreFailure would default it to the availability catch-all "recovery check failed" --
    // a present-but-corrupt backup wrongly read as availability (and replica-fallback-eligible).
    const corruptSeg = new Map(objs);
    const segKey = [...corruptSeg.keys()].find((k) => k.startsWith("seg/"));
    ok("the sealed archive has a content-addressed segment object to corrupt", segKey !== undefined);
    if (segKey !== undefined) {
      const seg = new Uint8Array(corruptSeg.get(segKey)!);
      // Flip a byte well inside the first ciphertext chunk: frame(5) + payload nonce(16) + into the ciphertext,
      // so the AEAD TAG fails on decrypt (a genuine corruption, not a framing/length error).
      const at = Math.min(seg.length - 1, 5 + 16 + 4);
      seg[at] = seg[at]! ^ 0xff;
      corruptSeg.set(segKey, seg);

      const run = await openRun(storeFor(corruptSeg), RUN_ID, opIdentity, verifier, { verifyFreshness: false, allowStale: true });
      ok("openRun SUCCEEDS over a corrupt SEGMENT (root + shard manifests intact, segments read per-record)", run.records.length === 3);

      let corruptErr: unknown;
      for (const rec of run.records) {
        try {
          await run.restoreRecord(rec);
        } catch (e) {
          corruptErr = e;
          break;
        }
      }
      ok("restoring a record whose PRESENT segment is corrupt THROWS", corruptErr !== undefined);
      ok("the decrypt failure of a PRESENT segment is a STRUCTURED integrity failure (not a plain Error)", isIntegrityFailure(corruptErr));
      ok("classifyRestoreFailure routes a present-but-corrupt segment to REASON_INTEGRITY", classifyRestoreFailure(corruptErr) === REASON_INTEGRITY);
      ok("a present-but-corrupt segment is NOT replica-fallback-eligible (surfaces loud, never falls back)", isReplicaFallbackReason(classifyRestoreFailure(corruptErr)) === false);
    }

    // 7b. CONTRAST: a GENUINE fetch fault on a segment (the read REACHED the destination and it faulted with an
    // HTTP status) is availability, and MUST stay availability -- the fix must NOT over-reach and turn a
    // network/status fault into integrity. store.get throws BEFORE any byte is decrypted, so the reader never
    // re-labels it; classifyRestoreFailure sees the "status" message and returns the fallback-eligible
    // REASON_DESTINATION_ACCESS. This is the boundary the fix preserves: fetched-then-undecryptable => integrity;
    // fetch itself faulted => availability.
    const faultStore: ObjectStore = {
      get: async (k: string) => {
        if (k.startsWith("seg/")) throw new Error(`GET ${k}: status 503`);
        const v = objs.get(k);
        if (!v) throw new Error(`object ${k} is missing`);
        return v;
      },
    };
    const run2 = await openRun(faultStore, RUN_ID, opIdentity, verifier, { verifyFreshness: false, allowStale: true });
    let fetchErr: unknown;
    for (const rec of run2.records) {
      try {
        await run2.restoreRecord(rec);
      } catch (e) {
        fetchErr = e;
        break;
      }
    }
    ok("a genuine segment FETCH fault (status 503) is NOT a structured integrity failure", isIntegrityFailure(fetchErr) === false);
    ok("classifyRestoreFailure keeps a segment fetch fault as REASON_DESTINATION_ACCESS (availability)", classifyRestoreFailure(fetchErr) === REASON_DESTINATION_ACCESS);
    ok("a segment fetch fault IS replica-fallback-eligible (a healthy replica could remedy it)", isReplicaFallbackReason(classifyRestoreFailure(fetchErr)) === true);
  }

  console.log("-- 6. OPAQUE-DEST-ERROR: a rejected destination WRITE surfaces the real S3 <Code>, still falls back --");
  {
    // s3WriteFailure (s3-worm.ts) builds "<verb> <key>: status NNN (<Code>[: hint])" on a rejected write.
    // The shared destRejectionDetail extractor pulls the parenthesised detail; a bare "status NNN" read
    // error (the get/list path) carries no parentheses and yields undefined.
    ok("destRejectionDetail extracts the parenthesised S3 code from a write-failure message", destRejectionDetail("PUT seg/0001: status 403 (AccessDenied)") === "AccessDenied");
    ok("destRejectionDetail extracts the object-lock checksum hint detail", destRejectionDetail("PUT seg/0001: status 400 (InvalidRequest: object lock write requires a checksum)") === "InvalidRequest: object lock write requires a checksum");
    ok("destRejectionDetail returns undefined for a bare 'status NNN' read error (no code)", destRejectionDetail("GET seg/0001: status 503") === undefined);

    // destAccessReason ENRICHES the availability reason with the real code instead of collapsing it to the
    // generic class — the actionable cause the operator was being denied.
    ok("destAccessReason surfaces the real code on a rejected write", destAccessReason("PUT seg/0001: status 403 (AccessDenied)") === `${REASON_DESTINATION_ACCESS} (AccessDenied)`);
    ok("destAccessReason falls back to the bare class when there is no code", destAccessReason("GET seg/0001: status 503") === REASON_DESTINATION_ACCESS);

    // CONTRACT-PRESERVING: the enriched reason is STILL an availability fault, so the 3-2-1 replica fallback
    // fires exactly as it did for the bare class. Surfacing the cause must never suppress fallback.
    ok("the enriched destination-access reason is STILL replica-fallback-eligible", isReplicaFallbackReason(destAccessReason("PUT seg/0001: status 403 (AccessDenied)")) === true);
    ok("the bare destination-access reason remains replica-fallback-eligible", isReplicaFallbackReason(REASON_DESTINATION_ACCESS) === true);
    // A non-availability integrity reason that happens to contain parentheses is NOT eligible (no accidental widening).
    ok("an integrity reason is NOT made fallback-eligible by the prefix change", isReplicaFallbackReason("integrity check failed (whatever)") === false);
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nRESTORE INTEGRITY-CLASS VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
