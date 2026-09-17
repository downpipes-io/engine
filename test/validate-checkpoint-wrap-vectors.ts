// FROZEN REGRESSION VECTORS for the checkpoint wrap key: the engine-internal HKDF label
// INFO_CHECKPOINT_WRAP (src/seal/checkpoint.ts) and the four AAD domains derived under it.
//
// WHY THESE EXIST, AND WHY THEY ARE NOT CROSS-IMPLEMENTATION VECTORS. Every known-answer vector in
// test/vectors/ pins a downpipe/0.1.0 WIRE constant against the Go reference. The checkpoint wrap is not
// on the wire and has no second implementation: it is a Worker-only key that seals a sliced run's own
// resume state into Durable Object storage. So there is nothing to lock to, and the engine's own
// cryptographic bill of materials records the label as sitting outside the vector corpus.
//
// That leaves a real gap, which these vectors close. The label is ONE string consumed by wrapKey, and
// wrapKey has six call sites in checkpoint.ts: every checkpoint wrap and unwrap in the product derives
// from it. An accidental edit to it -- a rename, a version bump made for tidiness, a merge -- is not
// caught by any round-trip test, because a round trip wraps and unwraps under the SAME changed label and
// passes. What it does instead is strand every in-flight sliced run: unwrapMaster then throws
// CheckpointUnwrapError("master-unwrap"), which checkpoint.ts's own comment on that error explains is
// indistinguishable at the record level from a SIGNER_PRIVATE rotation. The operator is then debugging a
// key rotation that never happened.
//
// So these are FROZEN CIPHERTEXTS, produced by the current label and pasted here, never regenerated at
// run time. A round trip would be self-fulfilling; opening bytes frozen under the label is not. A changed
// label turns them red at build time rather than at resume time.
//
// The negative controls matter as much as the positive ones. A vector that only proves "these bytes open"
// would still pass if the AAD binding were dropped, so each frozen envelope is also presented under the
// WRONG runId, the WRONG field domain and the WRONG sequence, and must fail.
//
// The fixture holds no real key material: the signer seed is bytes 0..63 and the run master is 0x40..0x5f,
// both constructed, and the run id is a literal. Nothing here is a secret and nothing here is a customer
// value.
//
// Run: node test/validate-checkpoint-wrap-vectors.ts

import { b64urlEncode, hexEncode } from "../src/crypto/bytes.ts";
import { checkpointUnwrapOf } from "../src/seal/checkpoint-fault.ts";
import { openOpenShardBatch, openStoredCheckpoint, unwrapMaster } from "../src/seal/checkpoint.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// The frozen fixture. SEED_B64 is base64url of the 64 bytes 0x00..0x3f (wrapKey refuses any other
// length); MASTER_HEX is the 32-byte run master 0x40..0x5f the wrapped envelope must open to.
const SEED_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw";
const RUN_ID = "01JCHECKPOINTWRAPVECTOR01";
const MASTER_HEX = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

// A one-byte-different seed. Present so the vectors are proven KEY-BOUND: if they opened under this too,
// they would be pinning nothing about the derivation at all.
const OTHER_SEED_B64 = "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw";

// wrapMaster's envelope, AAD = the bare runId.
const FROZEN_MASTER = { iv: "94efGaNESx9qG8Ag", ct: "nsqCXgUy3vrISAJP80k1y99XEyobVCgHjlvjZvJvSg3gpf--bzj48n8ZJ_86TCA-" };
// sealOpenShardBatch's envelope for seq 3, AAD = "open|<runId>|3".
const FROZEN_BATCH_SEQ = 3;
const FROZEN_BATCH = { iv: "4bRxiVOjM6A8VngM", ct: "XIslzprGdftQSL_RV79JQIhMn8zcIHJRNkmXXoqKITtWmgcWMQ1eU2BTK3p51E4OF1ZDisxhpvVEwAtfcHhfphATww" };
// sealCheckpointForStorage's two field envelopes, AAD = "cursor|<runId>" and "partial|<runId>".
const FROZEN_CURSOR = { iv: "Mip6Vp7s_3_wQTBo", ct: "RAbHvqOk-42MM1E7rxnwYuoFOqmnIMF4vDeujy6JCfM5jQ" };
const FROZEN_PARTIAL = {
  iv: "Sdci12ErSJyYBvnq",
  ct: "WdEn4B9AgVZgS0Kv0JK3Q8c2tzUF-tIMZvMTIKIYgmCbgn7TrEb_ZGZrf7vFf0rxsCQz6gcxTcgqo7skaY9flNzPVWzHsYNtPMAi4UGb7BrasHp5HLlC4fFLTf92TGnntWNIxqgSdm-aa2hbWHyXO6Q6xqiveE6O1Hp4T1K9ktAVi9e8MHd6My1FIhq-Yl1n5HQYXEMUMaFuiR4maM_oTfxw",
};

// The plaintext halves the frozen envelopes must open to.
const EXPECTED_CURSOR = "kv/alpha|after=zzz";
const EXPECTED_BATCH_LINES = [{ name: "kv/alpha", recordId: "r000000000000001" }];
const EXPECTED_PARTIAL_NAME = "r2/big-object.bin";

// storedDoc rebuilds the at-rest StoredRunCheckpoint the frozen envelopes came from. Only the two
// envelopes are frozen; every other field is plain, non-secret resume state written out here so a reader
// can see the whole document the open path validates.
function storedDoc(overrides: Record<string, unknown> = {}): unknown {
  return {
    v: 1,
    runId: RUN_ID,
    runlogIndex: 7,
    downpipeId: "dp-vectors",
    wrappedMaster: FROZEN_MASTER,
    nextRecordIndex: 2,
    nextShardIndex: 0,
    sliceCount: 1,
    sourceDone: false,
    frontier: { count: 2, nodes: [{ sizeLog: 1, hash: "AAAA" }] },
    counts: {
      records: 2, bytes: 10, objectsWritten: 2, objectsSkipped: 0, archiveBytesWritten: 40,
      recordsSkippedChanged: 0, recordsVanished: 0, recordsIncomplete: 0, incompleteByMarker: {}, incompleteIds: {},
      durationMs: 5, ops: {},
    },
    openShard: { count: 1 },
    wrappedCursor: FROZEN_CURSOR,
    wrappedPartial: FROZEN_PARTIAL,
    ...overrides,
  };
}

// threw runs fn and reports whether it failed, and (when asked) whether it failed with the exact closed
// unwrap code the resume path relies on (checkpointUnwrapOf, the type-based reader, never a message match).
// A negative control that passes for the wrong reason is not a control.
async function threw(fn: () => Promise<unknown>, code?: string): Promise<boolean> {
  try {
    await fn();
    return false;
  } catch (e) {
    if (code === undefined) return true;
    return checkpointUnwrapOf(e) === code;
  }
}

async function main(): Promise<void> {
  console.log("-- the frozen envelopes open under the shipped checkpoint-wrap label --");
  {
    // Each positive vector is run through okOpening rather than awaited bare. A changed label makes these
    // THROW, and an uncaught throw would end the run at the first one with a stack trace: the maintainer
    // would learn that something in checkpoint.ts failed, not that the wrap label no longer matches the
    // one every stored checkpoint in the field was sealed under. The catch turns it into that sentence.
    const okOpening = async (label: string, fn: () => Promise<boolean>): Promise<void> => {
      try {
        ok(label, await fn());
      } catch (e) {
        ok(`${label} [THREW: ${(e as Error).message}]`, false);
      }
    };
    await okOpening("wrapMaster: the frozen envelope opens to the known 32-byte run master", async () => hexEncode(await unwrapMaster(SEED_B64, RUN_ID, FROZEN_MASTER)) === MASTER_HEX);
    await okOpening("sealOpenShardBatch: the frozen batch opens to the known manifest line", async () => JSON.stringify(await openOpenShardBatch(SEED_B64, RUN_ID, FROZEN_BATCH_SEQ, FROZEN_BATCH)) === JSON.stringify(EXPECTED_BATCH_LINES));
    await okOpening("sealCheckpointForStorage: the frozen cursor envelope opens to the known resume token", async () => (await openStoredCheckpoint(SEED_B64, storedDoc())).cursor === EXPECTED_CURSOR);
    await okOpening("sealCheckpointForStorage: the frozen partialRecord envelope opens to the known record name", async () => (await openStoredCheckpoint(SEED_B64, storedDoc())).partialRecord?.meta.name === EXPECTED_PARTIAL_NAME);
    await okOpening("...and its sealed prefix offset survives the round trip", async () => (await openStoredCheckpoint(SEED_B64, storedDoc())).partialRecord?.offsetSealed === 65536);
    if (failures > 0) {
      console.error("\n  READ THIS BEFORE CHANGING ANYTHING. These are FROZEN ciphertexts sealed under the shipped");
      console.error("  INFO_CHECKPOINT_WRAP label (src/seal/checkpoint.ts). If they stopped opening, the wrap key");
      console.error("  derivation changed, and every in-flight sliced run in the field is now unresumable: its");
      console.error("  unwrap fails as CheckpointUnwrapError(\"master-unwrap\"), which reads exactly like a");
      console.error("  SIGNER_PRIVATE rotation. Restore the label. Do NOT regenerate this fixture to make it pass.");
    }
  }

  console.log("\n-- the vectors are KEY-bound (a different signer seed opens none of them) --");
  {
    ok("wrapMaster: a one-byte-different seed fails the AEAD", await threw(() => unwrapMaster(OTHER_SEED_B64, RUN_ID, FROZEN_MASTER), "master-unwrap"));
    ok("open-shard batch: a one-byte-different seed fails the AEAD", await threw(() => openOpenShardBatch(OTHER_SEED_B64, RUN_ID, FROZEN_BATCH_SEQ, FROZEN_BATCH), "batch-unwrap"));
    ok("stored checkpoint: a one-byte-different seed fails the AEAD", await threw(() => openStoredCheckpoint(OTHER_SEED_B64, storedDoc())));
  }

  console.log("\n-- the AAD domains still bind (run, field and sequence) --");
  {
    ok("wrapMaster: the SAME envelope under another runId is refused (no cross-run replay)", await threw(() => unwrapMaster(SEED_B64, "01JOTHERRUNIDVECTOR00000", FROZEN_MASTER), "master-unwrap"));
    ok("open-shard batch: the same envelope under another SEQUENCE is refused", await threw(() => openOpenShardBatch(SEED_B64, RUN_ID, FROZEN_BATCH_SEQ + 1, FROZEN_BATCH), "batch-unwrap"));
    ok("open-shard batch: the same envelope under another runId is refused", await threw(() => openOpenShardBatch(SEED_B64, "01JOTHERRUNIDVECTOR00000", FROZEN_BATCH_SEQ, FROZEN_BATCH)));
    ok(
      "stored checkpoint: the CURSOR envelope presented in the partialRecord slot is refused (the two domains are distinct)",
      await threw(() => openStoredCheckpoint(SEED_B64, storedDoc({ wrappedPartial: FROZEN_CURSOR }))),
    );
    ok(
      "stored checkpoint: the PARTIAL envelope presented in the cursor slot is refused",
      await threw(() => openStoredCheckpoint(SEED_B64, storedDoc({ wrappedCursor: FROZEN_PARTIAL }))),
    );
    ok(
      "stored checkpoint: the envelopes under another runId are refused",
      await threw(() => openStoredCheckpoint(SEED_B64, storedDoc({ runId: "01JOTHERRUNIDVECTOR00000" }))),
    );
  }

  console.log("\n-- the fixture itself is well formed --");
  {
    // A seed of the wrong length is a CONFIG fault, not an AEAD failure, and it must stay that way: the
    // pack names the variable rather than reporting a stranded run.
    const shortSeed = b64urlEncode(new Uint8Array(32));
    ok("a 32-byte SIGNER_PRIVATE is refused as malformed before any AEAD work", await threw(() => unwrapMaster(shortSeed, RUN_ID, FROZEN_MASTER)));
  }

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nCHECKPOINT-WRAP VECTORS PASS");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
