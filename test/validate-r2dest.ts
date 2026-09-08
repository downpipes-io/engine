// Prove the R2 destination satisfies the Destination contract over a native R2 binding,
// including the onlyIf-backed conditional put the single-writer RUNLOG relies on, and that
// a run sealed through it (buffered AND streamed records) reads back and restores. The R2
// binding is mocked in memory with faithful onlyIf precondition semantics so the If-Match /
// If-None-Match behaviour is actually exercised, not stubbed. Run:
//   node test/validate-r2dest.ts

import { R2Destination } from "../src/dest/r2.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { runBackup, type RunConfig, type RunClock } from "../src/seal/pipeline.ts";
import { coarseRunError } from "../src/seal/slice.ts";
import { loadSigner, loadRecipients, loadIdentity, verifierFrom } from "../src/keys-env.ts";
import type { SourceAdapter, SourceRecord, Selector } from "../src/sources/types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { x25519PublicFromScalar } from "../src/crypto/x25519.ts";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { eqBytes, fill, randomBytes, streamOf, toBytes } from "./testutil.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}


// deriveRecipient builds a matched recipient (public to wrap to, private to open with) from
// an x25519 scalar and an ML-KEM seed, in the engine's two env encodings: the public is
// x25519 public(32) || ML-KEM ek(1568); the private identity is the scalar(32) || seed(64).
function deriveRecipient(scalar: Uint8Array, seed: Uint8Array): { publicB64: string; privateB64: string } {
  const ek = mlkemKeygen(seed).encapKey;
  const xPub = x25519PublicFromScalar(scalar);
  return { publicB64: b64urlEncode(concat(xPub, ek)), privateB64: b64urlEncode(concat(scalar, seed)) };
}

// An in-memory R2 bucket mock implementing the subset of R2Bucket the destination calls,
// with the precondition semantics R2 documents: a conditional put that fails returns null;
// etagDoesNotMatch:"*" means "must not exist"; etagMatches:<etag> means "current etag must
// equal this". A fresh monotonic etag is minted on every successful write so a changed
// version is detectable (mirrors a real etag turning over on overwrite).
class MockR2Bucket {
  private store = new Map<string, { bytes: Uint8Array; etag: string }>();
  private seq = 0;

  private mintEtag(): string {
    this.seq += 1;
    return `etag-${this.seq}`;
  }

  private precondHolds(existing: { etag: string } | undefined, onlyIf?: R2Conditional): boolean {
    if (!onlyIf) return true;
    if (onlyIf.etagDoesNotMatch !== undefined) {
      // "*" => must not exist; a concrete etag => current must differ.
      if (onlyIf.etagDoesNotMatch === "*") {
        if (existing) return false;
      } else if (existing && existing.etag === onlyIf.etagDoesNotMatch) {
        return false;
      }
    }
    if (onlyIf.etagMatches !== undefined) {
      if (!existing || existing.etag !== onlyIf.etagMatches) return false;
    }
    return true;
  }

  async put(
    key: string,
    value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
    options?: { onlyIf?: R2Conditional },
  ): Promise<{ etag: string } | null> {
    const existing = this.store.get(key);
    if (options?.onlyIf && !this.precondHolds(existing, options.onlyIf)) return null;
    const bytes = await toBytes(value);
    const etag = this.mintEtag();
    this.store.set(key, { bytes, etag });
    return { etag };
  }

  async get(key: string): Promise<{ etag: string; arrayBuffer(): Promise<ArrayBuffer> } | null> {
    const rec = this.store.get(key);
    if (!rec) return null;
    const snapshot = rec.bytes; // copy out so a later overwrite cannot mutate the read
    return { etag: rec.etag, arrayBuffer: async () => snapshot.slice().buffer };
  }

  async head(key: string): Promise<{ etag: string } | null> {
    const rec = this.store.get(key);
    return rec ? { etag: rec.etag } : null;
  }

  // delete removes one object; absent keys are a no-op (R2's idempotent delete), which is what
  // the retention prune relies on so a re-run never fails on an already-gone object.
  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  // list returns the objects under a prefix with faithful cursor paging: the page size is small
  // (2) so the destination's continuation loop is actually exercised. The cursor is the index of
  // the next key in the prefix-filtered, key-sorted set; truncated narrows the return type to
  // carry the cursor exactly as the real R2Objects does.
  async list(options?: { prefix?: string; cursor?: string }): Promise<R2Objects> {
    const pageSize = 2;
    const prefix = options?.prefix ?? "";
    const all = [...this.store.keys()].filter((k) => k.startsWith(prefix)).sort();
    const start = options?.cursor !== undefined ? Number(options.cursor) : 0;
    const slice = all.slice(start, start + pageSize);
    const objects = slice.map((key) => ({ key }) as R2Object);
    const next = start + pageSize;
    if (next < all.length) {
      return { objects, truncated: true, cursor: String(next), delimitedPrefixes: [] } as unknown as R2Objects;
    }
    return { objects, truncated: false, delimitedPrefixes: [] } as unknown as R2Objects;
  }
}

// Part 1: the Destination contract directly against the mock binding.
async function contractTests(): Promise<void> {
  console.log("contract:");
  const bucket = new MockR2Bucket();
  const dest = new R2Destination(bucket as unknown as R2Bucket);

  // put + get round-trips bytes and exposes an etag.
  const body = utf8("hello downpipe");
  await dest.put("a/obj", body);
  const got = await dest.get("a/obj");
  ok("put then get returns the bytes", !!got && eqBytes(got.body, body));
  ok("get exposes a non-empty etag", !!got && got.etag.length > 0);
  ok("get of an absent key is null", (await dest.get("a/missing")) === null);

  // exists via head.
  ok("exists is true for a present object", await dest.exists("a/obj"));
  ok("exists is false for an absent object", !(await dest.exists("a/missing")));

  // putConditional If-None-Match:* creates only when absent (the RUNLOG create path).
  const create = await dest.putConditional("rl/log", utf8("v1"), { ifNoneMatch: "*" });
  ok("conditional create (ifNoneMatch:*) succeeds when absent", create.ok && !!create.etag);
  const recreate = await dest.putConditional("rl/log", utf8("v1-dup"), { ifNoneMatch: "*" });
  ok("conditional create (ifNoneMatch:*) fails when present", !recreate.ok);
  ok("a failed conditional create did not overwrite", eqBytes((await dest.get("rl/log"))!.body, utf8("v1")));

  // putConditional If-Match replaces only the exact version (the RUNLOG extend path).
  const cur = (await dest.get("rl/log"))!.etag;
  const replace = await dest.putConditional("rl/log", utf8("v2"), { ifMatch: cur });
  ok("conditional replace (ifMatch:current) succeeds", replace.ok && !!replace.etag);
  ok("conditional replace wrote the new body", eqBytes((await dest.get("rl/log"))!.body, utf8("v2")));
  const stale = await dest.putConditional("rl/log", utf8("v3"), { ifMatch: cur });
  ok("conditional replace (ifMatch:stale-etag) fails", !stale.ok);
  ok("a failed conditional replace did not overwrite", eqBytes((await dest.get("rl/log"))!.body, utf8("v2")));
  const wrong = await dest.putConditional("rl/absent", utf8("x"), { ifMatch: "etag-does-not-exist" });
  ok("conditional replace of an absent key fails", !wrong.ok);

  // putStream does a single streamed put that round-trips identically to a buffered put.
  const big = fill(200_000);
  await dest.putStream("seg/streamed", streamOf(big));
  const back = await dest.get("seg/streamed");
  ok("putStream then get returns the streamed bytes", !!back && eqBytes(back.body, big));

  // delete removes an object; deleting an absent key is an idempotent no-op (the retention
  // prune relies on this so a re-run never fails on an already-gone object).
  await dest.put("del/obj", utf8("to delete"));
  ok("object present before delete", await dest.exists("del/obj"));
  await dest.delete("del/obj");
  ok("object absent after delete", !(await dest.exists("del/obj")));
  let deleteThrew = false;
  try {
    await dest.delete("del/already-gone");
  } catch {
    deleteThrew = true;
  }
  ok("delete of an absent key is a no-op (idempotent)", !deleteThrew);

  // list enumerates the keys under a prefix, following the cursor across pages (the mock pages
  // at 2 keys, so 5 objects exercises three pages). The result is the complete prefix set.
  for (let i = 0; i < 5; i++) await dest.put(`run/RUN9/part${i}`, utf8(String(i)));
  await dest.put("run/OTHER/x", utf8("other")); // a different prefix, must NOT appear
  const listed = await dest.list("run/RUN9/");
  ok("list returns every key under the prefix across pages", listed.length === 5);
  ok("list scopes to the prefix (excludes other prefixes)", listed.every((k) => k.startsWith("run/RUN9/")));
}

// A minimal source that yields a buffered KV record and a streamed R2 record, so the seal
// drives BOTH dest.put and dest.putStream on the way to the bucket. The streamed value's
// size pushes it onto the streaming path in buildArchive (well above the 64 KiB chunk).
//
// The adapter's top-level sourceType ("kv") is a label only; the seal processes whatever
// per-record sourceType each yielded record declares, so a real adapter is homogeneous but
// this fixture deliberately mixes "kv" and "r2" records to exercise both seal paths from one
// crawl. The per-record sourceType, not the adapter label, is authoritative downstream.
function fixtureSource(buffered: Uint8Array, streamed: Uint8Array): SourceAdapter {
  return {
    sourceType: "kv",
    async *crawl(_selector: Selector): AsyncIterable<SourceRecord> {
      yield { sourceType: "kv", name: "config:site", value: buffered, namespace: "settings" };
      yield {
        sourceType: "r2",
        name: "media/blob.bin",
        bucket: "assets",
        stream: { size: streamed.length, open: () => ({ async *chunks() { yield streamed; } }) },
      };
    },
    async estimate(_selector: Selector) {
      return { records: 2, bytes: buffered.length + streamed.length };
    },
  };
}

// Part 2: a full seal -> read-back -> restore round-trip through the R2 destination.
async function roundTrip(): Promise<void> {
  console.log("seal -> restore round-trip:");
  const bucket = new MockR2Bucket();
  const dest = new R2Destination(bucket as unknown as R2Bucket);

  // Build the env-encoded keys the engine would load, exactly as keys-env expects them.
  const edSeed = randomBytes(32);
  const mldsaSeed = randomBytes(32);
  const mldsa = ml_dsa87.keygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));

  // The operational recipient identity is x25519 scalar(32) || ML-KEM seed(64) = 96 bytes
  // (parseIdentity's layout). The matching public, x25519 public(32) || ML-KEM ek(1568) =
  // 1600 bytes (loadRecipientPublic's layout), MUST be derived from those same secrets, so
  // deriveRecipient pairs them. The public is wrapped to in the run; the private opens it
  // for read-back, exactly as the drill uses OPERATIONAL_PRIVATE.
  const op = deriveRecipient(randomBytes(32), randomBytes(64));
  const operationalPublicB64 = op.publicB64;
  const operationalPrivateB64 = op.privateB64;
  // A break-glass recipient is mandatory; its public is wrapped to but never opened here.
  const breakGlassPublicB64 = deriveRecipient(randomBytes(32), randomBytes(64)).publicB64;

  const signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const recipients = loadRecipients(breakGlassPublicB64, operationalPublicB64);
  const identity = loadIdentity(operationalPrivateB64);

  const buffered = utf8(JSON.stringify({ theme: "dark", region: "au" }));
  const streamed = fill(150_000);

  const runId = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
  const cfg: RunConfig = {
    downpipeId: "dp_test",
    downpipeName: "r2 round-trip",
    cadence: "3600s",
    selector: { include: [], exclude: [] },
    recipients,
  };
  const clock: RunClock = {
    runId,
    runlogIndex: 1,
    prevRunId: null,
    now: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
    randomNonce: () => randomBytes(16),
    randomSalt: () => randomBytes(16),
    master: randomBytes(32),
  };

  const summary = await runBackup([fixtureSource(buffered, streamed)], cfg, signer, dest, clock);
  ok("runBackup sealed both records", summary.records === 2);
  ok("runBackup wrote objects through the R2 dest", summary.objectsWritten > 0);

  // The RUNLOG was written through the conditional create path of the R2 dest.
  ok("RUNLOG present after the run", await dest.exists("_RECOVERY/RUNLOG"));
  ok("RUNLOG sig present after the run", await dest.exists("_RECOVERY/RUNLOG.sig"));

  // Read back through the SAME R2 dest as the reader's ObjectStore, pinned to the operator
  // signer (never a key from the run), exactly the drill's posture.
  const store: ObjectStore = {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`object ${k} is missing`);
      return r.body;
    },
  };
  const run = await openRun(store, runId, identity, verifier);
  ok("run opens and verifies from the R2 dest", run.records.length === 2);

  const recBuffered = run.records.find((r) => r.name === "config:site");
  ok("buffered record present", !!recBuffered);
  if (recBuffered) ok("buffered record restores to its plaintext", eqBytes(await run.restoreRecord(recBuffered), buffered));

  const recStreamed = run.records.find((r) => r.name === "media/blob.bin");
  ok("streamed record present", !!recStreamed);
  if (recStreamed) ok("streamed record restores to its plaintext", eqBytes(await run.restoreRecord(recStreamed), streamed));
}

// A native R2Bucket binding fault carries no HTTP status and no S3 <Code> element (it is an in-process
// call, not a request over a wire), so coarseRunError -- which classifies a run failure by status/code/
// keyword found in the raw message -- must not lose the fact that a DESTINATION write failed at all. This
// drives the REAL code path: R2Destination.put against a binding double that throws a bare, unattributed
// error shape, then feeds the exact message that reaches the seal pipeline into coarseRunError, exactly
// as seal/slice.ts does on a failed run.
async function nativeFaultAttribution(): Promise<void> {
  console.log("native R2 binding write fault keeps its destination attribution:");
  // A binding double whose put() throws the way a live R2 binding does on an unrecoverable native fault: a
  // bare runtime Error with none of "status", "fetch", "network", "RUNLOG" or any S3 <Code> parenthetical --
  // the exact vocabulary gap the register cites.
  const faultingBucket = {
    put: async (): Promise<never> => {
      throw new Error("the R2 bucket does not exist");
    },
  };
  const dest = new R2Destination(faultingBucket as unknown as R2Bucket);
  let threw: Error | null = null;
  try {
    await dest.put("seg/aa/deadbeef.seg", utf8("segment bytes"));
  } catch (e) {
    threw = e as Error;
  }
  ok("R2Destination.put propagates the native binding fault", threw !== null);
  if (threw === null) return;
  ok("the propagated message still carries the native runtime's own text (nothing swallowed)", threw.message.includes("the R2 bucket does not exist"));
  const cls = coarseRunError(threw.message);
  ok("the run row does NOT collapse to the generic 'run failed' (the attribution the bug loses)", cls !== "run failed");
  ok("the class names it as a destination fault", cls.includes("destination"));

  // The same fault on the RUNLOG object must not be mis-swallowed by the RUNLOG-specific contention branches:
  // a native-binding fault writing the RUNLOG is a destination fault, not CAS contention,
  // and an operator who retries a contention message expecting it to clear will retry forever on a fault that
  // never will.
  const dest2 = new R2Destination(faultingBucket as unknown as R2Bucket);
  let threw2: Error | null = null;
  try {
    await dest2.put("_RECOVERY/RUNLOG", utf8("runlog bytes"));
  } catch (e) {
    threw2 = e as Error;
  }
  ok("the RUNLOG-object case also throws", threw2 !== null);
  if (threw2 === null) return;
  const cls2 = coarseRunError(threw2.message);
  ok("a native-binding fault on the RUNLOG object is NOT mislabelled as CAS contention", cls2 !== "runlog write contended");
  ok("it still names a destination fault", cls2.includes("destination"));
}

async function main(): Promise<void> {
  await contractTests();
  await roundTrip();
  await nativeFaultAttribution();
  console.log(failures === 0 ? "\nR2 DESTINATION CONTRACT + ROUND-TRIP PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
