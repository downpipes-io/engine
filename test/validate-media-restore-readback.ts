// VERIFY-ON-READBACK + SIGNED RECEIPT for the media re-upload path (images / stream), end to end
// through runRestore, in-memory only (no network). Before this change a media restore re-uploaded the
// captured bytes but never read the uploaded object back to prove it, and the media records were excluded
// from the signed restore receipt, so a media restore had weaker assurance than KV/R2/D1/secrets. This
// proves, within the platform's reality:
//   - an IMAGE keeps its ORIGINAL id, so the re-upload is proven by a DIRECT byte readback: the engine reads
//     the live /blob back, hashes it, and asserts it equals the archived bytes' SHA-384. A readback that
//     MISMATCHES is a FAILURE (the apply is not ok, the record is in failures, the receipt entry is
//     verified:false), never a silent success.
//   - a VIDEO is transcoded by Stream and gets a NEW uid (an id-map), so a byte-for-byte readback is
//     impossible; instead the engine verifies WHAT IS VERIFIABLE: the new uid RESOLVES (the live object is
//     queryable). The receipt records verifiedSha384:null (no byte proof on a transcoded asset) with
//     verified:true ONLY when the uid resolves; a uid that does not resolve is a FAILURE.
//   - every media record actually uploaded appears in the SIGNED restore receipt with the other source
//     types (so allVerified and the audit anchor cover media too).
//
// Run: node test/validate-media-restore-readback.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { b64urlEncode, concat, hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { runRestore } from "../src/admin/restore.ts";
import type { MediaUploader, MediaUploadResult } from "../src/admin/media-restore.ts";
import type { Env } from "../src/env.d.ts";
import type { RestoreResult } from "../src/admin/restore-types.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVS0";
const DP_ID = "dp_media_readback";
const ACCT = "acct-media";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
const enc = (s: string) => new TextEncoder().encode(s);

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

// MockR2Archive serves the sealed archive objects to the reader (the READ side the restore opens).
class MockR2Archive {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` };
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
}

// Build an archive holding one IMAGE blob ("<id>/blob") and one STREAM video ("<uid>/video.mp4").
async function buildMediaArchive(imageBytes: Uint8Array, videoBytes: Uint8Array): Promise<{ archiveR2: MockR2Archive; opB64: string; signerB64: string }> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  // account = ACCT stamps the SIGNED origin the cross-account guard cross-checks; it matches the mediaRestore
  // accountId every apply below uses (ACCT), so these are same-account restores that need no cross confirmation.
  const records: WriteRecord[] = [
    { sourceType: "images", name: "img-orig-id/blob", value: imageBytes, account: ACCT },
    { sourceType: "stream", name: "vid-old-uid/video.mp4", value: videoBytes, account: ACCT },
  ];
  const archive = await buildArchive({
    downpipeId: DP_ID,
    downpipeName: "media",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records,
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const archiveR2 = new MockR2Archive();
  for (const [k, b] of archive) archiveR2.store.set(k, b);
  return { archiveR2, opB64: b64urlEncode(op.identity), signerB64 };
}

function envFor(archiveR2: MockR2Archive, opB64: string, signerB64: string): Env {
  return {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: archiveR2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerB64,
    OPERATIONAL_PRIVATE: opB64,
  } as unknown as Env;
}

// A stub uploader whose readback is controllable: it remembers what it was asked to upload, returns the
// archived hash on a faithful image readback (or a corrupted one), and reports the stream uid as resolving
// (or not). This is the SAME seam production uses (mediaUploaderFactory); the real fetch-backed uploader
// performs the same readback against the Cloudflare API.
function stubUploader(opts: { imageReadbackBytes: Uint8Array | null; streamResolves: boolean }): MediaUploader {
  return {
    uploadImage: async (_acct, id, bytes): Promise<MediaUploadResult> => {
      // The re-upload kept the original id; PROVE it by a direct byte readback (the live /blob), then hash.
      const back = opts.imageReadbackBytes ?? bytes;
      const verifiedSha384 = hexEncode(await sha384(back));
      const expected = hexEncode(await sha384(bytes));
      // readbackReadable mirrors the real uploader's rule (verifiedSha384 !== null): this stub always READS the
      // live /blob, whether it holds the faithful bytes or different ones, so a mismatch here is the durable
      // "read it and the bytes are wrong" case, never the transient "could not read it at all" one.
      return { restoredId: id, remapped: false, verifiedSha384, verified: verifiedSha384 === expected, via: "media-image-readback", readbackReadable: true };
    },
    uploadStreamVideo: async (_acct, originalUid): Promise<MediaUploadResult> => {
      const newUid = "new-" + originalUid;
      // A transcoded video cannot be byte-verified; verify the new uid RESOLVES (queryable). No byte hash.
      // readbackReadable is always true on the stream path, as it is in the real uploader: there is no byte
      // proof to be unreadable, the proof IS the uid resolution that `verified` carries.
      return { restoredId: newUid, remapped: true, verifiedSha384: null, verified: opts.streamResolves, via: "media-stream-exists", readbackReadable: true };
    },
  };
}

// Section A: a faithful media restore proves both records and they appear in the SIGNED receipt.
async function sectionHappy(): Promise<void> {
  console.log("media restore: image byte-readback + stream existence proof, both in the signed receipt:");
  const imageBytes = enc("PNG-IMAGE-BYTES-eeee");
  const videoBytes = enc("MP4-VIDEO-BYTES-ffff");
  const { archiveR2, opB64, signerB64 } = await buildMediaArchive(imageBytes, videoBytes);
  const env = envFor(archiveR2, opB64, signerB64);
  const res = (await runRestore(env, { runId: RUN_ID, confirm: true, mediaRestore: { token: "edit-tok", accountId: ACCT } }, undefined, {
    mediaUploaderFactory: () => stubUploader({ imageReadbackBytes: null, streamResolves: true }),
  })) as RestoreResult;

  ok("the media apply is ok", res.ok === true);
  ok("both media files were re-uploaded", (res.mediaRestored ?? []).length === 2);
  const receipt = res.receipt;
  ok("the applied result carries a signed receipt", receipt !== undefined);
  const imgEntry = (receipt?.records ?? []).find((r) => r.name === "img-orig-id/blob");
  const vidEntry = (receipt?.records ?? []).find((r) => r.name === "vid-old-uid/video.mp4");
  ok("the IMAGE record is in the receipt (previously excluded)", imgEntry !== undefined);
  ok("the IMAGE entry is proven by a byte readback (via:media-image-readback, verified)", imgEntry?.via === "media-image-readback" && imgEntry.verified === true);
  ok("the IMAGE entry's verifiedSha384 equals the archived image's SHA-384", imgEntry?.verifiedSha384 === hexEncode(await sha384(imageBytes)));
  ok("the STREAM record is in the receipt (previously excluded)", vidEntry !== undefined);
  ok("the STREAM entry verifies existence (via:media-stream-exists, verified, no byte hash)", vidEntry?.via === "media-stream-exists" && vidEntry.verified === true && vidEntry.verifiedSha384 === null);
  ok("the receipt summary.allVerified is true and counts the media records", receipt?.summary.allVerified === true && receipt.summary.recordsRestored === 2);
  ok("the receipt is key-signed (a signer was reachable)", typeof receipt?.signature === "string" && (receipt?.signature ?? "").length > 0);
}

// Section B: an image readback MISMATCH (the live blob does not hash to the archived bytes) is a FAILURE,
// never a silent success. The OLD code did no readback, so it would have reported success.
async function sectionImageMismatch(): Promise<void> {
  console.log("\nmedia restore: an image readback MISMATCH fails the restore (not a silent success):");
  const imageBytes = enc("PNG-IMAGE-BYTES-eeee");
  const videoBytes = enc("MP4-VIDEO-BYTES-ffff");
  const { archiveR2, opB64, signerB64 } = await buildMediaArchive(imageBytes, videoBytes);
  const env = envFor(archiveR2, opB64, signerB64);
  // The live /blob holds DIFFERENT bytes than the archived image: the readback hash will not match.
  const res = (await runRestore(env, { runId: RUN_ID, confirm: true, mediaRestore: { token: "edit-tok", accountId: ACCT } }, undefined, {
    mediaUploaderFactory: () => stubUploader({ imageReadbackBytes: enc("A-DIFFERENT-IMAGE-LANDED"), streamResolves: true }),
  })) as RestoreResult;

  ok("a media image readback mismatch makes the apply NOT ok", res.ok === false);
  ok("the image record is in failures with a readback reason", res.failures.some((f) => f.name === "img-orig-id/blob" && /readback|verif/i.test(f.reason)));
  const imgEntry = (res.receipt?.records ?? []).find((r) => r.name === "img-orig-id/blob");
  ok("the receipt entry for the image is verified:false (proof the landed bytes are wrong)", imgEntry !== undefined && imgEntry.verified === false);
  ok("the receipt summary.allVerified is FALSE on a media readback mismatch", res.receipt?.summary.allVerified === false);
}

// Section C: a video whose new uid does NOT resolve after upload is a FAILURE (the existence proof failed).
async function sectionStreamUnresolved(): Promise<void> {
  console.log("\nmedia restore: a video whose new uid does not resolve fails the restore:");
  const imageBytes = enc("PNG-IMAGE-BYTES-eeee");
  const videoBytes = enc("MP4-VIDEO-BYTES-ffff");
  const { archiveR2, opB64, signerB64 } = await buildMediaArchive(imageBytes, videoBytes);
  const env = envFor(archiveR2, opB64, signerB64);
  const res = (await runRestore(env, { runId: RUN_ID, confirm: true, mediaRestore: { token: "edit-tok", accountId: ACCT } }, undefined, {
    mediaUploaderFactory: () => stubUploader({ imageReadbackBytes: null, streamResolves: false }),
  })) as RestoreResult;

  ok("a stream existence-proof failure makes the apply NOT ok", res.ok === false);
  ok("the video record is in failures with an existence/verify reason", res.failures.some((f) => f.name === "vid-old-uid/video.mp4" && /readback|verif|resolve|exist/i.test(f.reason)));
  const vidEntry = (res.receipt?.records ?? []).find((r) => r.name === "vid-old-uid/video.mp4");
  ok("the receipt entry for the video is verified:false", vidEntry !== undefined && vidEntry.verified === false);
}

async function main(): Promise<void> {
  await sectionHappy();
  await sectionImageMismatch();
  await sectionStreamUnresolved();
  console.log(failures === 0 ? "\nMEDIA RESTORE READBACK + RECEIPT PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
