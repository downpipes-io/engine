// ASVS V5.2.2: the media re-upload path (src/admin/media-restore.ts, called from restore-apply.ts) sent
// decrypted bytes straight to Cloudflare Images/Stream with NO type check at all, and never passed a
// content type either (the uploadImage/uploadStreamVideo calls in restore-apply.ts carried the bytes only).
// The record's "images" vs "stream" TYPE comes from its capture-side record NAME ("<id>/blob" vs
// "<uid>/video.mp4"), never from the bytes, so a record whose name says "images" but whose decrypted bytes
// are actually a video container (or the reverse) would be forwarded to the wrong Cloudflare endpoint
// unexamined.
//
// validateMediaBytesType (src/admin/media-restore.ts) closes this: it sniffs the record's OWN leading bytes
// against a small closed allow-list of image/video container signatures and refuses a genuine CROSS-TYPE
// mismatch (bytes that are recognisably the OTHER media kind) before any network call. Bytes that match
// NEITHER known signature (an exotic format the allow-list does not enumerate, or -- in the rest of this
// test suite -- a short synthetic placeholder) are left alone: the customer's own backed-up content is not
// bounced on an incomplete signature list, only a provable mismatch is. This is deliberately the SAME
// leniency the pre-existing test fixtures across the suite already rely on ("PNG-BYTES", "MP4-BYTES" and
// similar placeholders are neither a real PNG nor a real MP4, and must keep restoring exactly as before).
//
// Run: node test/validate-media-restore-type-check.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { runRestore } from "../src/admin/restore.ts";
import { mediaFaultOf, validateMediaBytesType, type MediaUploader, type MediaUploadResult } from "../src/admin/media-restore.ts";
import type { Env } from "../src/env.d.ts";
import type { RestoreResult } from "../src/admin/restore-types.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVT1";
const DP_ID = "dp_media_typecheck";
const ACCT = "acct-media-tc";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

// Real container signatures, padded with distinct filler so each fixture also hashes distinctly.
const REAL_PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8]);
const REAL_JPEG = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 9, 8, 7, 6, 5, 4]);
const REAL_GIF = new Uint8Array([0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 1, 1, 0, 0]);
// ISO base media container (MP4): [size:4][ftyp][major brand][...]
const REAL_MP4 = new Uint8Array([0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d, 0, 0, 2, 0, 0x69, 0x73, 0x6f, 0x6d, 1, 2, 3, 4]);
// WEBM/MKV: EBML header.
const REAL_WEBM = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3, 0x01, 0x02, 0x03, 0x04, 5, 6]);

console.log("-- validateMediaBytesType: unit-level sniff + gate (no network) --");
{
  ok("a real PNG passes the images gate and reports image/png", validateMediaBytesType("images", REAL_PNG) === "image/png");
  ok("a real JPEG passes the images gate and reports image/jpeg", validateMediaBytesType("images", REAL_JPEG) === "image/jpeg");
  ok("a real GIF passes the images gate and reports image/gif", validateMediaBytesType("images", REAL_GIF) === "image/gif");
  ok("a real MP4 passes the stream gate and reports video/mp4", validateMediaBytesType("stream", REAL_MP4) === "video/mp4");
  ok("a real WEBM passes the stream gate and reports video/webm", validateMediaBytesType("stream", REAL_WEBM) === "video/webm");

  // Unrecognised bytes (the rest of the suite's short text placeholders) are NOT bounced: the customer's own
  // backed-up content must not be rejected on an incomplete signature list.
  const placeholder = new TextEncoder().encode("PNG-BYTES-not-actually-a-png");
  let placeholderThrew = false;
  let placeholderContentType: string | undefined;
  try {
    placeholderContentType = validateMediaBytesType("images", placeholder);
  } catch {
    placeholderThrew = true;
  }
  ok("unrecognised bytes are NOT refused (no signature list is exhaustive)", !placeholderThrew);
  ok("unrecognised bytes report no inferred content type", placeholderContentType === undefined);
}

console.log("\n-- validateMediaBytesType: a genuine CROSS-TYPE mismatch is refused (RED before this fix existed) --");
{
  let threw = false;
  let cls: string | undefined;
  try {
    validateMediaBytesType("images", REAL_MP4); // a record whose NAME says "images" but whose bytes are a video
  } catch (e) {
    threw = true;
    cls = mediaFaultOf(e)?.cls;
  }
  ok("an MP4 body under an images-type record is refused before any upload", threw);
  ok("the refusal is tagged type-mismatch (a closed fault class)", cls === "type-mismatch");
}
{
  let threw = false;
  let cls: string | undefined;
  try {
    validateMediaBytesType("stream", REAL_PNG); // a record whose NAME says "stream" but whose bytes are an image
  } catch (e) {
    threw = true;
    cls = mediaFaultOf(e)?.cls;
  }
  ok("a PNG body under a stream-type record is refused before any upload", threw);
  ok("the refusal is tagged type-mismatch", cls === "type-mismatch");
}
{
  let threw = false;
  try {
    validateMediaBytesType("stream", REAL_GIF);
  } catch {
    threw = true;
  }
  ok("a GIF body under a stream-type record is also refused", threw);
}
{
  let threw = false;
  try {
    validateMediaBytesType("images", REAL_WEBM);
  } catch {
    threw = true;
  }
  ok("a WEBM body under an images-type record is also refused", threw);
}

// ---- end-to-end through runRestore/runApply: a mismatched-type media record is a per-record FAILURE, the
// apply is not ok, and the type-mismatch class is tallied on the result -- never a silent re-upload.

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

async function buildMediaArchive(imageBlobBytes: Uint8Array, videoBlobBytes: Uint8Array): Promise<{ archiveR2: MockR2Archive; opB64: string; signerB64: string }> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const records: WriteRecord[] = [
    { sourceType: "images", name: "img-swap/blob", value: imageBlobBytes, account: ACCT },
    { sourceType: "stream", name: "vid-swap/video.mp4", value: videoBlobBytes, account: ACCT },
  ];
  const archive = await buildArchive({
    downpipeId: DP_ID,
    downpipeName: "media-typecheck",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records,
    windowStart: "2026-09-13T00:00:00.000Z",
    windowEnd: "2026-09-13T00:00:01.000Z",
    createdAt: "2026-09-13T00:00:01.000Z",
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

// A recording stub uploader: on a happy path it reports success and remembers the contentType it was
// called with, so the fix to restore-apply.ts (pass the sniffed contentType through) is directly observed.
function recordingUploader(calls: { image?: string | undefined; video?: string | undefined }): MediaUploader {
  return {
    uploadImage: async (_a, id, _b, contentType): Promise<MediaUploadResult> => {
      calls.image = contentType;
      return { restoredId: id, remapped: false, verifiedSha384: null, verified: true, via: "media-image-readback", readbackReadable: true };
    },
    uploadStreamVideo: async (_a, uid, _b, contentType): Promise<MediaUploadResult> => {
      calls.video = contentType;
      return { restoredId: `new-${uid}`, remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true };
    },
  };
}

async function sectionEndToEndMismatch(): Promise<void> {
  console.log("\nend-to-end: an images-typed record whose bytes are actually a video is a per-record FAILURE:");
  // The archive's "images" blob is REAL MP4 BYTES (a mislabelled / corrupted capture, or a crafted swap);
  // the "stream" blob is a real PNG. Both are genuine cross-type mismatches.
  const { archiveR2, opB64, signerB64 } = await buildMediaArchive(REAL_MP4, REAL_PNG);
  const env = envFor(archiveR2, opB64, signerB64);
  const calls: { image?: string | undefined; video?: string | undefined } = {};
  const res = (await runRestore(env, { runId: RUN_ID, confirm: true, mediaRestore: { token: "edit-tok", accountId: ACCT } }, undefined, {
    mediaUploaderFactory: () => recordingUploader(calls),
  })) as RestoreResult;

  ok("the apply is NOT ok (a mismatched record must never restore silently)", res.ok === false);
  ok("neither mismatched record was actually uploaded", calls.image === undefined && calls.video === undefined);
  ok("the images-typed record is in failures", res.failures.some((f) => f.name === "img-swap/blob"));
  ok("the stream-typed record is in failures", res.failures.some((f) => f.name === "vid-swap/video.mp4"));
  ok("neither mismatched record appears in mediaRestored", !(res.mediaRestored ?? []).some((m) => m.name === "img-swap/blob" || m.name === "vid-swap/video.mp4"));
  ok("the type-mismatch class is tallied on the result", res.mediaFaults?.["type-mismatch"] === 2);
}

async function sectionEndToEndHappyPassesContentType(): Promise<void> {
  console.log("\nend-to-end: a correctly-typed media record restores, and the sniffed content type IS passed to the uploader:");
  const { archiveR2, opB64, signerB64 } = await buildMediaArchive(REAL_PNG, REAL_MP4);
  const env = envFor(archiveR2, opB64, signerB64);
  const calls: { image?: string | undefined; video?: string | undefined } = {};
  const res = (await runRestore(env, { runId: RUN_ID, confirm: true, mediaRestore: { token: "edit-tok", accountId: ACCT } }, undefined, {
    mediaUploaderFactory: () => recordingUploader(calls),
  })) as RestoreResult;

  ok("the apply is ok", res.ok === true);
  ok("both records restored", (res.mediaRestored ?? []).length === 2);
  ok("the image upload was called with the sniffed content type (was undefined before this fix)", calls.image === "image/png");
  ok("the video upload was called with the sniffed content type (was undefined before this fix)", calls.video === "video/mp4");
}

async function sectionEndToEndUnrecognisedStillRestores(): Promise<void> {
  console.log("\nend-to-end: unrecognised (non-signature) bytes still restore, exactly like the rest of the suite's fixtures:");
  const enc = (s: string) => new TextEncoder().encode(s);
  const { archiveR2, opB64, signerB64 } = await buildMediaArchive(enc("PNG-BYTES-placeholder"), enc("MP4-BYTES-placeholder"));
  const env = envFor(archiveR2, opB64, signerB64);
  const res = (await runRestore(env, { runId: RUN_ID, confirm: true, mediaRestore: { token: "edit-tok", accountId: ACCT } }, undefined, {
    mediaUploaderFactory: () => recordingUploader({}),
  })) as RestoreResult;

  ok("the apply is ok (an incomplete signature list never bounces the customer's real content)", res.ok === true);
  ok("both records restored", (res.mediaRestored ?? []).length === 2);
  ok("no type-mismatch fault was tallied", res.mediaFaults?.["type-mismatch"] === undefined);
}

async function main(): Promise<void> {
  await sectionEndToEndMismatch();
  await sectionEndToEndHappyPassesContentType();
  await sectionEndToEndUnrecognisedStillRestores();
  console.log(failures === 0 ? "\nMEDIA RESTORE TYPE-CHECK PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
