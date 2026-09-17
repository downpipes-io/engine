// Media auto-restore: re-upload captured media BYTES back into the account via the Cloudflare REST API,
// the "next increment" over the out-of-band reprovision default for stream/images (cf. the cf-config
// in-console write path). It is OPT-IN and SAFE-BY-DEFAULT exactly like cf-config restore: nothing is
// written unless the caller supplies an EDIT-scoped token AND confirms (a dry run reports what would be
// uploaded). The re-upload is ADDITIVE (it creates resources, never deletes), so it cannot brick a live
// service the way a blind Worker redeploy could.
//
// Per type:
//   - images: POST /images/v1 with a CUSTOM id (the original id, parsed from the "<id>/blob" record name),
//     so an image restores to its ORIGINAL identity when that id is free; identity-preserving.
//   - stream: POST /stream (direct upload) returns a NEW uid (Stream does not let a caller choose the uid),
//     so the restore reports an id-map (old uid -> new uid) for the operator to update references. Bounded
//     to STREAM_DIRECT_MAX; a larger video stays out of band (the tus resumable-upload path is a known
//     follow-up, not yet built).
//   - artifacts: re-push is the git smart-HTTP protocol, not a REST upload, so it is NOT auto-restored here
//     (a genuine API limit, surfaced as out-of-band guidance, like Vectorize vectors).
//
// The token is NEVER stored, NEVER logged, and used only for these uploads. Everything is retry-wrapped.

import type { CfPacer } from "../cf-pace.ts";
import { hexEncode } from "../crypto/bytes.ts";
import { sha384 } from "../crypto/primitives.ts";
import { isIncompleteMarkerValue } from "../seal/marker.ts";
import { API_WRITE_RETRY, parseRetryAfter, rateLimitError, withRetry } from "../seal/retry.ts";
import { CF_API_BASE } from "../lib/outbound.ts";

// The base URL lives in src/lib/outbound.ts (the one place vendor hosts are enumerated, V13.2.5).

// MEDIA_UPLOAD_MAX bounds an in-account re-upload. The upload is multipart/form-data with no streaming
// path (the Images/Stream direct-upload APIs take a whole body), so the value is held in memory; this cap
// keeps a re-upload well within a Worker's ~128 MiB limit allowing for the FormData copy. BACKUP has no
// such limit (it chains any size); a media file past this is surfaced for offline/manual re-upload, not
// auto-restored in-account. Most images fit; a large video does not (and stream also remaps its uid).
export const MEDIA_UPLOAD_MAX = 25 * 1024 * 1024; // 25 MiB

// STREAM_DIRECT_MAX bounds a single direct (non-resumable) Stream upload. Cloudflare's direct-upload POST
// accepts up to 200 MB (decimal, 200,000,000 bytes); a larger video needs the tus resumable protocol (a
// follow-up), so it stays out of band rather than failing a restore. The local guard matches Cloudflare's
// unit so a video between 200 MB and 200 MiB is surfaced out of band here rather than rejected downstream.
export const STREAM_DIRECT_MAX = 200_000_000; // 200 MB (decimal), the Cloudflare direct-upload ceiling

// MediaUploadResult reports what one re-upload produced AND its post-upload verification: a media
// restore carries the SAME verify-on-readback assurance the KV/R2/D1 sinks do, within the platform's
// reality. restoredId/remapped are the id-map (the original id for images, the new uid for a transcoded
// video). verifiedSha384/verified/via are the proof:
//   - images keep their ORIGINAL id, so the re-upload is proven by a DIRECT BYTE READBACK: the live /blob is
//     read back and re-hashed; verifiedSha384 is that hash and verified is true iff it equals the archived
//     bytes' SHA-384 (via "media-image-readback"). A mismatch is verified:false (a failed restore upstream).
//   - a VIDEO is transcoded by Stream to a NEW uid, so a byte-for-byte readback is impossible; the engine
//     proves the new uid RESOLVES (the live object is queryable) instead. verifiedSha384 is null (no byte
//     proof on a transcoded asset) and verified is true iff the uid resolved (via "media-stream-exists").
export interface MediaUploadResult {
  restoredId: string;
  remapped: boolean; // true when the service assigned a new id (stream); false when the original id was kept (images)
  verifiedSha384: string | null; // the readback hash (images); null for a transcoded video (no byte proof)
  verified: boolean; // images: readback hash equals the archived bytes; stream: the new uid resolves
  via: "media-image-readback" | "media-stream-exists"; // which proof produced verified
  // readbackReadable distinguishes the two ways an image proof can fail, which need OPPOSITE answers even
  // though both otherwise report simply verified:false:
  //   readbackReadable true  + verified false => the live /blob WAS read and its bytes DO NOT match the archive:
  //                                              a real, durable restore failure worth escalating.
  //   readbackReadable false + verified false => the live /blob could not be read AT ALL (a transient 5xx, a
  //                                              throttle, a propagation lag): the bytes may be perfectly fine
  //                                              and the answer is "retry", not "the restore is corrupt".
  // Always true on the stream path (uid resolution either happened or the fault is the resolution itself).
  readbackReadable: boolean;
}

// ---- the media re-upload's CLOSED failure classes ---------------------------------------------------
//
// THE GAP: "some videos restored, some failed". A record over the 200 MB direct-upload cap, a transient
// Cloudflare blip, and an id that is OCCUPIED BY DIFFERENT LIVE BYTES all land in the same anonymous per-record
// failure prose, and the apply's audit summary counts only {failures}. Support cannot say which of the three it
// is, and a conflict dispute ("that image WAS ours") has no digest evidence to adjudicate.
//
// THE RECORD: the throw is TAGGED here with a closed class (and, for a conflict, the archived + live SHA-384
// pair). The apply counts the classes; the router stamps the counts onto the restore-receipt audit target.
//
// REDACTION: the classes are a closed enum; the digests are SHA-384 hashes of the customer's OWN bytes, which is
// exactly the join-key idiom the receipt already carries (expectedSha384 / verifiedSha384) and is irreversible.
// The media bytes, the Cloudflare error body and the deploy token never ride.
export const MEDIA_FAULT_CLASSES = [
  "over-size-cap", // the value is past the direct-upload ceiling (200 MB for Stream): a PLATFORM limit, not a fault. The video must go out of band, and no amount of retrying will change that
  "conflict-different-bytes", // the id is occupied by a DIFFERENT live asset (the 409 whose live bytes do not hash to the archived bytes). NOT overwritten (no-clobber): the operator must choose to overwrite or remap
  "conflict-unreadable", // the id is occupied (409) but the live asset could not be READ to adjudicate: we cannot tell an idempotent re-restore from a genuine conflict, so we refuse rather than guess
  "upload-failed", // the upload POST itself was refused / faulted (a token scope problem, a CF-side fault, a throttle)
  "readback-unreadable", // the upload landed but the live /blob could NOT be read back to prove it: possibly a transient blip, and the correct answer is retry, not "corrupt"
  "readback-mismatch", // the upload landed, the live /blob WAS read, and its bytes DO NOT match the archive: a real restore failure
  "type-mismatch", // ASVS V5.2.2: the decrypted bytes are recognisably the OTHER media kind (a video body under an images-type record, or the reverse); refused before any upload, never forwarded unexamined
  "other", // residual: a media fault outside the named classes
] as const;
export type MediaFaultClass = (typeof MEDIA_FAULT_CLASSES)[number];
const MEDIA_FAULT_CLASS_SET: ReadonlySet<string> = new Set(MEDIA_FAULT_CLASSES);

/** The bounded media-fault tag. A closed class plus, on a conflict, the archived/live digest PAIR. */
export interface MediaFaultInfo {
  readonly cls: MediaFaultClass;
  readonly archivedSha384?: string; // the signed plaintext hash of what we hold
  readonly liveSha384?: string; // the hash of what is actually sitting on that id right now
}

/**
 * MediaFault TAGS a media re-upload throw with its closed class at the site that knows it. The MESSAGE is
 * unchanged, so the operator-facing per-record failure prose and every existing test are byte-identical; the tag
 * is additional, and only the tag is ever recorded.
 */
export class MediaFault extends Error {
  readonly mediaFault: MediaFaultInfo;
  constructor(message: string, fault: MediaFaultInfo) {
    super(message);
    this.name = "MediaFault";
    this.mediaFault = fault;
  }
}

// A SHA-384 hex digest is exactly 96 lower-case hex characters. The shape gate is the redaction boundary for the
// two digest fields: nothing that is not a bare hex digest can ever be recorded through them.
const SHA384_HEX = /^[0-9a-f]{96}$/;

/**
 * mediaFaultOf reads the closed tag off a thrown media fault, or null when it carries none. It NEVER reads an
 * untagged error's message (the sealErrorClassOf idiom: guessing from free text is exactly the leak the tag
 * prevents -- a Cloudflare media error can embed an account id and an asset id), and it re-validates the class
 * against the closed set and each digest against the SHA-384 hex shape, so even a forged tag cannot widen what is
 * recorded.
 *
 * @param e - the thrown value.
 * @returns the bounded fault, or null when untagged.
 */
export function mediaFaultOf(e: unknown): MediaFaultInfo | null {
  const f = (e as { mediaFault?: unknown } | null)?.mediaFault as Partial<MediaFaultInfo> | undefined;
  if (f === undefined || f === null || typeof f !== "object") return null;
  if (typeof f.cls !== "string" || !MEDIA_FAULT_CLASS_SET.has(f.cls)) return null;
  const archived = typeof f.archivedSha384 === "string" && SHA384_HEX.test(f.archivedSha384) ? f.archivedSha384 : undefined;
  const live = typeof f.liveSha384 === "string" && SHA384_HEX.test(f.liveSha384) ? f.liveSha384 : undefined;
  return {
    cls: f.cls as MediaFaultClass,
    ...(archived !== undefined ? { archivedSha384: archived } : {}),
    ...(live !== undefined ? { liveSha384: live } : {}),
  };
}

// ---- ASVS V5.2.2: a magic-byte type check gates every media re-upload ---------------------------------
//
// THE GAP: restore-apply.ts re-uploaded a media record's decrypted bytes to Cloudflare Images/Stream with
// NO check that the bytes actually ARE the kind of media the record claims, and never passed a content
// type either. The record's "images" vs "stream" TYPE comes from its capture-side record NAME
// ("<id>/blob" vs "<uid>/video.mp4", parsed by imageIdFromRecordName / streamUidFromRecordName above),
// never from the bytes -- so a record whose name says "images" but whose decrypted bytes are actually a
// video container (a mislabelled capture, a corrupted archive, or a crafted swap) would be forwarded to
// the Images endpoint unexamined, and the mirror case to Stream.
//
// validateMediaBytesType closes this: it sniffs the bytes' OWN leading magic number against a small closed
// allow-list of the container families each Cloudflare service actually serves, and refuses a PROVABLE
// cross-type mismatch (bytes that are recognisably the OTHER media kind) before any network call. Bytes
// that match NEITHER known signature are left alone rather than bounced: the restored bytes are the
// customer's own backed-up content, no fixed signature list is exhaustive (HEIC/AVIF/TIFF images, MOV/FLV/
// MPEG-TS videos and others are not enumerated below), and the check exists to catch a provable mismatch
// cheaply, not to second-guess every format the allow-list happens to miss.
const IMAGE_MAGIC: ReadonlyArray<{ contentType: string; magic: readonly number[] }> = [
  { contentType: "image/png", magic: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { contentType: "image/jpeg", magic: [0xff, 0xd8, 0xff] },
  { contentType: "image/gif", magic: [0x47, 0x49, 0x46, 0x38] }, // "GIF8" (covers both GIF87a and GIF89a)
  { contentType: "image/bmp", magic: [0x42, 0x4d] },
];

function matchesMagic(bytes: Uint8Array, magic: readonly number[]): boolean {
  if (bytes.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) if (bytes[i] !== magic[i]) return false;
  return true;
}

// fourCcAt reads a 4-byte ASCII tag at a fixed offset (a RIFF/ISO-base-media four-character-code), or ""
// when the bytes are too short to hold one there.
function fourCcAt(bytes: Uint8Array, offset: number): string {
  if (bytes.length < offset + 4) return "";
  return String.fromCharCode(bytes[offset] ?? 0, bytes[offset + 1] ?? 0, bytes[offset + 2] ?? 0, bytes[offset + 3] ?? 0);
}

// sniffImageContentType recognises PNG/JPEG/GIF/BMP by their fixed leading magic, plus WEBP (a RIFF
// container whose inner four-character-code is "WEBP"). Returns undefined when nothing matches.
function sniffImageContentType(bytes: Uint8Array): string | undefined {
  for (const sig of IMAGE_MAGIC) if (matchesMagic(bytes, sig.magic)) return sig.contentType;
  if (fourCcAt(bytes, 0) === "RIFF" && fourCcAt(bytes, 8) === "WEBP") return "image/webp";
  return undefined;
}

// HEIC/HEIF ftyp brands are STILL IMAGES wrapped in the same ISO-base-media box family MP4 uses, so an
// "ftyp" box alone cannot tell an MP4 video from a HEIC image apart -- only the brand can. Excluded here so
// a HEIC image is never mis-sniffed as a video (sniffImageContentType does not claim it either: HEIC is
// outside this allow-list, so it is correctly left unrecognised rather than misclassified).
const HEIF_FTYP_BRANDS: ReadonlySet<string> = new Set(["heic", "heix", "heim", "heis", "hevc", "hevx", "mif1", "msf1"]);

// sniffVideoContentType recognises the ISO-base-media family (MP4/MOV/3GP, via the "ftyp" box) except its
// HEIF/HEIC still-image brands, plus WEBM/MKV (the EBML header) and AVI (a RIFF container whose inner
// four-character-code is "AVI "). Returns undefined when nothing matches.
function sniffVideoContentType(bytes: Uint8Array): string | undefined {
  if (fourCcAt(bytes, 4) === "ftyp") {
    const brand = fourCcAt(bytes, 8);
    if (HEIF_FTYP_BRANDS.has(brand)) return undefined;
    return "video/mp4";
  }
  if (bytes.length >= 4 && bytes[0] === 0x1a && bytes[1] === 0x45 && bytes[2] === 0xdf && bytes[3] === 0xa3) return "video/webm";
  if (fourCcAt(bytes, 0) === "RIFF" && fourCcAt(bytes, 8) === "AVI ") return "video/x-msvideo";
  return undefined;
}

/**
 * validateMediaBytesType sniffs a decrypted media record's own leading bytes and returns the content type
 * to re-upload it with (undefined when the bytes match no known signature), OR throws a MediaFault (cls
 * "type-mismatch") when the bytes are recognisably the OTHER media kind than `type` expects -- an images-
 * type record whose bytes are a known video container, or a stream-type record whose bytes are a known
 * image format. Called once per record, before any upload (restore-apply.ts), so a cross-type mismatch is
 * refused before it ever reaches Cloudflare Images/Stream.
 *
 * Bytes matching neither an image nor a video signature are NOT refused: they report undefined and the
 * caller uploads with no explicit content type, exactly as before this check existed. No fixed signature
 * list is exhaustive, and the restored bytes are the customer's own backed-up content -- this check exists
 * to catch a provable mismatch cheaply, never to bounce a real file the allow-list does not happen to name.
 *
 * @param type - the record's declared media kind, from its capture-side record name.
 * @param bytes - the decrypted record bytes (already plaintext-hash-verified by the caller).
 * @returns the sniffed content type, or undefined when the bytes match no known signature.
 */
export function validateMediaBytesType(type: "images" | "stream", bytes: Uint8Array): string | undefined {
  const imageType = sniffImageContentType(bytes);
  const videoType = sniffVideoContentType(bytes);
  if (type === "images") {
    if (videoType !== undefined) {
      throw new MediaFault(
        `media re-upload refused: the decrypted bytes are a recognised video container (${videoType}), not an image, for a record captured as an image`,
        { cls: "type-mismatch" },
      );
    }
    return imageType;
  }
  if (imageType !== undefined) {
    throw new MediaFault(
      `media re-upload refused: the decrypted bytes are a recognised image format (${imageType}), not a video, for a record captured as a video`,
      { cls: "type-mismatch" },
    );
  }
  return videoType;
}

// MediaUploader re-uploads one media value. It is an interface so the restore validator drives it with an
// in-memory stub (no network); production builds the fetch-backed impl with the edit token.
export interface MediaUploader {
  // uploadImage re-uploads an image to its ORIGINAL id (identity-preserving), then PROVES it by reading the
  // live /blob back and hashing it (the result carries verifiedSha384 + verified, via "media-image-readback").
  // Throws on a failed upload; a readback that does not match the archived bytes returns verified:false (the
  // bytes landed but are wrong), which the apply path drains to a failure.
  uploadImage(accountId: string, id: string, bytes: Uint8Array, contentType?: string): Promise<MediaUploadResult>;
  // uploadStreamVideo re-uploads a video via direct upload; the service assigns a NEW uid (returned as
  // remapped). Stream TRANSCODES, so a byte readback is impossible; the result instead reports whether the
  // new uid RESOLVES (verified, via "media-stream-exists", verifiedSha384 null). Throws on a failed upload
  // or a body past STREAM_DIRECT_MAX.
  uploadStreamVideo(accountId: string, originalUid: string, bytes: Uint8Array, contentType?: string): Promise<MediaUploadResult>;
}

// isMarkerValue reports whether decrypted blob bytes are SHAPED LIKE one of the capture-side MARKER records
// (a small JSON object carrying ONE of the incompleteness sentinel keys) rather than real file bytes.
//
// NOT AUTHORITATIVE: a real customer file could coincidentally decrypt to this exact shape, so the
// media restore gate in restore-apply.ts/restore-plan.ts does not call this -- it reads rec.incompleteMarker
// (the signed manifest field, stamped at seal time from the source adapter's OWN markerKind assertion)
// instead. This stays as a thin alias over seal/marker.ts isIncompleteMarkerValue for tests/tooling that want
// a pure content-shape check, SINGLE-SOURCED on the same key set (MARKER_KEYS) so it can never recognise a
// different set of sentinels than the seal does. Hand-rolling a subset of sentinel keys instead of delegating
// could silently miss one (such as _refused), laundering a refused Stream record into a bogus restored video.
export function isMarkerValue(bytes: Uint8Array): boolean {
  return isIncompleteMarkerValue(bytes);
}

// imageIdFromRecordName extracts the original image id from an "<id>/blob" record name (the capture-side
// shape). Returns undefined for any other shape (so a metadata/marker record is never treated as a blob).
export function imageIdFromRecordName(name: string): string | undefined {
  const m = /^(.+)\/blob$/.exec(name);
  return m ? m[1] : undefined;
}

// streamUidFromRecordName extracts the original video uid from a "<uid>/video.mp4" record name.
export function streamUidFromRecordName(name: string): string | undefined {
  const m = /^(.+)\/video\.mp4$/.exec(name);
  return m ? m[1] : undefined;
}

// makeMediaUploader builds the fetch-backed uploader with the EDIT-scoped token. Multipart form uploads
// (the Images + Stream direct-upload contract) are sent as FormData; the Cloudflare success envelope is
// unwrapped and a non-ok response throws (a 429 carries the parsed Retry-After for withRetry).
export function makeMediaUploader(token: string, fetchImpl: typeof fetch = fetch, pacer?: CfPacer): MediaUploader {
  const auth = { authorization: `Bearer ${token}` };
  // unwrapResp turns one Cloudflare response into its result object, or THROWS (a 429 becomes a rateLimitError
  // carrying the parsed Retry-After). Shared by the idempotent and non-idempotent post paths.
  const unwrapResp = async (path: string, resp: Response): Promise<Record<string, unknown>> => {
    const b = (await resp.json().catch(() => null)) as
      | { success?: boolean; result?: unknown; errors?: Array<{ message?: string }> }
      | null;
    if (!resp.ok || b?.success !== true) {
      const why = (b?.errors ?? []).map((e) => e.message).filter(Boolean).join("; ") || `HTTP ${resp.status}`;
      throw resp.status === 429
        ? rateLimitError(`media upload ${path}: ${why}`, parseRetryAfter(resp.headers.get("retry-after")))
        : new Error(`media upload ${path}: ${why}`);
    }
    return (b?.result ?? {}) as Record<string, unknown>;
  };
  // postFormOnce issues a SINGLE multipart POST (no withRetry). Used for the non-idempotent Stream upload,
  // where the server assigns a fresh uid on every call: a blind retry after a lost response would create a
  // second ORPHAN video, so the caller surfaces a single-attempt failure cleanly instead.
  const postFormOnce = async (path: string, form: FormData): Promise<Record<string, unknown>> => {
    await pacer?.take();
    const resp = await fetchImpl(`${CF_API_BASE}${path}`, { method: "POST", headers: auth, body: form, redirect: "manual" });
    return unwrapResp(path, resp);
  };

  return {
    uploadImage: async (accountId, id, bytes, contentType) => {
      const path = `/accounts/${encodeURIComponent(accountId)}/images/v1`;
      // The image POST carries a CUSTOM id, so it IS idempotent on id: a retry after a lost success re-POSTs
      // the same id and Cloudflare returns HTTP 409 (duplicate). 409 is not transient, so withRetry would fail
      // the restore even though the image exists. Guard it: on a 409, the id is already taken, but only a
      // BYTE-IDENTICAL live image means OUR upload landed (an idempotent re-restore). A DIFFERENT image
      // occupying the id is a CONFLICT, not a success: reporting success there would tell the operator the
      // archived image was restored when a different image holds that id (a silent no-restore). So fetch the
      // live image's bytes (the /blob delivery endpoint), hash them, and compare to the archived bytes:
      //   - digests MATCH => the prior POST landed (or a true idempotent re-restore); treat as success.
      //   - digests DIFFER (or the bytes are unreadable) => CONFLICT; throw so the apply records a per-record
      //     failure (no-clobber: the re-upload is additive and must never overwrite a live image), leaving
      //     the operator to choose to overwrite or remap rather than believing a false success.
      const archivedDigest = hexEncode(await sha384(bytes));
      // readbackDigest hashes the live /blob of the restored id (the image keeps its original id), so the
      // result is PROVEN against what actually persisted, not against the write path's claim of success. A
      // /blob GET that cannot be read leaves the readback hash null and verified:false (a failed proof);
      // the apply path drains that to a per-record failure (the bytes may have landed but cannot be proven).
      const readbackDigest = async (): Promise<string | null> => {
        await pacer?.take();
        const get = await fetchImpl(`${CF_API_BASE}${path}/${encodeURIComponent(id)}/blob`, { method: "GET", headers: auth, redirect: "manual" });
        if (!get.ok) return null;
        return hexEncode(await sha384(new Uint8Array(await get.arrayBuffer())));
      };
      const result = await withRetry(async () => {
        const form = new FormData();
        form.append("file", new Blob([bytes as BlobPart], contentType !== undefined ? { type: contentType } : {}), id);
        form.append("id", id); // custom id => restore to the ORIGINAL identity (when free)
        await pacer?.take();
        const resp = await fetchImpl(`${CF_API_BASE}${path}`, { method: "POST", headers: auth, body: form, redirect: "manual" });
        if (resp.status === 409) {
          await pacer?.take();
          const get = await fetchImpl(`${CF_API_BASE}${path}/${encodeURIComponent(id)}/blob`, { method: "GET", headers: auth, redirect: "manual" });
          if (!get.ok) {
            // A 409 we could NOT adjudicate. Its own class: we cannot tell an idempotent re-restore from a
            // real conflict, which is a different answer from "a different image is sitting on that id".
            throw new MediaFault(
              `media upload ${path}: id already exists and the live image could not be read to verify it (HTTP ${get.status})`,
              { cls: "conflict-unreadable", archivedSha384: archivedDigest },
            );
          }
          const live = new Uint8Array(await get.arrayBuffer());
          const liveDigest = hexEncode(await sha384(live));
          if (liveDigest === archivedDigest) {
            return { id, conflictReadback: liveDigest }; // byte-identical: the prior POST landed (idempotent re-restore)
          }
          // The id is occupied by DIFFERENT live bytes. Carry BOTH digests (of the customer's own bytes,
          // the same irreversible join-key idiom the receipt already uses for expectedSha384/verifiedSha384), so
          // a "that image WAS ours" dispute can actually be ADJUDICATED from the pack instead of argued.
          throw new MediaFault(
            `media upload ${path}: id "${id}" is occupied by a DIFFERENT live image (bytes do not match the archived image); not overwritten`,
            { cls: "conflict-different-bytes", archivedSha384: archivedDigest, liveSha384: liveDigest },
          );
        }
        return unwrapResp(path, resp);
      }, API_WRITE_RETRY);
      const restoredId = typeof result.id === "string" ? result.id : id;
      // VERIFY-ON-READBACK: re-read the live /blob and hash it. On the 409-byte-identical path the readback
      // hash was already computed (it is the archived digest by construction); otherwise read the /blob now.
      const verifiedSha384 = typeof result.conflictReadback === "string" ? result.conflictReadback : await readbackDigest();
      const verified = verifiedSha384 === archivedDigest;
      // A NULL readback hash means the live /blob could not be READ (a transient 5xx / throttle), which is
      // a different fact from "it was read and the bytes are wrong", even though both report verified:false.
      return { restoredId, remapped: restoredId !== id, verifiedSha384, verified, via: "media-image-readback", readbackReadable: verifiedSha384 !== null };
    },
    uploadStreamVideo: async (accountId, originalUid, bytes, contentType) => {
      if (bytes.length > STREAM_DIRECT_MAX) {
        // A PLATFORM ceiling, not a fault. Its own class, because no amount of retrying will restore this
        // video in-account -- the honest answer is "recover it out of band", and support must be able to say so.
        throw new MediaFault("video exceeds the 200 MB direct-upload limit; use the resumable (tus) path", { cls: "over-size-cap" });
      }
      const form = new FormData();
      form.append("file", new Blob([bytes as BlobPart], contentType !== undefined ? { type: contentType } : {}), `${originalUid}.mp4`);
      // Single attempt: the POST is NOT idempotent (a new uid per call), so a retry could orphan a video.
      const result = await postFormOnce(`/accounts/${encodeURIComponent(accountId)}/stream`, form);
      const newUid = typeof result.uid === "string" ? result.uid : originalUid;
      // VERIFY WHAT IS VERIFIABLE on a transcoded asset: Stream re-encodes the upload, so a byte-for-byte
      // readback is impossible. Instead confirm the NEW uid RESOLVES (the live video object is queryable): a
      // GET of /stream/<uid> that returns a success envelope whose uid matches proves the upload was accepted
      // and is addressable. A uid that does not resolve is verified:false (the apply drains it to a failure).
      let verified = false;
      try {
        await pacer?.take();
        const get = await fetchImpl(`${CF_API_BASE}/accounts/${encodeURIComponent(accountId)}/stream/${encodeURIComponent(newUid)}`, { method: "GET", headers: auth, redirect: "manual" });
        if (get.ok) {
          const b = (await get.json().catch(() => null)) as { success?: boolean; result?: { uid?: string } } | null;
          verified = b?.success === true && b.result?.uid === newUid;
        }
      } catch {
        verified = false;
      }
      // readbackReadable is always true on the stream path: a transcoded asset has no byte proof to be unreadable
      // (the proof IS the uid resolution, which `verified` carries).
      return { restoredId: newUid, remapped: newUid !== originalUid, verifiedSha384: null, verified, via: "media-stream-exists", readbackReadable: true };
    },
  };
}
