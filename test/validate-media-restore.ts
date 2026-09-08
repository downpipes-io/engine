// Validates the media re-upload helpers (src/admin/media-restore.ts): the marker detector (a captured
// "_unavailable"/"_skipped" blob is NOT real file bytes), the id parsers (the original image id / video
// uid from a record name), and the fetch-backed uploader (multipart POST with a CUSTOM id so an image
// restores to its ORIGINAL identity; a video direct-upload returns a new uid and refuses an oversized
// body). No network: a fake fetch inspects the FormData and returns the Cloudflare success envelope.

import { makeMediaUploader, isMarkerValue, imageIdFromRecordName, streamUidFromRecordName, STREAM_DIRECT_MAX, MEDIA_UPLOAD_MAX } from "../src/admin/media-restore.ts";
import { MARKER_KEYS, isIncompleteMarkerValue } from "../src/seal/marker.ts";
import { hexEncode } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";

let failures = 0;
function ok(msg: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${msg}`);
  if (!cond) failures++;
}
const enc = (s: string) => new TextEncoder().encode(s);

console.log("-- isMarkerValue: a capture marker is not real file bytes --");
ok("an _unavailable marker is detected", isMarkerValue(enc(JSON.stringify({ _unavailable: "403" }))));
ok("a _skipped marker is detected", isMarkerValue(enc(JSON.stringify({ _skipped: "too large", size: 9 }))));
ok("a _pending marker is detected", isMarkerValue(enc(JSON.stringify({ _pending: "download inprogress" }))));
ok("real binary (PNG header) is NOT a marker", !isMarkerValue(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a])));
ok("a plain JSON object without a marker key is NOT a marker", !isMarkerValue(enc(JSON.stringify({ id: "x", filename: "a.png" }))));
ok("oversized input is cheaply rejected (not parsed)", !isMarkerValue(new Uint8Array(5000)));

console.log("\n-- a {_refused} Stream marker is detected (was the silently-missed key that laundered a refused video into a bogus restore) --");
// stream.ts emits {_refused:...} when a Stream download URL fails the SSRF host allow-list: the video was
// HONESTLY NOT captured. The OLD restore-side isMarkerValue hand-rolled a subset (_skipped/_unavailable/
// _pending/_truncated) and MISSED _refused, so this ~80-byte marker slipped the guard, was POSTed to Stream
// as a bogus "video", got a new uid, and the restore reported SUCCESS. Asserting it is now detected:
const refusedMarker = enc(JSON.stringify({ _refused: "download url is not an https cloudflarestream.com address", host: "evil.example" }));
ok("a {_refused} Stream marker IS detected (skipped at restore, never re-uploaded as a video)", isMarkerValue(refusedMarker));

console.log("\n-- the restore-side detector is SINGLE-SOURCED on seal/marker.ts (can never drift) and skips ALL FIVE marker kinds --");
// The two detectors must mirror each other. isMarkerValue now delegates to isIncompleteMarkerValue, so this
// loop proves every sentinel key (MARKER_KEYS) is recognised by BOTH and that they agree key-for-key.
for (const key of MARKER_KEYS) {
  const m = enc(JSON.stringify({ [key]: "honestly not captured" }));
  ok(`marker kind "${key}" is skipped at restore (isMarkerValue)`, isMarkerValue(m));
  ok(`marker kind "${key}" agrees with seal/marker.ts isIncompleteMarkerValue`, isMarkerValue(m) === isIncompleteMarkerValue(m));
}
ok("the restore-side detector recognises exactly the seal-side MARKER_KEYS set (all six, incl. _vanished)", MARKER_KEYS.length === 6);

console.log("\n-- id parsers --");
ok("imageIdFromRecordName('abc/blob') = 'abc'", imageIdFromRecordName("abc/blob") === "abc");
ok("imageIdFromRecordName('abc') (metadata) = undefined", imageIdFromRecordName("abc") === undefined);
ok("streamUidFromRecordName('v1/video.mp4') = 'v1'", streamUidFromRecordName("v1/video.mp4") === "v1");
ok("streamUidFromRecordName('v1/captions/en.vtt') = undefined", streamUidFromRecordName("v1/captions/en.vtt") === undefined);

console.log("\n-- uploader: image re-upload posts the bytes with a CUSTOM id (identity-preserving) + reads it back --");
{
  const imgBytes = enc("PNG-BYTES");
  let captured: { url: string; auth: string | null; id: unknown; fileSize: number } | null = null;
  let readbackGets = 0;
  const fetchImpl = (async (url: string, init?: { method?: string; headers?: HeadersInit; body?: unknown }) => {
    if ((init?.method ?? "GET") === "GET") {
      // the post-upload READBACK of the live /blob (the image kept its original id). Return the
      // SAME bytes that were uploaded so the readback hash matches the archived bytes (a proven restore).
      readbackGets++;
      ok("the readback GET targets the /blob delivery endpoint", url.endsWith("/images/v1/orig-id/blob"));
      return new Response(imgBytes as BlobPart, { status: 200, headers: { "content-type": "image/png" } });
    }
    const form = init?.body as FormData;
    const file = form.get("file") as Blob;
    // Normalise via Headers so the assertion holds whether the uploader passes a plain object or a
    // Headers instance (the header lookup is case-insensitive once wrapped).
    const auth = new Headers(init?.headers).get("authorization");
    captured = { url, auth, id: form.get("id"), fileSize: file.size };
    return new Response(JSON.stringify({ success: true, result: { id: form.get("id") } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  const res = await up.uploadImage("acct1", "orig-id", imgBytes, "image/png");
  ok("posts to the account's images/v1 endpoint", captured!.url.endsWith("/accounts/acct1/images/v1"));
  ok("sends the edit-scoped bearer token", captured!.auth === "Bearer edit-tok");
  ok("sends the original id as a custom id (restore to original identity)", captured!.id === "orig-id");
  ok("uploads the file bytes", captured!.fileSize === imgBytes.length);
  ok("reports the restored id, not remapped", res.restoredId === "orig-id" && res.remapped === false);
  ok("read the live /blob back exactly once to verify", readbackGets === 1);
  ok("the readback hash equals the archived bytes' SHA-384 (verified, via:media-image-readback)", res.verified === true && res.via === "media-image-readback" && res.verifiedSha384 === hexEncode(await sha384(imgBytes)));
}

console.log("\n-- uploader: an image whose live /blob does NOT match the archived bytes is verified:false  --");
{
  // The POST succeeds, but the post-upload /blob readback returns DIFFERENT bytes (the upload landed wrong,
  // or a different image occupies the id by the time we read it back). The result must be verified:false, so
  // the apply records a per-record failure rather than a silent success.
  const fetchImpl = (async (_url: string, init?: { method?: string }) => {
    if ((init?.method ?? "GET") === "GET") {
      return new Response(enc("A-DIFFERENT-IMAGE-LANDED") as BlobPart, { status: 200, headers: { "content-type": "image/png" } });
    }
    return new Response(JSON.stringify({ success: true, result: { id: "orig-id" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  const res = await up.uploadImage("acct1", "orig-id", enc("THE-ARCHIVED-IMAGE"));
  ok("a readback mismatch reports verified:false (not a silent success)", res.verified === false && res.via === "media-image-readback");
  ok("the readback hash differs from the archived bytes' hash", res.verifiedSha384 !== null && res.verifiedSha384 !== hexEncode(await sha384(enc("THE-ARCHIVED-IMAGE"))));
}

console.log("\n-- uploader: an image whose live /blob is unreadable on readback is verified:false  --");
{
  const fetchImpl = (async (_url: string, init?: { method?: string }) => {
    if ((init?.method ?? "GET") === "GET") return new Response("", { status: 404 });
    return new Response(JSON.stringify({ success: true, result: { id: "orig-id" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  const res = await up.uploadImage("acct1", "orig-id", enc("BYTES"));
  ok("an unreadable readback reports verifiedSha384:null and verified:false", res.verifiedSha384 === null && res.verified === false);
}

console.log("\n-- uploader: video direct-upload returns a NEW uid (remapped) + confirms the uid resolves  --");
{
  let existsGets = 0;
  const fetchImpl = (async (url: string, init?: { method?: string }) => {
    if ((init?.method ?? "GET") === "GET") {
      // the post-upload EXISTENCE proof. Stream transcodes (no byte readback possible), so the uploader
      // confirms the NEW uid resolves by GETting /stream/<uid> and matching the returned uid.
      existsGets++;
      ok("the existence GET targets /stream/<new-uid>", url.endsWith("/stream/new-uid-123"));
      return new Response(JSON.stringify({ success: true, result: { uid: "new-uid-123", readyToStream: false } }), { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify({ success: true, result: { uid: "new-uid-123" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  const res = await up.uploadStreamVideo("acct1", "old-uid", enc("MP4-BYTES"));
  ok("the service assigns a new uid (remapped id-map entry)", res.restoredId === "new-uid-123" && res.remapped === true);
  ok("the new uid was confirmed to resolve (verified, via:media-stream-exists, no byte hash)", res.verified === true && res.via === "media-stream-exists" && res.verifiedSha384 === null && existsGets === 1);
}

console.log("\n-- uploader: a video whose new uid does NOT resolve is verified:false  --");
{
  const fetchImpl = (async (_url: string, init?: { method?: string }) => {
    if ((init?.method ?? "GET") === "GET") return new Response(JSON.stringify({ success: false }), { status: 404, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ success: true, result: { uid: "new-uid-123" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  const res = await up.uploadStreamVideo("acct1", "old-uid", enc("MP4-BYTES"));
  ok("a uid that does not resolve reports verified:false", res.verified === false && res.via === "media-stream-exists");
}

console.log("\n-- uploader: an oversized video is refused before any upload (no streaming-multipart path) --");
{
  let called = false;
  const fetchImpl = (async () => { called = true; return new Response("{}", { status: 200 }); }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  let threw = false;
  try {
    await up.uploadStreamVideo("acct1", "u", new Uint8Array(STREAM_DIRECT_MAX + 1));
  } catch {
    threw = true;
  }
  ok("a video over the direct-upload limit throws, no fetch issued", threw && !called);
}

console.log("\n-- uploader: a Cloudflare error envelope throws (never a silent success) --");
{
  // 409 with no surviving image: the POST 409s, the confirm blob GET also 409s (no such image), so it throws.
  const fetchImpl = (async () =>
    new Response(JSON.stringify({ success: false, errors: [{ message: "id already exists" }] }), { status: 409, headers: { "content-type": "application/json" } })) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  let threw = false;
  try {
    await up.uploadImage("acct1", "dup", enc("x"));
  } catch (e) {
    threw = e instanceof Error && /could not be read to verify/.test(e.message);
  }
  ok("a failed upload (409, image absent/unreadable) throws", threw);
}

console.log("\n-- uploader: image 409 with BYTE-IDENTICAL live image is an idempotent re-restore (success) --");
{
  // First POST 409s (a retry of an already-landed upload); the confirm blob GET returns the SAME bytes we
  // are restoring, so the digests match and the restore succeeds. This is the idempotent-on-id recovery.
  const bytes = enc("PNG-IDENTICAL-BYTES");
  let posts = 0;
  let gets = 0;
  const fetchImpl = (async (url: string, init?: { method?: string }) => {
    if ((init?.method ?? "GET") === "POST") {
      posts++;
      return new Response(JSON.stringify({ success: false, errors: [{ message: "id already exists" }] }), { status: 409, headers: { "content-type": "application/json" } });
    }
    gets++;
    ok("the confirm GET targets the /blob delivery endpoint", url.endsWith("/images/v1/kept-id/blob"));
    return new Response(bytes as BlobPart, { status: 200, headers: { "content-type": "image/png" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  const res = await up.uploadImage("acct1", "kept-id", bytes);
  ok("a 409 confirmed by byte-identical blob reports the kept id (not remapped, not failed)", res.restoredId === "kept-id" && res.remapped === false);
  ok("exactly one POST and one confirm blob GET were issued", posts === 1 && gets === 1);
}

console.log("\n-- uploader: image 409 where the live id holds a DIFFERENT image surfaces a CONFLICT (not success) --");
{
  // the id is taken by a DIFFERENT live image (its bytes differ from the archived image). Reporting
  // success here would tell the operator the archived image was restored when a different image occupies the
  // id (a silent no-restore). The uploader must throw a conflict so the apply records a per-record failure.
  // The stub faithfully models the REAL Cloudflare API: the metadata GET (/images/v1/<id>) reports the id
  // exists; the blob GET (/images/v1/<id>/blob) returns the DIFFERENT live bytes. The OLD code consulted the
  // metadata GET only, so the id-exists envelope made it report SUCCESS (the bug this fixes). The fixed code reads
  // the blob, finds the bytes differ from the archived image, and surfaces a conflict.
  let posts = 0;
  let gets = 0;
  const fetchImpl = (async (url: string, init?: { method?: string }) => {
    if ((init?.method ?? "GET") === "POST") {
      posts++;
      return new Response(JSON.stringify({ success: false, errors: [{ message: "id already exists" }] }), { status: 409, headers: { "content-type": "application/json" } });
    }
    gets++;
    if (url.endsWith("/blob")) {
      // The live image at this id holds DIFFERENT bytes (a different image).
      return new Response(enc("A-COMPLETELY-DIFFERENT-IMAGE") as BlobPart, { status: 200, headers: { "content-type": "image/png" } });
    }
    // The metadata GET (what the OLD code consulted): the id DOES exist.
    return new Response(JSON.stringify({ success: true, result: { id: "taken-id" } }), { status: 200, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  let threw = false;
  let succeededWrongly = false;
  try {
    const res = await up.uploadImage("acct1", "taken-id", enc("THE-ARCHIVED-IMAGE-BYTES"));
    // OLD code: a 409 confirmed by mere id existence reports success here (the bug R1-2 fixes).
    succeededWrongly = res.restoredId === "taken-id";
  } catch (e) {
    threw = e instanceof Error && /DIFFERENT live image/.test(e.message) && /not overwritten/.test(e.message);
  }
  ok("a 409 over a different live image throws a CONFLICT, never reports success", threw && !succeededWrongly);
  ok("the conflict was detected by comparing bytes (POST then a confirm blob GET)", posts === 1 && gets === 1);
}

console.log("\n-- uploader: a Stream upload is NOT retried (orphan prevention) --");
{
  // A transient failure on the non-idempotent Stream POST must surface as a single-attempt failure: retrying
  // would create a second orphan video, so the uploader issues exactly one POST.
  let posts = 0;
  const fetchImpl = (async () => {
    posts++;
    return new Response(JSON.stringify({ success: false, errors: [{ message: "upstream timeout" }] }), { status: 500, headers: { "content-type": "application/json" } });
  }) as unknown as typeof fetch;
  const up = makeMediaUploader("edit-tok", fetchImpl);
  let threw = false;
  try {
    await up.uploadStreamVideo("acct1", "old-uid", enc("MP4"));
  } catch (e) {
    threw = e instanceof Error && /upstream timeout/.test(e.message);
  }
  ok("a failed Stream upload throws after exactly one POST (no retry, no orphan)", threw && posts === 1);
}

console.log("\n-- size constants are ordered sanely --");
ok("MEDIA_UPLOAD_MAX (in-memory re-upload cap) < STREAM_DIRECT_MAX (Stream's direct-POST cap)", MEDIA_UPLOAD_MAX < STREAM_DIRECT_MAX);
// Pin the absolute values so a silent mutation (both equal, one zeroed) is caught, not just the order.
ok("MEDIA_UPLOAD_MAX is exactly 25 MiB", MEDIA_UPLOAD_MAX === 25 * 1024 * 1024);
ok("STREAM_DIRECT_MAX is exactly 200 MB (decimal), the Cloudflare direct-upload ceiling", STREAM_DIRECT_MAX === 200_000_000);

console.log(failures === 0 ? "\nMEDIA-RESTORE PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
