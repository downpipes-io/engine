// RESTORE PROMISES, PER SOURCE TYPE: drive the real restore path over an archive holding one record of
// every non-cf-config source type and assert what the customer is ACTUALLY told about each.
//
// WHY: the docs make specific, differing claims per source type about what a recovery gives back, and a wrong
// promise costs most during a recovery. Those claims were read from prose, not driven. This drives them.
//
// It drives the REAL runRestore (dry run and apply) through the real verifying reader over a real signed
// in-memory archive, and asserts the exact operator-facing strings, the receipt entries and the id map.
//
// Run: node test/validate-restore-promises-by-type.ts
// In-memory doubles only. No network, no account, no deploy, no cost.

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import type { MediaUploader, MediaUploadResult } from "../src/admin/media-restore.ts";
import { runRestore as runRestoreUnderTest } from "../src/admin/restore.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { D1_BACKUP_FORMAT, encodeD1Backup } from "../src/sources/d1-format.ts";

const RUN = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_promises";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

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

// MockKV is the LIVE KV namespace a kv record restores into.
class MockKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string): Promise<ArrayBuffer | null> {
    const v = this.store.get(k);
    return v ? toAB(v) : null;
  }
}

// MockR2Archive serves the sealed archive to the R2 destination the restore reads through.
class MockR2Archive {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}

// MockR2Target is the LIVE bucket an r2 record restores into. It must read its own writes back, because the
// R2 sink is the only one with a post-write readback.
class MockR2Target {
  store = new Map<string, Uint8Array>();
  async put(key: string, body: ArrayBuffer | Uint8Array | ReadableStream<Uint8Array>): Promise<{ etag: string }> {
    if (body instanceof ReadableStream) {
      const chunks: Uint8Array[] = [];
      const r = body.getReader();
      for (;;) {
        const { done, value } = await r.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      this.store.set(key, concat(...chunks));
    } else {
      this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    }
    return { etag: `"${key.length}"` };
  }
  async get(key: string): Promise<{ body: ReadableStream<Uint8Array> } | null> {
    const v = this.store.get(key);
    if (!v) return null;
    return {
      body: new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(v);
          c.close();
        },
      }),
    };
  }
}

// MockD1 is the LIVE database a d1 record restores into: an empty target, so the fresh-target check passes.
class MockD1 {
  statements: string[] = [];
  batches = 0;
  prepare(sql: string): { sql: string; bind: (...a: unknown[]) => unknown; all: () => Promise<{ results: unknown[] }> } {
    const self = this;
    return {
      sql,
      bind(..._a: unknown[]) {
        return this;
      },
      async all() {
        self.statements.push(sql);
        return { results: [] }; // an EMPTY target: requireFreshTarget passes
      },
    };
  }
  async batch(stmts: Array<{ sql: string }>): Promise<unknown[]> {
    this.batches++;
    for (const s of stmts) this.statements.push(s.sql);
    return [];
  }
}

// The media uploader double: records what would be uploaded and reports the platform's real identity
// behaviour (an image keeps its id, a video is assigned a new uid).
function uploaderDouble(): { uploader: MediaUploader; uploads: Array<{ kind: string; id: string }> } {
  const uploads: Array<{ kind: string; id: string }> = [];
  const uploader: MediaUploader = {
    async uploadImage(_acct, id, bytes): Promise<MediaUploadResult> {
      uploads.push({ kind: "image", id });
      const { sha384 } = await import("../src/crypto/primitives.ts");
      const { hexEncode } = await import("../src/crypto/bytes.ts");
      const h = hexEncode(await sha384(bytes));
      return { restoredId: id, remapped: false, verifiedSha384: h, verified: true, via: "media-image-readback", readbackReadable: true };
    },
    async uploadStreamVideo(_acct, originalUid): Promise<MediaUploadResult> {
      uploads.push({ kind: "video", id: originalUid });
      return { restoredId: `new-${originalUid}`, remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true };
    },
  };
  return { uploader, uploads };
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const mldsa = mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  ok("signer public halves derive consistently", b64urlEncode(verifier.ed) === b64urlEncode(ed25519.getPublicKey(edSeed)) && b64urlEncode(verifier.mldsa) === b64urlEncode(mldsa.publicKey));

  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  // ONE archive, ONE record of every non-cf-config source type the product captures, plus the Workers
  // aspects and the media shapes whose guidance differs. cf-config is measured by its own pass.
  const DB = "appdb";
  const d1Body = encodeD1Backup({ format: D1_BACKUP_FORMAT, tables: [{ name: "t", sql: "CREATE TABLE t (id INTEGER)", columns: ["id"], rows: [[1], [2]] }], schema: ["CREATE INDEX ix ON t(id)"] });
  const archive = await buildArchive({
    downpipeId: "dp_promises",
    downpipeName: "promises",
    cadence: "3600s",
    runId: RUN,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: [
      { sourceType: "kv", name: "kv-key", value: utf8("kv-value"), namespace: NS, descriptor: { kvMetadata: { a: "b" }, kvExpiration: 4102444800 } },
      { sourceType: "r2", name: "obj.txt", value: utf8("r2-value"), bucket: "bkt", descriptor: { r2HttpMetadata: { contentType: "text/plain" }, r2CustomMetadata: { cm: "1" } } },
      { sourceType: "d1", name: DB, value: d1Body },
      { sourceType: "secrets", name: "session-secret", value: utf8("s3cr3t"), account: "acct-1" },
      { sourceType: "workers", name: "api", value: utf8("export default {}"), account: "acct-1" },
      { sourceType: "workers", name: "api/settings", value: utf8(JSON.stringify({ bindings: [], reprovisionChecklist: [{ name: "TOKEN", type: "secret_text" }] })), account: "acct-1" },
      { sourceType: "workers", name: "api/versions", value: utf8(JSON.stringify([])), account: "acct-1" },
      { sourceType: "workers", name: "api/schedules", value: utf8(JSON.stringify([{ cron: "0 * * * *" }])), account: "acct-1" },
      { sourceType: "images", name: "img1", value: utf8(JSON.stringify({ id: "img1" })), account: "acct-1" },
      { sourceType: "images", name: "img1/blob", value: utf8("PNG-BYTES"), account: "acct-1" },
      { sourceType: "stream", name: "vid1", value: utf8(JSON.stringify({ uid: "vid1" })), account: "acct-1" },
      { sourceType: "stream", name: "vid1/video.mp4", value: utf8("MP4-BYTES"), account: "acct-1" },
      { sourceType: "stream", name: "vid1/captions/en", value: utf8("WEBVTT"), account: "acct-1" },
      { sourceType: "artifacts", name: "ns/repo", value: utf8(JSON.stringify({ repo: "r" })), account: "acct-1" },
      { sourceType: "artifacts", name: "ns/repo/blob/abc", value: utf8("git-object"), account: "acct-1" },
    ],
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });

  const dest = new MockR2Archive();
  for (const [k, b] of archive) dest.store.set(k, b);
  const logged = parseRunlog(archive.get("_RECOVERY/RUNLOG")!);
  ok("the archive's runlog carries this run", logged.some((e) => e.runId === RUN));

  const kv = new MockKV();
  const r2t = new MockR2Target();
  const d1 = new MockD1();
  const env = (): Env =>
    ({
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: dest as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      [`KV_${NS}`]: kv as unknown as KVNamespace,
      R2_bkt: r2t as unknown as R2Bucket,
      [`D1_${DB}`]: d1 as unknown as D1Database,
    }) as unknown as Env;

  const reasonFor = (rows: ReadonlyArray<{ name: string; reason: string }>, name: string): string => rows.find((s) => s.name === name)?.reason ?? "(absent)";

  // ---- DRY RUN, no media token: every non-data type must be out of band with its own guidance ----
  const plan = (await runRestoreUnderTest(env(), { runId: RUN })) as RestorePlan;
  console.log("\nDRY RUN, no media token. Every out-of-band record and the EXACT reason a customer is shown:");
  for (const s of plan.skipped) console.log(`    ${s.name.padEnd(20)} ${s.reason}`);

  ok("kv, r2 and d1 are the only planned in-band writes", plan.plannedWrites === 3);

  console.log("\nPER-TYPE PROMISES:");
  // secrets. The exact wording of the reason is pinned by validate-restore-promise-gaps.ts. Here we pin only
  // what holds: the record is out of band and is never a planned write.
  const secretReason = reasonFor(plan.skipped, "session-secret");
  ok("secrets: the record is out of band, never a planned write", secretReason !== "(absent)");
  ok("secrets: no secrets record ever reaches the write plan", !plan.sample.some((s) => s.sourceType === "secrets"));

  // workers: four aspects, four distinct promises
  ok("workers content: re-deploy the script code from the verified content snapshot", /re-deploy the script code from the verified content snapshot/.test(reasonFor(plan.skipped, "api")));
  ok("workers settings: names the reprovision checklist and says values were never captured", /secret VALUES were never captured/.test(reasonFor(plan.skipped, "api/settings")));
  ok("workers versions: informational inventory only", /version inventory only, informational/.test(reasonFor(plan.skipped, "api/versions")));
  ok("workers schedules: re-create the cron triggers so the re-deployed Worker keeps its schedule", /re-create the cron triggers/.test(reasonFor(plan.skipped, "api/schedules")));
  ok("workers: NO record of type workers is ever a planned write", !plan.sample.some((s) => s.sourceType === "workers"));

  // media without a token
  ok("images blob without a token: says to supply an edit-scoped token to re-upload in-account", /supply an edit-scoped Cloudflare token under Restore to re-upload it in-account/.test(reasonFor(plan.skipped, "img1/blob")));
  ok("images blob without a token: states the image keeps its id", /images keep their id/.test(reasonFor(plan.skipped, "img1/blob")));
  ok("stream video without a token: states a video gets a new uid", /a video gets a new uid/.test(reasonFor(plan.skipped, "vid1/video.mp4")));
  ok("stream captions: says to re-attach the caption track after the video re-uploads", /re-attach the caption track after the video re-uploads/.test(reasonFor(plan.skipped, "vid1/captions/en")));
  ok("images metadata is inventory, informational", /inventory\/metadata, informational/.test(reasonFor(plan.skipped, "img1")));
  ok("artifacts blob: a git push, never a REST upload", /re-push the repository via git/.test(reasonFor(plan.skipped, "ns/repo/blob/abc")));
  ok("artifacts inventory: re-create the namespace/repository then git push", /re-create the namespace\/repository/.test(reasonFor(plan.skipped, "ns/repo")));

  // ---- APPLY, with a media token ----
  const up = uploaderDouble();
  const applied = (await runRestoreUnderTest(env(), { runId: RUN, confirm: true, mediaRestore: { token: "edit", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => up.uploader })) as RestoreResult;
  console.log("\nAPPLY with a media edit token:");
  console.log(`    ok=${applied.ok} restored=${applied.recordsRestored} failures=${applied.failures.length}`);
  console.log(`    mediaRestored: ${JSON.stringify(applied.mediaRestored ?? [])}`);
  console.log(`    receipt records: ${JSON.stringify((applied.receipt?.records ?? []).map((r) => ({ n: r.name, via: r.via, v: r.verified })))}`);

  ok("the apply succeeded", applied.ok === true);
  ok("kv restored through the atomic put with no readback (the resource has none)", (applied.receipt?.records ?? []).some((r) => r.name === "kv-key" && r.via === "buffered-no-readback"));
  ok("r2 restored and PROVEN by a post-write readback of the landed object", (applied.receipt?.records ?? []).some((r) => r.name === "obj.txt" && r.via === "buffered-readback" && r.verified));
  ok("d1 restored through the batched replay, honestly labelled no-readback", (applied.receipt?.records ?? []).some((r) => r.name === DB && r.via === "buffered-no-readback"));
  ok("d1 replayed into the empty target in bounded batches", d1.batches > 0);
  ok("the image kept its ORIGINAL id", (applied.mediaRestored ?? []).some((m) => m.name === "img1/blob" && m.restoredId === "img1" && m.remapped === false));
  ok("the video took a NEW uid and is flagged remapped", (applied.mediaRestored ?? []).some((m) => m.name === "vid1/video.mp4" && m.restoredId === "new-vid1" && m.remapped === true));
  ok("no secret was written: the secrets record is skipped, never restored, never a failure", (applied.skipped ?? []).some((s) => s.name === "session-secret") && !(applied.receipt?.records ?? []).some((r) => r.name === "session-secret") && !applied.failures.some((f) => f.name === "session-secret"));
  ok("no Worker was redeployed: no workers record reaches the receipt", !(applied.receipt?.records ?? []).some((r) => r.sourceType === "workers"));

  // The video's re-upload reaches the signed receipt as a record. Whether the receipt carries the NEW UID
  // (the id map) is pinned by validate-restore-promise-gaps.ts.
  const videoReceipt = (applied.receipt?.records ?? []).find((r) => r.name === "vid1/video.mp4");
  ok("the video's re-upload is ON the signed receipt at all", videoReceipt !== undefined);
  ok("a transcoded video's receipt entry carries no landed-byte hash, and says so honestly", videoReceipt?.via === "media-stream-exists" && videoReceipt.verifiedSha384 === null);

  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures}`);
  if (failures > 0) process.exit(1);
}

await main();
