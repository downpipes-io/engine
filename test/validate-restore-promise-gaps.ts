// This file drives three documented restore behaviours against the engine's real code, each against the
// doc line that makes the claim, proving the engine keeps every promise the documentation makes about
// restore. Each block keeps a record of what could otherwise go wrong, because a passing assertion with no
// account of what it guards against is the first thing that looks safe to delete.
//
// Run it directly with `npm run validate:restore-promise-gaps`.
//
// SECRETS OUT-OF-BAND REASON. A secrets record's out-of-band reason names neither the cause nor a remedy if
// left as the bare string "restore out of band" -- unlike Workers, media and Artifact Registry records,
// which each carry a sentence naming what to do. Three docs pages say the secrets guidance names both:
//   docs/src/content/docs/recovery/what-restore-can-and-cannot-write-back.mdx:57
//     "the guidance tells you to re-apply the value, recovered from the archive, through the Cloudflare API
//      or wrangler"
//   docs/src/content/docs/sources/overview.mdx:90
//     "the record is surfaced as 'restore out of band' for you to re-create through the Cloudflare API"
//   docs/src/content/docs/sources/secrets-and-workers.mdx:45
//     "the record is surfaced as 'restore out of band' so the operator knows to restore it manually through
//      the Cloudflare API or wrangler"
// The same page (line 55) also says "the restore sink for secrets refuses a write rather than silently
// skipping it". That mechanism does not run on the restore path: buildRestorePlan routes every secrets
// record to out-of-band before a sink is constructed, so SecretsRestoreSink.put() is never reached from
// runRestore (engine/test/validate-secrets-restore.ts states this at its own line 15). The safety comes from
// the plan-time routing, not from a sink guard that never fires. SECRETS_OUT_OF_BAND_REASON
// (engine/src/admin/restore-sinks.ts) is the one shared constant naming the read-only binding and the
// re-creation path through the Cloudflare API or wrangler. Note also: the offline Go reader does not restore
// a secrets record by direct value write. Its sinks are file, env and discard, and cmd/downpipe/restore.go
// says a secrets-store target "is not implemented in this binary". So the remedy is to recover the value
// with the reader and re-create the secret by hand, which is what the sentence says.
//
// MEDIA RESTORE RECEIPT ID MAP. Stream transcodes every upload, so a restored video lands on a new uid and
// every reference to the old uid has to be updated. The old-to-new mapping must ride on something durable,
// not only on RestoreResult.mediaRestored, the ephemeral API response: RestoreReceiptRecord carries
// restoredId and remapped fields, so the receipt the console's "Download receipt" button writes
// (console/src/screens/restore-flow/receipt.ts:377, which serialises res.receipt) contains the map, matching
//   docs/src/content/docs/recovery/what-restore-can-and-cannot-write-back.mdx:47
//     "a transcoded video gets a new uid that the receipt reports as an id map"
// The fields are emitted into the signed and hashed receipt core, and only when the upload actually
// remapped, which is the position recordsSkipped, configSkipReasonCounts and destFallback already sit on: a
// receipt with no remapped record canonicalises byte-for-byte as before, so its digest and its signature are
// unchanged and every receipt already anchored in the audit chain still verifies. metadataFieldsDropped sits
// in the same position, one field along.
//
// KV EXPIRATION FIDELITY. KV expirations are captured and reproduced as the absolute Unix epoch second,
// unclamped; a live KV binding refuses an expiration that is not at least sixty seconds in the future. So
// restoring a backup older than a namespace's TTLs would otherwise fail exactly those keys, the dry run
// reporting ok=true while the apply returns "destination access error" for a reason that never mentions an
// expiration and points at the destination instead.
//
// THE JUDGEMENT. Three answers were open: refuse it in the dry run, restore the value without the lapsed
// expiry and say so, or keep failing it with a reason that names the expiration. The last two both leave
// the customer without their data, and restoring a year-old backup is the ORDINARY operation of a backup
// product, not an edge case. There is also no in-product path back: a customer never runs a terminal, and
// the offline reader writes a recovered value to a file, it does not put a KV key back. So the engine
// restores the key with its value and metadata and WITHOUT the lapsed expiration, and says so twice: the
// dry run carries a fidelityWarnings row BEFORE the operator confirms, and the receipt carries the count
// through the shed tally afterwards. Clamping the expiration forward was rejected: it would invent a TTL
// the customer never chose.
//
// The key must actually LAND, the expiration must actually be DROPPED and counted, and the dry run must say
// so before anything is written, matching:
//   docs/src/content/docs/recovery/what-restore-can-and-cannot-write-back.mdx
//     "Workers KV | Yes | Value plus metadata and expiration"
//   docs/src/content/docs/sources/overview.mdx
//     "KV | Writes back in-account at full fidelity through the binding, metadata and expiry reconstructed"
//
// In-memory doubles only. No network, no account, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { APPROVAL_TTL_MS, PLAN_SEEN_PREFIX, RESTORE_APPLY_DEADLINE_MS, RESTORE_APPLY_LEASE_MS, restorePlanHash } from "../src/admin/approvals.ts";
import { CALLER_HEADER, type Caller, encodeCaller } from "../src/admin/identity.ts";
import type { MediaUploader, MediaUploadResult } from "../src/admin/media-restore.ts";
import { runRestore } from "../src/admin/restore.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { kvExpirationLapsed } from "../src/dest/restore-sink.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { seedBoundRole } from "./testutil.ts";

const RUN = "01ARZ3NDEKTSV4RRFFQ69G5FB2";

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

// In-memory Durable Object storage that drives the real SchedulerDO so the approval's expiry is the one the
// product writes rather than one this file computed. Sorted, prefix/limit-aware list, because the
// plan-anchor sweep pages over its own prefix.
class MockDOStorage {
  readonly map = new Map<string, unknown>();
  async get<T>(key: string): Promise<T | undefined> {
    return this.map.get(key) as T | undefined;
  }
  async put<T>(key: string, value: T): Promise<void> {
    this.map.set(key, JSON.parse(JSON.stringify(value)));
  }
  async delete(key: string): Promise<boolean> {
    return this.map.delete(key);
  }
  async list<T>(opts?: { prefix?: string; limit?: number; startAfter?: string }): Promise<Map<string, T>> {
    const prefix = opts?.prefix ?? "";
    let keys = [...this.map.keys()].filter((k) => k.startsWith(prefix)).sort();
    if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
    if (typeof opts?.limit === "number") keys = keys.slice(0, opts.limit);
    const out = new Map<string, T>();
    for (const k of keys) out.set(k, this.map.get(k) as T);
    return out;
  }
  async setAlarm(_t: number): Promise<void> {
    /* no alarm is scheduled by anything this file drives */
  }
}

const uploader: MediaUploader = {
  async uploadImage(_a, id): Promise<MediaUploadResult> {
    return { restoredId: id, remapped: false, verifiedSha384: null, verified: true, via: "media-image-readback", readbackReadable: true };
  },
  async uploadStreamVideo(_a, originalUid): Promise<MediaUploadResult> {
    return { restoredId: `new-${originalUid}`, remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true };
  },
};

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  const archive = await buildArchive({
    downpipeId: "dp_gaps",
    downpipeName: "gaps",
    cadence: "3600s",
    runId: RUN,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: [
      { sourceType: "secrets", name: "session-secret", value: utf8("s3cr3t"), account: "acct-1" },
      { sourceType: "stream", name: "vid1/video.mp4", value: utf8("MP4-BYTES"), account: "acct-1" },
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
  const env = (): Env =>
    ({
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: dest as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
    }) as unknown as Env;

  // ---- Secrets: the out-of-band reason ----
  const plan = (await runRestore(env(), { runId: RUN })) as RestorePlan;
  const secretReason = plan.skipped.find((s) => s.name === "session-secret")?.reason ?? "(absent)";
  console.log(`\nThe exact sentence a customer is shown for a Secrets Store record: "${secretReason}"`);
  ok("the secrets reason NAMES the cause (Secrets Store bindings are read-only at runtime)", /read-only at runtime|Secrets Store/.test(secretReason));
  ok("the secrets reason names a REMEDY (the Cloudflare API or wrangler), as three docs pages state", /Cloudflare API|wrangler/i.test(secretReason));

  // ---- Media restore: the receipt's id map ----
  const applied = (await runRestore(env(), { runId: RUN, confirm: true, mediaRestore: { token: "edit", accountId: "acct-1" } }, null, { mediaUploaderFactory: () => uploader })) as RestoreResult;
  const receiptRow = (applied.receipt?.records ?? []).find((r) => r.name === "vid1/video.mp4");
  console.log(`\nThe ephemeral result carries the id map: ${JSON.stringify(applied.mediaRestored ?? [])}`);
  console.log(`       The SIGNED receipt row the customer downloads:  ${JSON.stringify(receiptRow ?? null)}`);
  ok("the signed receipt row for a remapped video carries the new uid", receiptRow !== undefined && JSON.stringify(receiptRow).includes("new-vid1"));

  // ---- KV restore: an expiration that has already lapsed ----
  // A second archive holding one KV key whose expiration has already LAPSED, restored through a KV double
  // that enforces Cloudflare's own rule (an expiration must be at least sixty seconds in the future).
  const LAPSED_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FB3";
  const NS = "nsttl";
  const lapsed = Math.floor(Date.now() / 1000) - 86_400; // a day in the past: the backup outlived the TTL
  const lapsedArchive = await buildArchive({
    downpipeId: "dp_gaps",
    downpipeName: "gaps",
    cadence: "3600s",
    runId: LAPSED_RUN,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: [
      { sourceType: "kv", name: "ttl-key", value: utf8("still-wanted"), namespace: NS, descriptor: { kvExpiration: lapsed } },
      { sourceType: "kv", name: "plain-key", value: utf8("no-ttl"), namespace: NS },
    ],
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const lapsedDest = new MockR2Archive();
  for (const [k, b] of lapsedArchive) lapsedDest.store.set(k, b);
  // CloudflareLikeKV enforces the binding's documented rule: an absolute expiration must be at least sixty
  // seconds in the future, else the put is rejected.
  const kvStore = new Map<string, Uint8Array>();
  // What the binding was ASKED for, per key, so the test can prove the engine never offered the lapsed
  // expiration rather than inferring it from the double not having thrown.
  const kvPutOpts = new Map<string, { expiration?: number } | undefined>();
  const kvDouble = {
    async put(k: string, v: ArrayBuffer | Uint8Array, opts?: { expiration?: number }): Promise<void> {
      kvPutOpts.set(k, opts);
      if (opts?.expiration !== undefined && opts.expiration < Math.floor(Date.now() / 1000) + 60) {
        throw new Error("KV PUT failed: 400 Invalid expiration of 0. Please specify an integer greater than the current number of seconds since the UNIX epoch.");
      }
      kvStore.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
    },
  };
  const lapsedEnv = (): Env =>
    ({
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: lapsedDest as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      [`KV_${NS}`]: kvDouble as unknown as KVNamespace,
    }) as unknown as Env;

  const lapsedPlan = (await runRestore(lapsedEnv(), { runId: LAPSED_RUN })) as RestorePlan;
  const lapsedApply = (await runRestore(lapsedEnv(), { runId: LAPSED_RUN, confirm: true })) as RestoreResult;
  console.log(`\nThe DRY RUN an operator reads before applying: ok=${lapsedPlan.ok} plannedWrites=${lapsedPlan.plannedWrites} skipped=${lapsedPlan.skipped.length}`);
  for (const w of lapsedPlan.fidelityWarnings ?? []) console.log(`         WARNS ${w.name}: ${w.reason}`);
  console.log(`       The APPLY that follows it:                       ok=${lapsedApply.ok} restored=${lapsedApply.recordsRestored} failures=${lapsedApply.failures.length}`);
  for (const f of lapsedApply.failures) console.log(`         ${f.name}: ${f.reason}`);
  console.log(`       The receipt's record of what was NOT reproduced:  ${JSON.stringify(lapsedApply.metadataFieldsDropped ?? {})}`);
  // The premise control, INVERTED from the original on purpose: the key whose expiration lapsed must now
  // reach the namespace rather than fail. This is the assertion that would catch a regression to the old
  // behaviour, and it is the whole point of the change.
  ok("the lapsed-TTL key LANDS in the namespace rather than failing the apply", kvStore.has("ttl-key") && !lapsedApply.failures.some((f) => f.name === "ttl-key"));
  ok("the sibling key with no TTL restores fine (per-record isolation)", kvStore.has("plain-key"));
  ok("the DRY RUN warns, BEFORE the operator confirms, that a recovered expiration has already lapsed", (lapsedPlan.fidelityWarnings ?? []).some((w) => /expir|lapsed|TTL/i.test(w.reason)));
  ok("the APPLY records the dropped expiration rather than claiming full fidelity", (lapsedApply.metadataFieldsDropped?.["kv-expiration-lapsed"] ?? 0) === 1);
  // And it must be on the artefact the customer KEEPS, not only on the live response, matching the media
  // receipt's id map: the console's "Download receipt" button serialises res.receipt, so a count that lives
  // only on RestoreResult is gone the moment the screen is closed.
  ok("the SIGNED receipt carries the dropped-expiration count, not just the live response", (lapsedApply.receipt?.summary.metadataFieldsDropped?.["kv-expiration-lapsed"] ?? 0) === 1);
  // The value must be the RECOVERED value, not an empty or sentinel write: a restore that lands the key and
  // loses its contents would satisfy every assertion above and be worse than the failure it replaced.
  ok("the landed key holds the recovered value, not a placeholder", new TextDecoder().decode(kvStore.get("ttl-key") ?? new Uint8Array()) === "still-wanted");
  // And the drop must be SPECIFIC to the lapsed case: a still-valid expiration must reach the binding
  // untouched, or the fix would have silently stripped every TTL in the product.
  ok("a still-valid future expiration is NOT dropped", kvExpirationLapsed(Math.floor(Date.now() / 1000) + 86_400) === false && kvExpirationLapsed(lapsed) === true);
  ok("the binding was never OFFERED the lapsed expiration (the drop is at the sink, not a swallowed error)", kvPutOpts.has("ttl-key") && kvPutOpts.get("ttl-key")?.expiration === undefined);

  // ---- KV restore: the plan and the apply read different clocks ----
  //
  // Running the dry run and the apply back to back sees both agree on the second by accident. A real
  // restore does not work that way: the plan is read, a second person approves it, and the apply happens
  // later. If nowMs is read fresh at each call site, an expiration sitting between the two instants reads
  // NOT lapsed in the plan the operator approved and LAPSED at the sink, and the key is dropped with nothing
  // in that plan naming it -- a silent drop that only shows up once the clock is allowed to move between the
  // two calls.
  //
  // So this block moves the clock. One key expires ten minutes out, which is comfortably valid at plan time
  // (KV_EXPIRATION_MIN_LEAD_SECONDS is 60), and the apply runs eleven minutes later.
  const SKEW_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FB4";
  const SKEW_NS = "nsskew";
  const ADVANCE_MS = 11 * 60 * 1000;
  const skewExpiration = Math.floor(Date.now() / 1000) + 600; // valid now, gone in eleven minutes
  const skewArchive = await buildArchive({
    downpipeId: "dp_gaps",
    downpipeName: "gaps",
    cadence: "3600s",
    runId: SKEW_RUN,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: [{ sourceType: "kv", name: "skew-key", value: utf8("still-wanted"), namespace: SKEW_NS, descriptor: { kvExpiration: skewExpiration } }],
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const skewDest = new MockR2Archive();
  for (const [k, b] of skewArchive) skewDest.store.set(k, b);
  const skewStore = new Map<string, Uint8Array>();
  const skewPutOpts = new Map<string, { expiration?: number } | undefined>();
  const skewKv = {
    async put(k: string, v: ArrayBuffer | Uint8Array, opts?: { expiration?: number }): Promise<void> {
      skewPutOpts.set(k, opts);
      if (opts?.expiration !== undefined && opts.expiration < Math.floor(Date.now() / 1000) + 60) {
        throw new Error("KV PUT failed: 400 Invalid expiration of 0. Please specify an integer greater than the current number of seconds since the UNIX epoch.");
      }
      skewStore.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
    },
  };
  const skewEnv = (): Env =>
    ({
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: skewDest as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      [`KV_${SKEW_NS}`]: skewKv as unknown as KVNamespace,
    }) as unknown as Env;

  const skewPlan = (await runRestore(skewEnv(), { runId: SKEW_RUN })) as RestorePlan;
  // The clock moves HERE, between the two calls, which is the whole point. It is restored in a finally so a
  // failure in the apply cannot leave every later test running against a fake clock.
  const realNow = Date.now;
  let skewApply: RestoreResult;
  try {
    Date.now = () => realNow.call(Date) + ADVANCE_MS;
    skewApply = (await runRestore(skewEnv(), { runId: SKEW_RUN, confirm: true })) as RestoreResult;
  } finally {
    Date.now = realNow;
  }
  const skewWarned = (skewPlan.fidelityWarnings ?? []).length;
  const skewDropped = skewApply.metadataFieldsDropped?.["kv-expiration-lapsed"] ?? 0;
  console.log(`\nAn expiration ${skewExpiration - Math.floor(Date.now() / 1000)}s out, applied ${ADVANCE_MS / 60_000} minutes after the dry run.`);
  for (const w of skewPlan.fidelityWarnings ?? []) console.log(`         PLAN WARNS ${w.name}: ${w.reason}`);
  console.log(`         APPLY DROPPED: ${JSON.stringify(skewApply.metadataFieldsDropped ?? {})}`);

  // The premise control first. If the clock did not actually move the sink's answer, everything below is
  // asserting about a case that never happened, and a green would mean nothing.
  ok("the advanced clock really does make the sink drop this expiration", skewDropped === 1);
  ok("and the key still lands with its recovered value, so this is a fidelity loss and not a data loss", new TextDecoder().decode(skewStore.get("skew-key") ?? new Uint8Array()) === "still-wanted");
  // THE ASSERTION THIS BLOCK EXISTS FOR. A restore must never drop a record the approved plan did not
  // mention, so the plan the operator read has to name this key even though it had not lapsed when they read
  // it.
  ok("the DRY RUN warns about a key that lapses between the plan and the apply", skewWarned === 1);
  ok("and the warning tells the operator the second group is still savable by applying sooner", /Applying sooner/.test((skewPlan.fidelityWarnings ?? [])[0]?.reason ?? ""));

  // THE INVARIANT, stated as an invariant rather than as one example: over every instant an apply of this
  // plan may still be WRITING, what the plan warned about is a SUPERSET of what the sink will drop.
  //
  // Walking a fixed list of offsets measured from the plan instant and comparing each against a warning
  // computed at plan + APPROVAL_TTL_MS would only be a test of its own premise: it would take for granted
  // both that no apply runs later than plan + APPROVAL_TTL_MS (an apply could, if the TTL is stamped at the
  // request rather than the plan) and that an apply stops writing the moment the approval expires (it holds
  // a reservation for RESTORE_APPLY_LEASE_MS afterwards, so it does not). Two independent under-warns would
  // sit inside a green assertion built that way, invisible because it never let the request move and never
  // let the write outlive the approval.
  //
  // So the deadline read here is the PLAN'S OWN published one, reading the product's claim rather than
  // restating the arithmetic that produced it, and the block below drives the approval machinery to prove
  // that no apply can actually get past it.
  const deadlineMs = Date.parse(skewPlan.applyDeadline ?? "");
  ok("the plan states the instant its warning is computed against, so the claim can be checked from outside", Number.isFinite(deadlineMs) && Number.isFinite(Date.parse(skewPlan.plannedAt ?? "")));
  // The deadline must cover the APPLY LEASE, not just the approval's own life. An apply reserved one second
  // inside the window is still writing half an hour later, so a deadline of plan + APPROVAL_TTL_MS describes
  // as safe every key that lapses in those thirty minutes.
  ok(
    "the deadline covers the apply lease, not only the approval's TTL",
    Number.isFinite(deadlineMs) && deadlineMs - Date.parse(skewPlan.plannedAt ?? "") === APPROVAL_TTL_MS + RESTORE_APPLY_LEASE_MS,
  );
  const supersetHolds = [0, ADVANCE_MS, APPROVAL_TTL_MS, APPROVAL_TTL_MS + RESTORE_APPLY_LEASE_MS].every((offset) => {
    const droppedThen = kvExpirationLapsed(skewExpiration, realNow.call(Date) + offset);
    const warnedAtDeadline = kvExpirationLapsed(skewExpiration, deadlineMs);
    return !droppedThen || warnedAtDeadline;
  });
  ok("the plan's warned set is a SUPERSET of the sink's dropped set at every instant an apply may still be writing", supersetHolds);
  // And the superset must not be vacuous in the other direction: the plan may not warn about a key no apply
  // could ever drop, which is what a horizon larger than the deadline would produce.
  ok("a key that outlives the apply deadline is NOT warned about", kvExpirationLapsed(Math.floor(deadlineMs / 1000) + 86_400, deadlineMs) === false);
  // The obvious remedy, refuted rather than argued. Carrying the PLAN's instant into the sink makes the two
  // agree and re-creates the original defect: the sink would read not-lapsed, hand the binding a stale
  // expiration, and the put would be refused. The double above enforces the real rule, so this is measured.
  let bindingRefused = false;
  try {
    Date.now = () => realNow.call(Date) + ADVANCE_MS;
    await skewKv.put("would-fail", new Uint8Array([1]), { expiration: skewExpiration });
  } catch {
    bindingRefused = true;
  } finally {
    Date.now = realNow;
  }
  ok("threading the plan's instant into the sink would restore the ORIGINAL defect, since the binding refuses that expiration now", bindingRefused && kvExpirationLapsed(skewExpiration, realNow.call(Date)) === false);

  // ---- KV restore: the approval clock starts at the request, and the write outlives the approval ----
  //
  // Letting the clock move between the plan and the apply is not enough on its own. Two separate windows
  // can each widen the gap between what the plan warned about and what the sink actually drops:
  //
  //   WINDOW A -- THE APPROVAL CLOCK MUST NOT START AT THE REQUEST. The dry run and the approval request are
  //     separate calls, and the console builds the request from a plan it is holding in memory
  //     (console/src/screens/restore-flow/confirm.ts, renderRequestPanel). If the DO stamped
  //     expiresAt = now + APPROVAL_TTL_MS at the REQUEST rather than the plan, an operator who read a plan
  //     and raised the request three hours later would move the last possible write instant three hours past
  //     the horizon the plan had warned on. And restorePlanHash binds no timestamp, so the SAME displayed
  //     plan could be re-requested after every expiry: the window would not merely widen, it would reopen
  //     for ever.
  //
  //   WINDOW B -- THE APPLY KEEPS WRITING AFTER THE APPROVAL IS SPENT. The router reserves the approval
  //     (router-restore.ts, POST /restore/reserve) and then writes, and the DO honours that reservation for
  //     RESTORE_APPLY_LEASE_MS. An apply reserved one second inside the approval window is still writing half
  //     an hour later, so a horizon of APPROVAL_TTL_MS describes as safe every key lapsing in those minutes.
  //
  // Neither is arguable from the constants alone, so this drives them: the REAL SchedulerDO mints and
  // approves the approval, the deadline is read off the record the DO actually wrote, and the apply runs at
  // that deadline plus the whole lease. Two keys, chosen so each window is separately visible: one lapses
  // inside the lease that follows a prompt approval, one lapses only if the request clock is allowed to slip.
  {
    const G_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FB5";
    const G_NS = "nshorizon";
    const t0 = Date.now();
    const inLease = Math.floor((t0 + APPROVAL_TTL_MS + 12 * 60 * 1000) / 1000); // gone before the lease ends
    const beyondDeadline = Math.floor((t0 + APPROVAL_TTL_MS + 3 * 60 * 60 * 1000) / 1000); // only a slipped request clock reaches it
    const gArchive = await buildArchive({
      downpipeId: "dp_gaps",
      downpipeName: "gaps",
      cadence: "3600s",
      runId: G_RUN,
      master: rand(32),
      recipients: [breakGlass.entry, op.entry],
      signer,
      records: [
        { sourceType: "kv", name: "lapses-in-lease", value: utf8("wanted-a"), namespace: G_NS, descriptor: { kvExpiration: inLease } },
        { sourceType: "kv", name: "lapses-past-deadline", value: utf8("wanted-b"), namespace: G_NS, descriptor: { kvExpiration: beyondDeadline } },
      ],
      windowStart: "2026-06-07T00:00:00.000Z",
      windowEnd: "2026-06-07T00:00:01.000Z",
      createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId: null,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    });
    const gDest = new MockR2Archive();
    for (const [k, b] of gArchive) gDest.store.set(k, b);
    const gPutOpts = new Map<string, { expiration?: number } | undefined>();
    const gKv = {
      async put(k: string, _v: ArrayBuffer | Uint8Array, opts?: { expiration?: number }): Promise<void> {
        gPutOpts.set(k, opts);
        if (opts?.expiration !== undefined && opts.expiration < Math.floor(Date.now() / 1000) + 60) throw new Error("KV PUT failed: 400 Invalid expiration");
      },
    };
    const gEnv = (): Env =>
      ({
        SCHEDULER: {} as unknown as DurableObjectNamespace,
        DEST_KIND: "r2",
        DEST_R2: gDest as unknown as R2Bucket,
        SIGNER_PRIVATE: signerPrivateB64,
        OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
        [`KV_${G_NS}`]: gKv as unknown as KVNamespace,
      }) as unknown as Env;

    // 1) THE PLAN the operator reads, at t0.
    const gPlan = (await runRestore(gEnv(), { runId: G_RUN })) as RestorePlan;
    const gWarned = gPlan.fidelityWarnings ?? [];
    const gPlanHash = await restorePlanHash({ runId: G_RUN });

    // 2) THE APPROVAL, minted by the REAL DO. The dry-run route records the plan anchor (POST
    // /restore/plan-seen); the request is then raised THREE HOURS LATER, which is window A's whole point.
    // Both are driven through the DO's own routes, so the expiresAt below is the one the product writes,
    // not one this test computed for it.
    const storage = new MockDOStorage();
    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const maker: Caller = { method: "access", email: "maker@x.example", subject: "sub|maker", role: "operator", groups: [] };
    const checker: Caller = { method: "access", email: "checker@x.example", subject: "sub|checker", role: "approver", groups: [] };
    await seedBoundRole(storage, maker.subject!, maker.email, maker.role);
    await seedBoundRole(storage, checker.subject!, checker.email, checker.role);
    const doCall = async (path: string, caller: Caller | null, body: unknown): Promise<Response> =>
      dobj.fetch(
        new Request(`https://scheduler.internal${path}`, {
          method: "POST",
          headers: { "content-type": "application/json", ...(caller ? { [CALLER_HEADER]: encodeCaller(caller) } : {}) },
          body: JSON.stringify(body),
        }),
      );
    // Exactly what router-restore.ts sends from the dry-run branch: the hash, and the PLAN'S OWN instant
    // rather than this call's, because the plan computed its deadline from that instant.
    const anchorResp = await doCall("/restore/plan-seen", null, { planHash: gPlanHash, plannedAt: Date.parse(gPlan.plannedAt ?? "") });
    const gRealNow = Date.now;
    let approval: { expiresAt?: string } = {};
    try {
      Date.now = () => gRealNow.call(Date) + 3 * 60 * 60 * 1000; // the operator sits on the plan for three hours
      await doCall("/restore/request", maker, { planHash: gPlanHash, runId: G_RUN, reason: "horizon drive" });
      approval = (await (await doCall("/restore/approve", checker, { planHash: gPlanHash })).json()) as { expiresAt?: string };
    } finally {
      Date.now = gRealNow;
    }
    const expiresAtMs = Date.parse(approval.expiresAt ?? "");
    // 3) THE LAST INSTANT A WRITE CAN LAND: the approval is reserved while it is still valid, and the write
    // continues under that reservation for the whole lease. This is the instant the plan's warning has to
    // have covered.
    const lastWriteMs = expiresAtMs + RESTORE_APPLY_LEASE_MS;
    let gApply: RestoreResult;
    try {
      Date.now = () => lastWriteMs;
      gApply = (await runRestore(gEnv(), { runId: G_RUN, confirm: true })) as RestoreResult;
    } finally {
      Date.now = gRealNow;
    }
    const gDropped = gApply.metadataFieldsDropped?.["kv-expiration-lapsed"] ?? 0;
    const gWarnedCount = /(\d+) further Workers KV/.exec(gWarned[0]?.reason ?? "")?.[1];
    const gDisclosed = gWarned.length === 0 ? 0 : Number(gWarnedCount ?? "0");
    const droppedNames = ["lapses-in-lease", "lapses-past-deadline"].filter((n) => gPutOpts.has(n) && gPutOpts.get(n)?.expiration === undefined);
    console.log(`\nPlan read at t0; approval requested 3h later; apply writing at the approval's expiry plus the whole ${RESTORE_APPLY_LEASE_MS / 60_000}-minute lease.`);
    console.log(`         PLAN (deadline ${gPlan.applyDeadline ?? "NOT STATED"}) discloses ${gDisclosed} lapsing before it can be applied.`);
    console.log(`         APPROVAL expiresAt ${approval.expiresAt ?? "(none)"}; last possible write ${new Date(lastWriteMs).toISOString()}.`);
    console.log(`         APPLY dropped ${gDropped}: ${droppedNames.join(", ") || "(none)"}`);

    // Premise controls first. If the DO did not mint an approval, or the apply did not actually write, every
    // assertion below is about a case that never happened.
    ok("the DO minted an approval with a parseable expiry", Number.isFinite(expiresAtMs));
    ok("the dry-run route recorded a plan anchor for this plan hash", anchorResp.status === 200 && ((await anchorResp.json()) as { noted?: boolean }).noted === true);
    ok("both keys were offered to the binding, so this is a fidelity question and not a data loss", gPutOpts.has("lapses-in-lease") && gPutOpts.has("lapses-past-deadline"));
    // WINDOW A. An approval may not outlive the plan it was read from: the three hours the operator spent
    // reading must not move the deadline, or the plan warned on one instant while the sink acted on a later
    // one.
    ok(
      "the approval expires relative to the PLAN, not to the request raised three hours later",
      Number.isFinite(expiresAtMs) && expiresAtMs - t0 <= APPROVAL_TTL_MS + 60_000,
    );
    // WINDOW B. The plan's deadline must cover the whole lease, so a write landing at the last permitted
    // instant is still inside what the plan warned about.
    ok(
      "the plan's stated deadline is not earlier than the last instant a write can land",
      Number.isFinite(Date.parse(gPlan.applyDeadline ?? "")) && Date.parse(gPlan.applyDeadline ?? "") >= lastWriteMs,
    );
    // THE PROPERTY ITSELF, over the drive rather than over the arithmetic: nothing the apply dropped was
    // absent from what the plan disclosed.
    ok("the apply drops no more expirations than the plan disclosed, at the last instant it may write", gDropped <= gDisclosed);
    // And it is not green by warning about everything: the key that lapses only PAST the deadline keeps its
    // expiration and is not counted, so the disclosure still tells the operator something.
    ok("the key that lapses past the deadline keeps its expiration, so the horizon is not simply 'warn about every key'", gPutOpts.get("lapses-past-deadline")?.expiration === beyondDeadline);
    ok("and the key that lapses inside the lease is the one both disclosed and dropped", gDisclosed === 1 && droppedNames.length === 1 && droppedNames[0] === "lapses-in-lease");

    // THE INDEFINITE REOPEN, which anchoring alone does not close. restorePlanHash binds no timestamp, so the
    // SAME displayed plan can be re-requested once its approval expires. If a stale anchor simply fell back
    // to "now", each re-request would mint a fresh 24 hours against a plan read days earlier, and the window
    // the two assertions above just closed would reopen once per expiry, for ever. So a request raised
    // against an anchor past its own deadline is REFUSED, and the operator is told to re-plan.
    {
      await doCall("/restore/reject", checker, { planHash: gPlanHash, rejectReason: "stale-plan" });
      await doCall("/restore/plan-seen", null, { planHash: gPlanHash, plannedAt: t0 });
      let reRequest: Response;
      try {
        Date.now = () => t0 + APPROVAL_TTL_MS + RESTORE_APPLY_LEASE_MS + 60_000; // one minute past the plan's own deadline
        reRequest = await doCall("/restore/request", maker, { planHash: gPlanHash, runId: G_RUN, reason: "re-raised against yesterday's plan" });
      } finally {
        Date.now = gRealNow;
      }
      const reBody = (await reRequest.json()) as { error?: string; expiresAt?: string };
      ok("re-requesting the SAME plan hash past its deadline is refused rather than granted a fresh 24 hours", reRequest.status >= 400 && /run the dry run again/.test(reBody.error ?? ""));
      ok("and no approval was minted by that refusal", reBody.expiresAt === undefined);
    }

    // ---- KV restore: the sweep that removes the anchor the refusal reads ----
    //
    // The stale-plan refusal above must hold even when the anchor it reads has been swept away by unrelated
    // traffic, not only when the test mints the anchor itself and never lets the sweep run. notePlanSeen
    // sweeps EVERY entry under the planseen: prefix older than RESTORE_APPLY_DEADLINE_MS, for EVERY plan
    // hash, on EVERY dry run. So a colleague previewing one unrelated plan can delete the anchor this
    // refusal reads; if planAnchorMs then answered null and null were read as "no preview recorded, anchor
    // to now", the operator holding yesterday's card would get a clean 24 hours, reopening the window once
    // per sweep cycle for as long as anybody keeps running dry runs -- with the last write instant landing a
    // full RESTORE_APPLY_DEADLINE_MS past the deadline the plan published, and the apply dropping
    // lapses-past-deadline, the very key the earlier control asserts is not warned about.
    //
    // So this block drives the sweep rather than assuming it away, and the two controls under it exist to
    // prove the sweep really ran: the anchor is read out of the DO's own storage before and after the
    // colleague's call. Without them a refusal here would be indistinguishable from a sweep that never
    // happened.
    {
      const anchorKey = PLAN_SEEN_PREFIX + gPlanHash;
      const COLLEAGUE_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FC6";
      const colleagueHash = await restorePlanHash({ runId: COLLEAGUE_RUN });
      await doCall("/restore/reject", checker, { planHash: gPlanHash, rejectReason: "stale-plan" });
      await doCall("/restore/plan-seen", null, { planHash: gPlanHash, plannedAt: t0 });
      const anchorBefore = storage.map.get(anchorKey);
      const staleNow = t0 + RESTORE_APPLY_DEADLINE_MS + 60_000; // one minute past this plan's own deadline
      let sweptRequest: Response;
      try {
        Date.now = () => staleNow;
        // A COLLEAGUE PREVIEWS SOMETHING ELSE. Read-only, unrelated plan, no privilege beyond restore.dryrun.
        await doCall("/restore/plan-seen", null, { planHash: colleagueHash, plannedAt: staleNow });
        sweptRequest = await doCall("/restore/request", maker, { planHash: gPlanHash, runId: G_RUN, reason: "re-raised after the sweep" });
      } finally {
        Date.now = gRealNow;
      }
      const anchorAfter = storage.map.get(anchorKey);
      const sweptBody = (await sweptRequest.json()) as { error?: string; expiresAt?: string };
      console.log(`\nAnchor for this plan before the colleague's unrelated dry run: ${JSON.stringify(anchorBefore ?? null)}; after: ${JSON.stringify(anchorAfter ?? null)}`);
      console.log(`         Re-request status ${sweptRequest.status}; expiresAt ${sweptBody.expiresAt ?? "(none minted)"}`);
      ok("the anchor for this plan existed before the colleague ran a dry run", anchorBefore !== undefined);
      ok("and the colleague's dry run really did sweep it away, so the refusal is asked the hard question", anchorAfter === undefined);
      ok("the SAME plan hash, past its deadline, is STILL refused after an unrelated dry run swept its anchor", sweptRequest.status >= 400 && /run the dry run/.test(sweptBody.error ?? ""));
      ok("and no approval was minted by that refusal", sweptBody.expiresAt === undefined);
    }

    // NO ANCHOR THAT EVER EXISTED, which is the same storage state as the swept one and must therefore have
    // the same answer. If it did not, the refusal above would be a formality anybody could walk around by
    // waiting for a sweep. It is also the shape of the OTHER way an anchor goes missing: the dry-run route's
    // notePlanSeen swallows its faults, so a Durable Object hiccup during a preview leaves exactly this.
    // Refusing here is what makes that fail-open loud instead of silent: the operator is told to re-run a
    // read-only dry run rather than being handed a window against a plan the engine cannot date.
    {
      const UNSEEN_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FD7";
      const unseenHash = await restorePlanHash({ runId: UNSEEN_RUN });
      const unseenResp = await doCall("/restore/request", maker, { planHash: unseenHash, runId: UNSEEN_RUN, reason: "no dry run was ever recorded" });
      const unseenBody = (await unseenResp.json()) as { error?: string; expiresAt?: string };
      ok("no anchor is recorded for this plan hash at all", storage.map.get(PLAN_SEEN_PREFIX + unseenHash) === undefined);
      ok("a request against a plan with NO recorded dry run is refused, not anchored to now", unseenResp.status >= 400 && /run the dry run/.test(unseenBody.error ?? ""));
      ok("and no approval was minted by that refusal either", unseenBody.expiresAt === undefined);
    }

    // THE COST OF THAT REFUSAL, MEASURED RATHER THAN ARGUED. Refusing on an absent anchor would be the wrong
    // trade if ordinary traffic could take a valid plan's anchor away, because that would refuse a customer
    // holding a current preview during the one operation they cannot postpone. It cannot: the sweep only
    // removes entries ALREADY past RESTORE_APPLY_DEADLINE_MS, so its deletion set is a SUBSET of the set the
    // refusal rejects anyway. Driven here with a planted stale entry as the control, so "the sweep ran" is
    // observed and not inferred from the absence of a failure.
    {
      const CURRENT_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FE8";
      const NOISE_RUN = "01ARZ3NDEKTSV4RRFFQ69G5FF9";
      const currentHash = await restorePlanHash({ runId: CURRENT_RUN });
      const noiseHash = await restorePlanHash({ runId: NOISE_RUN });
      const plantedKey = `${PLAN_SEEN_PREFIX}sha384:planted-stale-entry-for-the-sweep-control`;
      await doCall("/restore/plan-seen", null, { planHash: currentHash, plannedAt: t0 });
      await storage.put(plantedKey, { at: t0 - 2 * RESTORE_APPLY_DEADLINE_MS });
      const busyNow = t0 + 60 * 60 * 1000; // an hour on: well inside the deadline, so this plan is still current
      let currentResp: Response;
      try {
        Date.now = () => busyNow;
        await doCall("/restore/plan-seen", null, { planHash: noiseHash, plannedAt: busyNow });
        currentResp = await doCall("/restore/request", maker, { planHash: currentHash, runId: CURRENT_RUN, reason: "ordinary first request, an hour after the preview" });
      } finally {
        Date.now = gRealNow;
      }
      const currentBody = (await currentResp.json()) as { error?: string; expiresAt?: string };
      const currentExpiry = Date.parse(currentBody.expiresAt ?? "");
      ok("the unrelated dry run really did run the sweep (a planted stale entry is gone)", storage.map.get(plantedKey) === undefined);
      ok("an operator holding a CURRENT plan is still accepted after other people's dry runs have swept", currentResp.status === 200 && storage.map.get(PLAN_SEEN_PREFIX + currentHash) !== undefined);
      ok("and that accepted approval is anchored to the PLAN, not to the request an hour later", Number.isFinite(currentExpiry) && currentExpiry - t0 <= APPROVAL_TTL_MS + 60_000);
    }
  }

  verdictReached(failures);
  console.log(`\nVERDICT: ${failures === 0 ? "PASS (every documented restore behaviour holds)" : `FAIL failures=${failures} (a documented restore behaviour does not hold)`}`);
  if (failures > 0) process.exit(1);
}

await main();
