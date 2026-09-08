// Journey: the CROSS-ACCOUNT (confused-deputy) guard on the cf-config and media restore legs.
// A cf-config or media apply re-applies through the Cloudflare API to a CALLER-SUPPLIED accountId, so a wrong
// or drifted account would land the write in the WRONG account. This drives the REAL runRestore handler
// (through the dest factory + the verifying reader) over signed in-memory archives to prove:
//   - SAME-account restore (target == the archive's signed origin) is UNAFFECTED: it applies and writes.
//   - a CROSS-account restore (target != origin) is SEEN on the dry-run (crossAccountWarnings) and REFUSED on
//     apply before any write, unless the caller EXPLICITLY echoes the target account (confirmDifferentAccountId).
//   - the refusal writes NOTHING, not even the run's data records (the whole restore is refused before any write).
//   - an UNVERIFIABLE origin (an archive that recorded no origin account) fails CLOSED (refused unless confirmed).
//   - a WRONG confirmation (echoing something other than the target) does NOT satisfy the guard.
// Run: node test/validate-restore-cross-account.ts   In-memory doubles only; no network, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer, type WriteRecord } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { runRestore } from "../src/admin/restore.ts";
import { type MediaUploader } from "../src/admin/media-restore.ts";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import type { Env } from "../src/env.d.ts";
import type { RestorePlan, RestoreResult } from "../src/admin/restore-types.ts";
import type { CfApi, CfPage } from "../src/sources/cf-config-surfaces.ts";

const RUN_CFG = "01ARZ3NDEKTSV4RRFFQ69G5CA1"; // cf-config leg (also carries one KV data record)
const RUN_MEDIA = "01ARZ3NDEKTSV4RRFFQ69G5CA2"; // media leg (image + video)
const RUN_NOORIG = "01ARZ3NDEKTSV4RRFFQ69G5CA3"; // a cf-config record with NO captured origin account
const RUN_TWOFOREIGN = "01ARZ3NDEKTSV4RRFFQ69G5CA4"; // ONE restore, TWO legs, TWO DIFFERENT foreign accounts
const NS = "ns_cax";
const ORIGIN = "acct-origin"; // the account the archives were captured from (their signed rec.account)
const OTHER = "acct-different"; // a different account a cross-account restore targets
const OTHER2 = "acct-different-2"; // a THIRD, distinct account -- so a two-leg restore can target two DIFFERENT foreign accounts

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

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

// MockKV / MockR2 mirror validate-restore.ts: the smallest KVNamespace / R2 surfaces restore touches.
class MockKV {
  store = new Map<string, Uint8Array>();
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> { this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v)); }
  async get(k: string): Promise<ArrayBuffer | null> { const v = this.store.get(k); return v ? toAB(v) : null; }
}
class MockR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> { const v = this.store.get(key); return v ? { etag: `"${key.length}"` } : null; }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> { this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body)); return { etag: `"${key.length}"` }; }
}

// makeCfDouble: an EMPTY live zone (so a snapshot record is a create), recording every send.
function makeCfDouble(): { api: CfApi; sent: Array<{ method: string; path: string }> } {
  const sent: Array<{ method: string; path: string }> = [];
  const api: CfApi = { get: async () => [], getPage: async (): Promise<CfPage> => ({ result: [] }), send: async (method, path) => { sent.push({ method, path }); return {}; } };
  return { api, sent };
}

// makeUploaderDouble: images keep their id, a video is remapped to a new uid; records every upload.
function makeUploaderDouble(): { uploader: MediaUploader; uploads: Array<{ id: string; bytes: string }> } {
  const uploads: Array<{ id: string; bytes: string }> = [];
  const uploader: MediaUploader = {
    // readbackReadable mirrors the real uploader: this double always READS the live blob back, so the
    // image path is readable; the stream path is always readable, there being no byte readback to fail.
    uploadImage: async (_acct, id, bytes) => { uploads.push({ id, bytes: new TextDecoder().decode(bytes) }); return { restoredId: id, remapped: false, verifiedSha384: hexEncode(await sha384(bytes)), verified: true, via: "media-image-readback", readbackReadable: true }; },
    uploadStreamVideo: async (_acct, originalUid, bytes) => { uploads.push({ id: originalUid, bytes: new TextDecoder().decode(bytes) }); return { restoredId: `new-${originalUid}`, remapped: true, verifiedSha384: null, verified: true, via: "media-stream-exists", readbackReadable: true }; },
  };
  return { uploader, uploads };
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);

  // seal builds a single-run archive into its own MockR2 (so the runs never share a RUNLOG).
  const seal = async (runId: string, downpipeId: string, records: WriteRecord[]): Promise<MockR2> => {
    const archive = await buildArchive({
      downpipeId, downpipeName: downpipeId, cadence: "3600s", runId,
      master: rand(32), recipients: [breakGlass.entry, op.entry], signer, records,
      windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z", createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
    const r2 = new MockR2();
    for (const [k, b] of archive) r2.store.set(k, b);
    return r2;
  };

  const dnsSnapshot = utf8(JSON.stringify([{ type: "A", name: "new.example.com", content: "3.3.3.3", proxied: false, ttl: 1 }]));
  // The cf-config run also carries a KV DATA record (no account: KV is bound by namespace, not an account API),
  // so a refused cross-account restore can be shown to write NOTHING, not even the data record.
  const cfgR2 = await seal(RUN_CFG, "dp_cax_cfg", [
    { sourceType: "kv", name: "k1", value: utf8("data-value"), namespace: NS },
    { sourceType: "cf-config", name: "dns", value: dnsSnapshot, account: ORIGIN },
  ]);
  const mediaR2 = await seal(RUN_MEDIA, "dp_cax_media", [
    { sourceType: "images", name: "img1/blob", value: utf8("PNG-BYTES-img1"), account: ORIGIN },
    { sourceType: "stream", name: "vid1/video.mp4", value: utf8("MP4-BYTES-vid1"), account: ORIGIN },
  ]);
  // An archive whose cf-config record recorded NO origin account (the defensive fail-closed branch): the target
  // cannot be verified as the origin, so even a plausible-looking target must be confirmed.
  const noOrigR2 = await seal(RUN_NOORIG, "dp_cax_noorig", [
    { sourceType: "cf-config", name: "dns", value: dnsSnapshot },
  ]);
  // ONE restore whose cf-config leg AND media leg target TWO DIFFERENT foreign accounts. Each leg's
  // confirmation must be checked against THAT leg's own target, independently, so confirming the cf-config
  // leg alone must not unlock the media leg's write into a DIFFERENT account nobody echoed.
  const twoForeignR2 = await seal(RUN_TWOFOREIGN, "dp_cax_twoforeign", [
    { sourceType: "cf-config", name: "dns", value: dnsSnapshot, account: ORIGIN },
    { sourceType: "images", name: "img1/blob", value: utf8("PNG-BYTES-img1"), account: ORIGIN },
  ]);

  const envFor = (r2: MockR2, kv: MockKV): Env => ({
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: r2 as unknown as R2Bucket,
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
    [`KV_${NS}`]: kv as unknown as KVNamespace,
  } as unknown as Env);

  const cfCtx = (accountId: string, confirmDifferentAccountId?: string) => ({ token: "edit-token", accountId, ...(confirmDifferentAccountId !== undefined ? { confirmDifferentAccountId } : {}) });
  const mediaCtx = (accountId: string, confirmDifferentAccountId?: string) => ({ token: "edit-token", accountId, ...(confirmDifferentAccountId !== undefined ? { confirmDifferentAccountId } : {}) });

  // ---------------- cf-config leg ----------------
  console.log("-- cf-config leg --");
  {
    // SAME-account dry-run: no cross-account warning; the diff previews as normal.
    const cf = makeCfDouble();
    const dry = (await runRestore(envFor(cfgR2, new MockKV()), { runId: RUN_CFG, cfConfig: cfCtx(ORIGIN) }, null, { cfApiFactory: () => cf.api })) as RestorePlan;
    ok("same-account dry-run has NO crossAccountWarnings", dry.crossAccountWarnings === undefined);
    ok("same-account dry-run still previews the surface diff", (dry.configChanges ?? []).some((c) => c.surface === "dns"));
  }
  {
    // SAME-account apply: writes the KV data record AND re-applies the cf-config surface (unchanged behaviour).
    const cf = makeCfDouble();
    const kv = new MockKV();
    const res = (await runRestore(envFor(cfgR2, kv), { runId: RUN_CFG, confirm: true, cfConfig: cfCtx(ORIGIN) }, null, { cfApiFactory: () => cf.api })) as RestoreResult;
    ok("same-account apply succeeds", res.ok === true && res.mode === "applied");
    ok("same-account apply wrote the cf-config surface (one create POST)", cf.sent.length === 1 && cf.sent[0]!.method === "POST");
    ok("same-account apply wrote the KV data record", kv.store.has("k1"));
  }
  {
    // CROSS-account dry-run: the warning names the leg, the signed origin and the target.
    const cf = makeCfDouble();
    const dry = (await runRestore(envFor(cfgR2, new MockKV()), { runId: RUN_CFG, cfConfig: cfCtx(OTHER) }, null, { cfApiFactory: () => cf.api })) as RestorePlan;
    const w = (dry.crossAccountWarnings ?? [])[0];
    ok("cross-account dry-run surfaces a crossAccountWarning (leg + origin + target)", w !== undefined && w.leg === "cf-config" && w.originAccount === ORIGIN && w.targetAccount === OTHER);
    ok("cross-account dry-run writes NOTHING", cf.sent.length === 0);
  }
  {
    // CROSS-account apply, UNCONFIRMED: refused before any write; not even the KV data record lands.
    const cf = makeCfDouble();
    const kv = new MockKV();
    const res = (await runRestore(envFor(cfgR2, kv), { runId: RUN_CFG, confirm: true, cfConfig: cfCtx(OTHER) }, null, { cfApiFactory: () => cf.api })) as RestoreResult;
    ok("unconfirmed cross-account apply is REFUSED (ok:false, nothing restored)", res.ok === false && res.recordsRestored === 0);
    ok("the refusal reason names both accounts and the confirm field", typeof res.reason === "string" && res.reason.includes(ORIGIN) && res.reason.includes(OTHER) && res.reason.includes("cfConfig.confirmDifferentAccountId"));
    ok("the refused apply wrote NOTHING to Cloudflare", cf.sent.length === 0);
    ok("the refused apply wrote NOTHING to KV either (whole restore refused before any write)", kv.store.size === 0);
  }
  {
    // CROSS-account apply, WRONG confirmation (echoes the ORIGIN, not the target): still refused.
    const cf = makeCfDouble();
    const kv = new MockKV();
    const res = (await runRestore(envFor(cfgR2, kv), { runId: RUN_CFG, confirm: true, cfConfig: cfCtx(OTHER, ORIGIN) }, null, { cfApiFactory: () => cf.api })) as RestoreResult;
    ok("a WRONG confirmation (not the target account) does NOT satisfy the guard", res.ok === false && res.recordsRestored === 0 && cf.sent.length === 0 && kv.store.size === 0);
  }
  {
    // CROSS-account apply, CONFIRMED (echoes the target): proceeds and writes to the different account.
    const cf = makeCfDouble();
    const kv = new MockKV();
    const res = (await runRestore(envFor(cfgR2, kv), { runId: RUN_CFG, confirm: true, cfConfig: cfCtx(OTHER, OTHER) }, null, { cfApiFactory: () => cf.api })) as RestoreResult;
    ok("an explicitly-confirmed cross-account apply PROCEEDS", res.ok === true && (res.configApplied ?? []).some((c) => c.surface === "dns" && c.applied === 1));
    ok("the confirmed cross-account apply wrote the cf-config surface", cf.sent.length === 1 && cf.sent[0]!.method === "POST");
    ok("the confirmed cross-account apply wrote the KV data record", kv.store.has("k1"));
  }

  // ---------------- media leg ----------------
  console.log("-- media leg --");
  {
    // SAME-account apply: both media files re-upload (unchanged behaviour).
    const up = makeUploaderDouble();
    const res = (await runRestore(envFor(mediaR2, new MockKV()), { runId: RUN_MEDIA, confirm: true, mediaRestore: mediaCtx(ORIGIN) }, null, { mediaUploaderFactory: () => up.uploader })) as RestoreResult;
    ok("same-account media apply succeeds and uploads both files", res.ok === true && up.uploads.length === 2);
  }
  {
    // CROSS-account dry-run: the media warning names the leg + origin + target.
    const up = makeUploaderDouble();
    const dry = (await runRestore(envFor(mediaR2, new MockKV()), { runId: RUN_MEDIA, mediaRestore: mediaCtx(OTHER) }, null, { mediaUploaderFactory: () => up.uploader })) as RestorePlan;
    const w = (dry.crossAccountWarnings ?? [])[0];
    ok("cross-account media dry-run surfaces the warning", w !== undefined && w.leg === "media" && w.originAccount === ORIGIN && w.targetAccount === OTHER);
    ok("cross-account media dry-run uploads NOTHING", up.uploads.length === 0);
  }
  {
    // CROSS-account apply, UNCONFIRMED: refused, nothing uploaded.
    const up = makeUploaderDouble();
    const res = (await runRestore(envFor(mediaR2, new MockKV()), { runId: RUN_MEDIA, confirm: true, mediaRestore: mediaCtx(OTHER) }, null, { mediaUploaderFactory: () => up.uploader })) as RestoreResult;
    ok("unconfirmed cross-account media apply is REFUSED", res.ok === false && res.recordsRestored === 0);
    ok("the media refusal names the media confirm field", typeof res.reason === "string" && res.reason.includes("mediaRestore.confirmDifferentAccountId") && res.reason.includes(OTHER));
    ok("the refused media apply uploaded NOTHING", up.uploads.length === 0);
  }
  {
    // CROSS-account apply, CONFIRMED: proceeds and uploads to the different account.
    const up = makeUploaderDouble();
    const res = (await runRestore(envFor(mediaR2, new MockKV()), { runId: RUN_MEDIA, confirm: true, mediaRestore: mediaCtx(OTHER, OTHER) }, null, { mediaUploaderFactory: () => up.uploader })) as RestoreResult;
    ok("an explicitly-confirmed cross-account media apply PROCEEDS and uploads both files", res.ok === true && up.uploads.length === 2);
  }

  // ---------------- unverifiable origin (fail-closed) ----------------
  console.log("-- unverifiable origin (an archive that recorded no origin account) --");
  {
    // The archive recorded NO origin account, so even the plausible target ORIGIN cannot be verified: the
    // dry-run warns (origin null) and an unconfirmed apply is refused. This is the defensive fail-closed branch.
    const cfDry = makeCfDouble();
    const dry = (await runRestore(envFor(noOrigR2, new MockKV()), { runId: RUN_NOORIG, cfConfig: cfCtx(ORIGIN) }, null, { cfApiFactory: () => cfDry.api })) as RestorePlan;
    const w = (dry.crossAccountWarnings ?? [])[0];
    ok("an unrecorded origin warns with originAccount:null", w !== undefined && w.leg === "cf-config" && w.originAccount === null && w.targetAccount === ORIGIN);

    const cf = makeCfDouble();
    const refused = (await runRestore(envFor(noOrigR2, new MockKV()), { runId: RUN_NOORIG, confirm: true, cfConfig: cfCtx(ORIGIN) }, null, { cfApiFactory: () => cf.api })) as RestoreResult;
    ok("an unverifiable-origin apply fails CLOSED (refused unless confirmed)", refused.ok === false && cf.sent.length === 0);

    const cf2 = makeCfDouble();
    const proceeded = (await runRestore(envFor(noOrigR2, new MockKV()), { runId: RUN_NOORIG, confirm: true, cfConfig: cfCtx(ORIGIN, ORIGIN) }, null, { cfApiFactory: () => cf2.api })) as RestoreResult;
    ok("an explicitly-confirmed unverifiable-origin apply PROCEEDS", proceeded.ok === true && cf2.sent.length === 1);
  }

  // ---------------- ONE restore, TWO legs, TWO DIFFERENT foreign accounts ----------------
  //
  // This section proves the engine is an independent authority rather than merely trusting whatever
  // confirmDifferentAccountId the caller sends. Both legs' targetAccount differ from the archive's
  // ORIGIN and from EACH OTHER (cf-config -> OTHER, media -> OTHER2).
  console.log("\n-- two DIFFERENT foreign accounts in one restore --");
  {
    // Dry-run: the plan carries BOTH warnings, naming both distinct targets.
    const cfDry = makeCfDouble();
    const upDry = makeUploaderDouble();
    const dry = (await runRestore(
      envFor(twoForeignR2, new MockKV()),
      { runId: RUN_TWOFOREIGN, cfConfig: cfCtx(OTHER), mediaRestore: mediaCtx(OTHER2) },
      null,
      { cfApiFactory: () => cfDry.api, mediaUploaderFactory: () => upDry.uploader },
    )) as RestorePlan;
    const warnings = dry.crossAccountWarnings ?? [];
    ok("the dry-run carries TWO warnings, one per leg", warnings.length === 2);
    ok("the cf-config warning names its own target", warnings.some((w) => w.leg === "cf-config" && w.targetAccount === OTHER));
    ok("the media warning names its OWN, DIFFERENT target", warnings.some((w) => w.leg === "media" && w.targetAccount === OTHER2));
  }
  {
    // Apply, NEITHER leg confirmed: refused before any write, naming both accounts.
    const cf = makeCfDouble();
    const up = makeUploaderDouble();
    const kv = new MockKV();
    const res = (await runRestore(
      envFor(twoForeignR2, kv),
      { runId: RUN_TWOFOREIGN, confirm: true, cfConfig: cfCtx(OTHER), mediaRestore: mediaCtx(OTHER2) },
      null,
      { cfApiFactory: () => cf.api, mediaUploaderFactory: () => up.uploader },
    )) as RestoreResult;
    ok("neither leg confirmed: the WHOLE restore is refused, nothing written", res.ok === false && cf.sent.length === 0 && up.uploads.length === 0);
    ok("the refusal names BOTH unconfirmed accounts", typeof res.reason === "string" && res.reason.includes(OTHER) && res.reason.includes(OTHER2));
  }
  {
    // Only the FIRST leg (cf-config) confirmed, the second (media, a DIFFERENT foreign account) left
    // unconfirmed. If the engine trusted the request's OWN echo without checking it against THAT leg's own
    // target, this would proceed. It must not.
    const cf = makeCfDouble();
    const up = makeUploaderDouble();
    const kv = new MockKV();
    const res = (await runRestore(
      envFor(twoForeignR2, kv),
      { runId: RUN_TWOFOREIGN, confirm: true, cfConfig: cfCtx(OTHER, OTHER), mediaRestore: mediaCtx(OTHER2) },
      null,
      { cfApiFactory: () => cf.api, mediaUploaderFactory: () => up.uploader },
    )) as RestoreResult;
    ok(
      "confirming ONLY the first (cf-config) leg still refuses the WHOLE restore -- the media leg's DIFFERENT foreign account is not silently allowed through",
      res.ok === false && cf.sent.length === 0 && up.uploads.length === 0,
    );
    ok("the refusal names the STILL-unconfirmed media account", typeof res.reason === "string" && res.reason.includes("mediaRestore.confirmDifferentAccountId") && res.reason.includes(OTHER2));
  }
  {
    // A WRONG cross-echo: the cf-config leg's confirmDifferentAccountId is set to the MEDIA leg's target
    // (OTHER2) rather than its own (OTHER). Proves the check is bound to EACH leg's own target, not
    // satisfied by any confirmed-looking value floating in the request.
    const cf = makeCfDouble();
    const up = makeUploaderDouble();
    const res = (await runRestore(
      envFor(twoForeignR2, new MockKV()),
      { runId: RUN_TWOFOREIGN, confirm: true, cfConfig: cfCtx(OTHER, OTHER2), mediaRestore: mediaCtx(OTHER2, OTHER2) },
      null,
      { cfApiFactory: () => cf.api, mediaUploaderFactory: () => up.uploader },
    )) as RestoreResult;
    ok("a cross-leg echo (confirming cf-config with the MEDIA leg's target) does not satisfy the cf-config guard", res.ok === false && cf.sent.length === 0 && up.uploads.length === 0);
  }
  {
    // BOTH legs explicitly and correctly confirmed: proceeds, writing to BOTH distinct foreign accounts.
    const cf = makeCfDouble();
    const up = makeUploaderDouble();
    const kv = new MockKV();
    const res = (await runRestore(
      envFor(twoForeignR2, kv),
      { runId: RUN_TWOFOREIGN, confirm: true, cfConfig: cfCtx(OTHER, OTHER), mediaRestore: mediaCtx(OTHER2, OTHER2) },
      null,
      { cfApiFactory: () => cf.api, mediaUploaderFactory: () => up.uploader },
    )) as RestoreResult;
    ok("both legs explicitly confirmed to their OWN targets: the restore PROCEEDS", res.ok === true);
    ok("the cf-config leg wrote to its confirmed foreign account", cf.sent.length === 1 && cf.sent[0]!.method === "POST");
    ok("the media leg wrote to ITS OWN confirmed (different) foreign account", up.uploads.length === 1);
  }

  // ---- the ZONE guard, unit-level ----------------------------------------------------------------
  //
  // The account guard above covers a wrong ACCOUNT. This covers the mistake that is easier to make: the
  // right account and the wrong ZONE. A customer with several zones picks the wrong one, the account
  // matches, nothing gates, and every zone-scoped surface lands in the wrong zone. Additively, so it does
  // not delete the target zone's records; it pollutes the zone with another zone's configuration.
  {
    const { crossZoneWarning, crossZoneConfirmed, originZoneFrom } = await import("../src/admin/restore-cross-account.ts");
    const zoneSurface = { rec: { name: "dns" }, surface: { scope: "zone" } };
    const acctSurface = { rec: { name: "account-members" }, surface: { scope: "account" } };
    const req = (zoneId?: string, confirm?: string) =>
      ({ cfConfig: { token: "t", accountId: "acct", ...(zoneId ? { zoneId } : {}), ...(confirm ? { confirmDifferentZoneId: confirm } : {}) } }) as never;

    console.log("\n-- cf-config cross-ZONE guard --");
    const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));

    ok("originZoneFrom reads the zoneId out of an identity record", originZoneFrom(enc({ v: 1, accountId: "acct", zoneId: "zoneA" })) === "zoneA");
    ok("originZoneFrom returns null for an account-only archive (no zoneId)", originZoneFrom(enc({ v: 1, accountId: "acct" })) === null);
    ok("originZoneFrom returns null on unparseable bytes rather than throwing", originZoneFrom(new TextEncoder().encode("not json")) === null);
    ok("originZoneFrom returns null when there is no identity record at all", originZoneFrom(null) === null);

    ok("SAME zone does not warn", crossZoneWarning(req("zoneA"), "zoneA", [zoneSurface]) === null);
    const w = crossZoneWarning(req("zoneB"), "zoneA", [zoneSurface]);
    ok("a DIFFERENT zone warns", w !== null && w.originZone === "zoneA" && w.targetZone === "zoneB");
    ok("the warning NAMES the zone-scoped surfaces, not just a count", w !== null && w.zoneSurfaces.join(",") === "dns");

    // The unverifiable case must warn, not pass. An archive whose origin cannot be read is exactly the case
    // the guard exists for, so treating null as "fine" would invert it.
    // An unverifiable origin WARNS but does not refuse. The apply gates on originZone !== null, because a
  // null origin usually means the identity record is outside this restore's window (it is emitted first in
  // every crawl, so a windowed restore routinely omits it) rather than that the zones differ. Refusing
  // those would break ordinary same-zone restores to guard against a mismatch there is no evidence of.
  const unverifiable = crossZoneWarning(req("zoneB"), null, [zoneSurface]);
  ok("an UNVERIFIABLE origin still WARNS, so the operator sees the zone could not be checked", unverifiable !== null);
  ok("an unverifiable origin is distinguishable from a proven mismatch, which is what the apply gates on", unverifiable !== null && unverifiable.originZone === null && w !== null && w.originZone === "zoneA");

    // Account-scoped surfaces ignore zoneId entirely, so warning about them would train the operator to
    // click past the warning that matters.
    ok("an account-scoped surface alone does NOT warn even across zones", crossZoneWarning(req("zoneB"), "zoneA", [acctSurface]) === null);
    ok("no cf-config zone in the request does not warn", crossZoneWarning(req(), "zoneA", [zoneSurface]) === null);
    ok("an empty config plan does not warn", crossZoneWarning(req("zoneB"), "zoneA", []) === null);

    // Type-to-confirm: a bare boolean or the WRONG zone must not clear it.
    ok("confirmation requires the EXACT target zone", w !== null && crossZoneConfirmed(w, req("zoneB", "zoneB")));
    ok("echoing the ORIGIN zone does not confirm", w !== null && !crossZoneConfirmed(w, req("zoneB", "zoneA")));
    ok("no confirmation does not confirm", w !== null && !crossZoneConfirmed(w, req("zoneB")));
  }

  console.log(failures === 0 ? "\nAll cross-account guard journeys passed." : `\n${failures} cross-account guard assertion(s) FAILED.`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
