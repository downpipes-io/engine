// A record name reaches the support pack only as a keyed name MAC, never as a plain hash.
//
// Two pack fields identify a customer record without its name:
//   - integrityFaults.<downpipe>.locators[].digest, for a record the writer sealed as zero bytes
//     (format/writer.ts sealBufferedRecord);
//   - runs.<downpipe>[].incompleteIds, the per-kind handles of the records a run sealed as markers
//     (seal/marker.ts safeMarkerAttribution, from seal/slice.ts and seal/pipeline.ts).
// A plain SHA-384 of a short or guessable name ("user:1") is reversed by hashing candidates. Both fields now
// carry the record's keyed name MAC (SPEC 6.4, crypto/derive.ts nameMAC): the locator carries all 96 hex, a
// marker handle carries "k:" and the first 12. The MAC key derives from the run master, which is never in the
// pack, and the value is the keyNameHash on the record's own manifest line, so the customer can match it.
//
// Each field's path is driven for real with a short sentinel name: the writer and the sliced and buffered seal
// paths, the real SchedulerDO, and the pack in every form it leaves the engine in (body, signed pack, band
// manifests, sealed envelope, opened inner, unsealed body). Neither the name nor its unkeyed hash may appear in
// any form, and the keyed value must recompute from the run key and match the customer's opened manifest. A
// ring an earlier engine wrote, holding unkeyed hashes, must lose them at the pack boundary.
//
// The negative control proves the scan can see: a legacy row that plants the name and its unkeyed hash in a
// field the pack still carries is FOUND by the same scan in every plaintext form.
//
// No network, no real Cloudflare. Run: node test/validate-keyed-pack-digests.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type WriteRecord } from "../src/format/writer.ts";
import { decodeULID } from "../src/format/ulid.ts";
import { deriveMK, deriveNameMACKey, nameMAC } from "../src/crypto/derive.ts";
import { b64urlEncode, concat, hexEncode, utf8 } from "../src/crypto/bytes.ts";
import { sha384 } from "../src/crypto/primitives.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { beginIntegrityFaults, reportIntegrityFaults } from "../src/admin/integrity-fault-report.ts";
import { INTEGRITY_FAULTS_KEY } from "../src/admin/diag-records.ts";
import { buildSupportBundle, sealedSupportBundle } from "../src/admin/support.ts";
import { runSlice, finaliseRun, type SliceDeps } from "../src/seal/slice.ts";
import { wrapMaster, unwrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { runBackup, type RunClock, type RunConfig } from "../src/seal/pipeline.ts";
import type { Meter, Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import type { MarkerKey } from "../src/seal/marker.ts";
import type { Env } from "../src/env.d.ts";
import type { RunHistoryEntry } from "../src/sched/types.ts";
import { makeSupportRecipient } from "../tools/generate-support-keypair.ts";
import { openSupportBundle } from "../tools/open-support-bundle.ts";
import { MemoryDestination } from "./memdest.ts";
import { makeScheduler } from "./validate-scheduler-shared.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

// The planted short names, one per path, and the name only an earlier engine's ring holds.
const LOCATOR_NAME = "user:1"; // a KV key the writer seals as zero bytes
const SLICED_NAME = "user:2"; // a KV key the sliced seal records as a marker
const BUFFERED_NAME = "user:3"; // a KV key the buffered seal records as a marker, in two namespaces
const BUFFERED_OTHER = "user:4"; // a second marker key in the buffered run
const LEGACY_NAME = "user:9"; // hashed without a key by an earlier engine
const NAMES = [LOCATOR_NAME, SLICED_NAME, BUFFERED_NAME, BUFFERED_OTHER, LEGACY_NAME];

const DP_EMPTY = "dp_u1b_empty";
const DP_SLICED = "dp_u1b_sliced";
const DP_BUFFERED = "dp_u1b_buffered";
const DP_LEGACY = "dp_u1b_legacy";

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
const sha384Hex = async (s: string): Promise<string> => hexEncode(await sha384(utf8(s)));
const runNameKey = async (master: Uint8Array, runId: string): Promise<Uint8Array> => {
  const runIdBytes = decodeULID(runId);
  return deriveNameMACKey(await deriveMK(master, runIdBytes), runIdBytes);
};

class MapStore implements ObjectStore {
  private readonly map: Map<string, Uint8Array>;
  constructor(map: Map<string, Uint8Array>) {
    this.map = map;
  }
  async get(key: string): Promise<Uint8Array> {
    const v = this.map.get(key);
    if (v === undefined) throw new Error(`object not found: ${key}`);
    return v;
  }
}

// A KV source that yields the given records, each an adapter-asserted marker or a plain value.
class ListSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private readonly recs: SourceRecord[];
  constructor(recs: SourceRecord[]) {
    this.recs = recs;
  }
  async *crawl(_selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for (const r of this.recs) {
      meter?.spend(1);
      yield r;
    }
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: this.recs.length, bytes: -1 };
  }
}
const marker = (name: string, kind: MarkerKey, namespace: string): SourceRecord => ({ sourceType: "kv", name, value: utf8(JSON.stringify({ [kind]: "not captured" })), namespace, markerKind: kind });
const plain = (name: string, namespace: string): SourceRecord => ({ sourceType: "kv", name, value: utf8(`${name}-value`), namespace });

// The real SchedulerDO takes a Request; the engine's stubs call fetch(url, init), so adapt the call shape only.
function doStub(real: unknown): DurableObjectStub {
  const r = real as { fetch(req: Request): Promise<Response> };
  return { fetch: (input: RequestInfo | URL, init?: RequestInit) => r.fetch(input instanceof Request ? input : new Request(String(input), init)) } as unknown as DurableObjectStub;
}
async function post(stub: DurableObjectStub, path: string, body: unknown): Promise<Response> {
  return stub.fetch(`https://do${path}`, { method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
}

// The legacy ring an earlier engine wrote: a locator digest and a marker handle that are plain hashes.
async function seedLegacy(storage: { put(k: string, v: unknown): Promise<void>; get(k: string): Promise<unknown> }, legacy12: string): Promise<void> {
  const prior = ((await storage.get(INTEGRITY_FAULTS_KEY)) ?? {}) as Record<string, unknown>;
  prior[DP_LEGACY] = {
    fetchFaults: {}, failStages: {}, classifiedBy: {}, cryptoFaults: [], streamFaults: [], runlogAnomalies: [], writerRefusals: {},
    locators: [{ kind: "defaulted-empty-record", digest: legacy12 }],
    defaultedEmptyRecords: 1,
    at: 1,
  };
  await storage.put(INTEGRITY_FAULTS_KEY, prior);
  const row: RunHistoryEntry = { runId: "01ARZ3NDEKTSV4RRFFQ69G5V9Z", index: 1, startedAt: "2026-09-01T00:00:00.000Z", status: "ok", recordsIncomplete: 1, incompleteByMarker: { _vanished: 1 }, incompleteIds: { _vanished: [`h:${legacy12}`] } } as RunHistoryEntry;
  await storage.put(`hist:${DP_LEGACY}`, [row]);
}

interface PackForms {
  forms: Array<[string, unknown, boolean]>; // label, form, plaintext
  unsealedBody: Record<string, unknown>;
}

async function buildForms(env: Env, stub: DurableObjectStub, signer: Awaited<ReturnType<typeof loadSigner>>): Promise<PackForms> {
  const vendor = await makeSupportRecipient();
  const body = await buildSupportBundle({ ...env } as Env, stub);
  const signedPlain = await sealedSupportBundle({ ...env } as Env, stub);
  const sealed = await sealedSupportBundle({ ...env, VENDOR_SUPPORT_PUBLIC: b64urlEncode(vendor.recipientPublic) } as Env, stub);
  const opened = await openSupportBundle(sealed, parseIdentity(vendor.identity), verifierFrom(signer));
  const unsealedBody = (opened.inner as { bundle?: unknown }).bundle as Record<string, unknown>;
  ok("the signed pack and the sealed envelope both carry a band manifest", (signedPlain as { manifest?: unknown }).manifest !== undefined && (sealed as { manifest?: unknown }).manifest !== undefined);
  ok("the sealed envelope opens and its body is the signed pack", opened.form === "sealed" && opened.signature === "verified" && typeof unsealedBody === "object" && unsealedBody !== null);
  return {
    forms: [
      ["the pack body", body, true],
      ["the signed pack", signedPlain, true],
      ["the signed pack's band manifest", (signedPlain as { manifest?: unknown }).manifest, true],
      ["the sealed envelope", sealed, false],
      ["the sealed envelope's band manifest", (sealed as { manifest?: unknown }).manifest, true],
      ["the opened signed inner", opened.inner, true],
      ["the unsealed body", unsealedBody, true],
    ],
    unsealedBody,
  };
}

async function main(): Promise<void> {
  console.log("Support pack: a record name rides only as its keyed name MAC");

  const recipient = (role: string): { entry: RecipientEntry; identity: Uint8Array } => {
    const xk = x25519.keygen();
    const seed = rand(64);
    return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
  };
  const signerB64 = b64urlEncode(concat(rand(32), rand(32)));
  const signer = await loadSigner(signerB64);
  const verifier = verifierFrom(signer);
  const breakGlass = recipient("break-glass");
  const recipients = [breakGlass.entry];

  const sched = makeScheduler();
  const stub = doStub(sched.stub);
  const env = { DEST_KIND: "r2", DEST_R2: {} as unknown as R2Bucket, SIGNER_PRIVATE: signerB64 } as unknown as Env;

  // The two downpipes whose runs the DO allocates and completes.
  for (const id of [DP_SLICED, DP_BUFFERED]) {
    await sched.storage.put(`dp:${id}`, { config: { id, name: id, enabled: true, cadenceSeconds: 3600, source: { type: "kv", namespaceId: "ns_a" } }, nextRunAt: 0, lastRunId: null, inFlight: false });
  }
  const unkeyed = new Map<string, string>();
  for (const n of NAMES) unkeyed.set(n, await sha384Hex(n));
  await seedLegacy(sched.storage as never, unkeyed.get(LEGACY_NAME)!.slice(0, 12));

  // ---- (a) the zero-byte seal's locator digest -----------------------------------------------------------
  console.log("\n(a) integrityFaults locator: a record sealed as zero bytes");
  const emptyRun = "01ARZ3NDEKTSV4RRFFQ69G5V1B";
  const emptyMaster = rand(32);
  const emptyRecords: WriteRecord[] = [
    { sourceType: "kv", name: "alpha", value: utf8("alpha-value"), namespace: "ns_a" },
    { sourceType: "kv", name: LOCATOR_NAME, namespace: "ns_a" }, // neither a value nor a stream
  ];
  beginIntegrityFaults();
  const emptyArchive = await buildArchive({
    downpipeId: DP_EMPTY, downpipeName: "u1b-empty", cadence: "3600s", runId: emptyRun, master: emptyMaster, recipients, signer,
    records: emptyRecords,
    windowStart: "2026-09-28T00:00:00.000Z", windowEnd: "2026-09-28T00:00:01.000Z", createdAt: "2026-09-28T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  await reportIntegrityFaults(stub, DP_EMPTY);
  const emptyKey = await runNameKey(emptyMaster, emptyRun);
  const emptyMac = hexEncode(await nameMAC(emptyKey, "kv", LOCATOR_NAME));
  const emptyOpened = await openRun(new MapStore(emptyArchive), emptyRun, parseIdentity(breakGlass.identity), verifier, {});
  const emptyManifestHash = emptyOpened.records.find((r) => r.name === LOCATOR_NAME)?.keyNameHash;
  emptyOpened.dispose();

  // ---- (b) the sliced seal's marker handle ---------------------------------------------------------------
  console.log("(b) runs[].incompleteIds: a marker on the sliced path");
  const slicedTrig = (await (await post(stub, "/trigger", { id: DP_SLICED })).json()) as { runId: string; index: number };
  const slicedRun = slicedTrig.runId;
  const slicedMaster = rand(32);
  const slicedDest = new MemoryDestination();
  let cp: RunCheckpoint = {
    v: 1, downpipeId: DP_SLICED, downpipeName: "u1b-sliced", cadence: "3600s", sourceType: "kv",
    selector: { include: [], exclude: [] }, runId: slicedRun, runlogIndex: slicedTrig.index, prevRunId: null,
    startedAt: "2026-09-28T00:00:00.000Z", wrappedMaster: await wrapMaster(signerB64, slicedRun, slicedMaster),
    cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
    frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
  };
  const slicedSource = new ListSource([plain("beta", "ns_a"), marker(SLICED_NAME, "_vanished", "ns_a")]);
  const slicedDeps = (): SliceDeps => ({ source: slicedSource, dest: slicedDest, signer, recipients, budget: new SliceBudget({ subrequests: 200, wallMs: 60_000 }) });
  const sr = await runSlice(slicedDeps(), cp, slicedMaster);
  cp = sr.checkpoint;
  {
    const m = await unwrapMaster(signerB64, slicedRun, cp.wrappedMaster);
    await finaliseRun(slicedDeps(), cp, m, sr.newShards, sr.openWrite);
    m.fill(0);
  }
  await post(stub, "/complete", {
    id: DP_SLICED, runId: slicedRun, index: slicedTrig.index, status: "ok", recordCount: cp.counts.records, bytes: cp.counts.bytes,
    recordsIncomplete: cp.counts.recordsIncomplete, incompleteByMarker: cp.counts.incompleteByMarker, incompleteIds: cp.counts.incompleteIds,
  });
  const slicedKey = await runNameKey(slicedMaster, slicedRun);
  const slicedMac = hexEncode(await nameMAC(slicedKey, "kv", SLICED_NAME));
  const slicedOpened = await openRun(new MapStore(slicedDest.entries()), slicedRun, parseIdentity(breakGlass.identity), verifier, {});
  const slicedManifestHash = slicedOpened.records.find((r) => r.name === SLICED_NAME)?.keyNameHash;

  // ---- (b) the buffered seal's marker handles ------------------------------------------------------------
  console.log("(b) runs[].incompleteIds: markers on the buffered path, one key in two namespaces");
  const bufTrig = (await (await post(stub, "/trigger", { id: DP_BUFFERED })).json()) as { runId: string; index: number };
  const bufRun = bufTrig.runId;
  const bufMaster = rand(32);
  const bufDest = new MemoryDestination();
  const bufSource = new ListSource([
    plain("gamma", "ns_a"),
    marker(BUFFERED_NAME, "_vanished", "ns_a"),
    marker(BUFFERED_OTHER, "_vanished", "ns_a"),
    marker(BUFFERED_NAME, "_unavailable", "ns_b"),
  ]);
  const cfg: RunConfig = { downpipeId: DP_BUFFERED, downpipeName: "u1b-buffered", cadence: "3600s", selector: { include: [], exclude: [] }, recipients };
  const summary = await runBackup([bufSource], cfg, signer, bufDest, {
    runId: bufRun, runlogIndex: bufTrig.index, prevRunId: null, now: "2026-09-28T00:00:02.000Z",
    master: bufMaster, randomNonce: () => rand(16), randomSalt: () => rand(16),
  } as RunClock);
  await post(stub, "/complete", {
    id: DP_BUFFERED, runId: bufRun, index: bufTrig.index, status: "ok", recordCount: summary.records, bytes: summary.bytes,
    recordsIncomplete: summary.recordsIncomplete, incompleteByMarker: summary.incompleteByMarker, incompleteIds: summary.incompleteIds,
  });
  const bufKey = await runNameKey(bufMaster, bufRun);
  const bufMac = hexEncode(await nameMAC(bufKey, "kv", BUFFERED_NAME));
  const bufOtherMac = hexEncode(await nameMAC(bufKey, "kv", BUFFERED_OTHER));
  const bufOpened = await openRun(new MapStore(bufDest.entries()), bufRun, parseIdentity(breakGlass.identity), verifier, {});
  const bufManifestHashes = bufOpened.records.filter((r) => r.name === BUFFERED_NAME).map((r) => r.keyNameHash);

  // ---- every form of the pack --------------------------------------------------------------------------
  console.log("\nthe pack in every form carries neither a planted name nor its unkeyed hash");
  const { forms, unsealedBody } = await buildForms(env, stub, signer);
  for (const [label, form] of forms) {
    const json = JSON.stringify(form ?? null);
    const names = NAMES.filter((n) => json.includes(n));
    const hashes = NAMES.filter((n) => json.includes(unkeyed.get(n)!.slice(0, 12)));
    ok(`${label}: no planted name${names.length > 0 ? ` (found ${names.join(", ")})` : ""}`, names.length === 0);
    ok(`${label}: no unkeyed SHA-384 digest of a planted name${hashes.length > 0 ? ` (found for ${hashes.join(", ")})` : ""}`, hashes.length === 0);
  }

  console.log("\n(a) the locator carries the record's keyed name MAC");
  const faults = (unsealedBody.integrityFaults ?? {}) as Record<string, { locators?: Array<Record<string, unknown>>; defaultedEmptyRecords?: number }>;
  const loc = faults[DP_EMPTY]?.locators?.find((l) => l.kind === "defaulted-empty-record");
  ok("the zero-byte seal is counted", faults[DP_EMPTY]?.defaultedEmptyRecords === 1);
  ok("its locator digest is the keyed name MAC recomputed from the run key", loc?.digest === emptyMac);
  ok("the customer matches it: it equals the keyNameHash on the record's opened manifest line", typeof emptyManifestHash === "string" && loc?.digest === emptyManifestHash);
  ok("the legacy ring's unkeyed locator digest is dropped at the pack boundary", (faults[DP_LEGACY]?.locators ?? []).every((l) => l.digest === undefined));

  console.log("\n(b) the marker handles carry the record's keyed name MAC");
  const runs = (unsealedBody.runs ?? {}) as Record<string, Array<{ incompleteIds?: Record<string, string[]> }>>;
  const slicedIds = runs[DP_SLICED]?.[0]?.incompleteIds;
  ok("sliced path: the marker is attributed by the first 12 hex of its keyed name MAC", JSON.stringify(slicedIds) === JSON.stringify({ _vanished: [`k:${slicedMac.slice(0, 12)}`] }));
  ok("sliced path: the customer matches it against the record's opened manifest line", typeof slicedManifestHash === "string" && slicedIds?._vanished?.[0] === `k:${slicedManifestHash.slice(0, 12)}`);
  const bufIds = runs[DP_BUFFERED]?.[0]?.incompleteIds;
  ok("buffered path: two marker keys give two distinct handles, so support can COUNT them", JSON.stringify(bufIds?._vanished) === JSON.stringify([`k:${bufMac.slice(0, 12)}`, `k:${bufOtherMac.slice(0, 12)}`]));
  ok("buffered path: one key under two kinds gives one handle, so support can COMPARE them", bufIds?._unavailable?.[0] === bufIds?._vanished?.[0]);
  ok("buffered path: the customer matches it against both opened manifest lines", bufManifestHashes.length === 2 && bufManifestHashes.every((h) => bufIds?._vanished?.[0] === `k:${h.slice(0, 12)}`));
  const legacyRow = runs[DP_LEGACY]?.[0];
  ok("the legacy run row still rides, without its unkeyed handle", legacyRow !== undefined && legacyRow.incompleteIds === undefined);

  // ---- negative control --------------------------------------------------------------------------------
  // The same scan over a pack whose ring plants a name and its unkeyed hash in fields the pack still carries
  // (a downpipe id and a RUNLOG digest) must FIND both in every plaintext form, or the absences above prove
  // nothing. The sealed envelope is ciphertext; its content is scanned through the opened inner.
  console.log("\nnegative control: the scan finds a name and an unkeyed hash that do ride");
  const ctl = makeScheduler();
  const ctlStub = doStub(ctl.stub);
  const ctlHash = unkeyed.get(LEGACY_NAME)!.slice(0, 12);
  await ctl.storage.put(INTEGRITY_FAULTS_KEY, {
    [`ctl-${LEGACY_NAME}`]: {
      fetchFaults: {}, failStages: {}, classifiedBy: {}, locators: [], cryptoFaults: [], streamFaults: [], writerRefusals: {},
      runlogAnomalies: [{ kind: "index-regression", indexA: 2, indexB: 1, digest: ctlHash }],
      defaultedEmptyRecords: 0, at: 1,
    },
  });
  const ctlForms = await buildForms(env, ctlStub, signer);
  for (const [label, form, plaintext] of ctlForms.forms) {
    if (!plaintext || label.includes("band manifest")) continue;
    const json = JSON.stringify(form ?? null);
    ok(`control, ${label}: the scan finds the planted name`, json.includes(LEGACY_NAME));
    ok(`control, ${label}: the scan finds the planted unkeyed hash`, json.includes(ctlHash));
  }

  console.log(failures === 0 ? "\nAll keyed pack digest checks passed." : `\n${failures} check(s) FAILED.`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e);
  process.exit(1);
});
