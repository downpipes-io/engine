// A RESTORE MUST NOT REPORT A STATE THE RUN IS NOT IN.
//
// Four surfaces were claiming success over nothing. This file is the proof for all four, and every one
// carries a GREEN CONTROL that differs from the red case in exactly one field, so a pass here is a
// discrimination rather than a state.
//
//   A. buildSourceBindingMap's r2 branch REQUIRED bucketName, so restoring to where the data came from
//      planned 0 of 8. The kv branch two lines above already carried this exact fallback, under a comment
//      ending "a restore that completes and writes nothing", and the d1 branch one line below keys on the
//      binding. It was a lone hold-out between two siblings that both handle it.
//
//   B. The plan's ok/complete were computed from dryRunSkipped and outOfWindow only, so a plan that could
//      write NOTHING reported ok:true complete:true with every record in a `skipped` array neither field
//      read. The windowed case was already graded correctly, which is what made this a hole rather than a
//      design. The control that matters here is the OPPOSITE error: a deliberate one-record granular restore
//      must STILL be ok, because "every record is accounted for" and "every record is written" are different
//      claims and only one of them is what the operator asked for.
//
//   C. A RUN THAT HOLDS NO RECORDS. The product answers this in two opposite ways. format/writer.ts refuses
//      it outright -- "An empty run is never valid" -- and records the closed CUSTOMER-fault kind
//      source-enumerated-zero so support can say "your source produced nothing". That is the BUFFERED path.
//      The SLICED path is the default, never reaches that writer, and seals the same state ok. This file
//      seals a real zero-record archive through the sliced path and proves the buffered path refuses the
//      identical input, so the contradiction is asserted rather than described.
//
//   D. THE DRILL'S VERDICT OVER THAT ARCHIVE. restore-verify.ts:127 has always carried the clause
//      `recordsVerified > 0`; drill.ts carried no such clause and answered ok:true about the same run in the
//      same minute. The drill's verdict is the one that travels: it stamps lastRestoreTestOk, which
//      posture-checks reads as "restore tested recently", so the estate's evidence log read "scheduled
//      restore test passed (records verified: 0)". That is our own compliance artefact asserting a restore
//      test passed when nothing was verified, which is the artefact a customer shows an auditor.
//
// E. THE MANUAL POST /admin/restore/verify ROUTE OVER THE SAME ARCHIVE. restore-verify.ts:127's
//      `recordsVerified > 0` clause NEVER answered a false PASS the way drill.ts's missing clause did (ok was
//      always false here), but it also never carried the nothingToVerify+reason pair the empty-run drill
//      landed above: a caller received a bare {ok:false}, indistinguishable from a genuine per-record or
//      freshness failure. A fresh install's first seal against an as-yet-unseeded KV source verified 0
//      records and read as "verification failed" with zero diagnostic content. Section E below proves
//      runBlindRestoreTest returns the SAME {nothingToVerify:true, reason:NOTHING_TO_VERIFY_REASON} pair
//      drill.ts already returns for the identical archive, so both restorability-proof routes describe the
//      same state the same way.
//
// THE POPULATION IS ASSERTED, NOT ASSUMED. "The restore planned everything" is also true of a plan of
// nothing, which is literally defect B. Every red case here first proves the run HOLDS records, and the
// zero-record case proves the archive opened and verified before asking what the drill said about it.
//
// Run: node test/validate-restore-honesty.ts
// In-memory doubles only; no network, no estate, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { parseIdentity } from "../src/crypto/keys.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { NOTHING_TO_VERIFY_REASON, runDrill } from "../src/admin/drill.ts";
import { buildSourceBindingMap } from "../src/admin/router-restore.ts";
import { runRestore, runBlindRestoreTest } from "../src/admin/restore.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { openRun } from "../src/format/reader.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { wrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { finaliseRun, type ShardEntry, type SliceDeps } from "../src/seal/slice.ts";
import { KVSource } from "../src/sources/kv.ts";
import type { Destination, GetResult, PutConditionalResult } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import type { RestorePlan } from "../src/admin/restore-types.ts";

let failures = 0;
function ok(what: string, cond: boolean): void {
  console.log(cond ? `  ok   ${what}` : `  FAIL ${what}`);
  if (!cond) failures += 1;
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

// MemDest is the full Destination contract over a map, the same double the sliced-seal proof uses.
class MemDest implements Destination {
  map = new Map<string, Uint8Array>();
  private tags = new Map<string, string>();
  private seq = 0;
  async get(key: string): Promise<GetResult | null> {
    const v = this.map.get(key);
    return v ? { body: v, etag: this.tags.get(key) ?? "e0" } : null;
  }
  async put(key: string, body: Uint8Array): Promise<void> {
    this.map.set(key, body);
    this.tags.set(key, `e${++this.seq}`);
  }
  async putStream(key: string, body: ReadableStream<Uint8Array>): Promise<void> {
    const parts: Uint8Array[] = [];
    const reader = body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      parts.push(value);
    }
    await this.put(key, concat(...parts));
  }
  async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }): Promise<PutConditionalResult> {
    const cur = this.tags.get(key);
    if (opts.ifNoneMatch === "*" && cur !== undefined) return { ok: false };
    if (opts.ifMatch !== undefined && cur !== opts.ifMatch) return { ok: false };
    await this.put(key, body);
    return { ok: true, etag: this.tags.get(key)! };
  }
  async exists(key: string): Promise<boolean> {
    return this.map.has(key);
  }
  async delete(key: string): Promise<void> {
    this.map.delete(key);
    this.tags.delete(key);
  }
  async list(prefix: string): Promise<string[]> {
    return [...this.map.keys()].filter((k) => k.startsWith(prefix));
  }
}

// An R2Bucket-shaped view over a plain object map, so buildDestination(env) picks R2Destination and reads
// the archive these proofs sealed. Reads only; a drill must never write, and a restore here is a dry run.
function bucketOver(store: Map<string, Uint8Array>): R2Bucket {
  return {
    async get(key: string) {
      const v = store.get(key);
      if (!v) return null;
      return { arrayBuffer: async () => toAB(v), etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2ObjectBody;
    },
    async head(key: string) {
      const v = store.get(key);
      return v ? ({ etag: `${key.length}`, httpEtag: `"${key.length}"` } as unknown as R2Object) : null;
    },
    async put(key: string, body: ArrayBuffer | Uint8Array | ReadableStream) {
      if (body instanceof ReadableStream) throw new Error("unexpected stream write in a read-only proof");
      store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body as ArrayBuffer));
      return {} as unknown as R2Object;
    },
  } as unknown as R2Bucket;
}

// A KV double with no keys at all: the genuinely empty source the sliced path seals as a zero-record run.
class EmptyKV {
  async list(): Promise<{ keys: Array<{ name: string }>; list_complete: boolean; cursor?: string }> {
    return { keys: [], list_complete: true };
  }
  async get(): Promise<null> {
    return null;
  }
  async getWithMetadata(): Promise<{ value: null; metadata: null }> {
    return { value: null, metadata: null };
  }
}

const NS = "ns_emptyrun";
const DP_ID = "dp_emptyrun";

// ============================================================================================
// A. THE r2 BINDING FALLBACK
// ============================================================================================

// The DO's real response shape: GET /downpipes returns DownpipeState[] with the source on `config`.
// The kv-fallback proof learned this the hard way and says so in its own header: a fixture invented from
// the same assumption as the code proves only that they share it.
const stub = (sources: unknown[]): DurableObjectStub =>
  ({ fetch: async () => new Response(JSON.stringify(sources.map((source) => ({ schemaVersion: 1, config: { id: DP_ID, source } })))) }) as unknown as DurableObjectStub;

async function proofR2BindingFallback(): Promise<void> {
  console.log("\nA. RESTORING TO WHERE IT CAME FROM (the r2 branch's missing fallback)");

  // THE DEFECT. An r2 source attached WITHOUT a bucketName. seal/adapters.ts stamps such a record's bucket
  // as `bucketName ?? binding`, so the archive carries SRC_R2 and resolveSink asks for `r2:SRC_R2`.
  const noBucket = await buildSourceBindingMap(stub([{ type: "r2", binding: "SRC_R2" }]));
  ok("an r2 source with NO bucketName still yields a binding-keyed entry", noBucket.get("r2:SRC_R2") === "SRC_R2");
  ok("and that is the key resolveSink asks for, since capture stamps the binding as the record bucket", noBucket.has("r2:SRC_R2"));
  // POPULATION: an empty map would satisfy neither assertion above by accident, but assert it anyway, since
  // "nothing was mapped wrongly" is trivially true of a map with nothing in it.
  ok("POPULATION: the map is not empty for a real response", noBucket.size > 0);

  // The bucketName path is UNCHANGED, which is the whole point of a fallback over a re-keying.
  const withBucket = await buildSourceBindingMap(stub([{ type: "r2", binding: "SRC_R2", bucketName: "my-bucket" }]));
  ok("an r2 source WITH a bucketName still maps by its bucket", withBucket.get("r2:my-bucket") === "SRC_R2");
  ok("and also gains the binding key, so both spellings resolve", withBucket.get("r2:SRC_R2") === "SRC_R2");

  // The authoritative mapping wins a collision, exactly as the kv fallback does not overwrite a namespaceId.
  const collide = await buildSourceBindingMap(
    stub([
      { type: "r2", binding: "REAL", bucketName: "SHARED" },
      { type: "r2", binding: "SHARED" },
    ]),
  );
  ok("a bucketName mapping is NOT overwritten by another downpipe's binding fallback", collide.get("r2:SHARED") === "REAL");

  // THE GREEN CONTROL: the sibling branches are untouched. If this repair had been made by loosening the
  // whole map rather than by giving one branch what its siblings have, these would move.
  const others = await buildSourceBindingMap(
    stub([
      { type: "kv", binding: "SRC_KV", namespaceId: "ns1" },
      { type: "d1", binding: "SRC_D1" },
    ]),
  );
  ok("CONTROL: kv still keys on its namespace id", others.get("kv:ns1") === "SRC_KV");
  ok("CONTROL: kv still gains its own binding key", others.get("kv:SRC_KV") === "SRC_KV");
  ok("CONTROL: d1 still keys on the binding", others.get("d1:SRC_D1") === "SRC_D1");
  ok("CONTROL: no r2 entry is invented for a non-r2 source", [...others.keys()].every((k) => !k.startsWith("r2:")));

  // Presence-safe: a source with no usable binding is skipped, never mapped to undefined.
  const nameless = await buildSourceBindingMap(stub([{ type: "r2" }, { type: "r2", binding: "" }]));
  ok("an r2 source with no usable binding yields no entry", nameless.size === 0);
}

// ============================================================================================
// B. A PLAN THAT CAN WRITE NOTHING IS NOT COMPLETE
// ============================================================================================

async function proofPlanVerdict(signer: Signer, recipients: RecipientEntry[], operationalPrivateB64: string, signerPrivateB64: string): Promise<void> {
  console.log("\nB. THE PLAN THAT WOULD HAVE WRITTEN NOTHING");

  const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVR1";
  const store = new Map<string, Uint8Array>();
  const archive = await buildArchive({
    downpipeId: DP_ID,
    downpipeName: "emptyrun",
    cadence: "3600s",
    runId: RUN_ID,
    master: rand(32),
    recipients,
    signer,
    records: [
      { sourceType: "kv" as const, name: "a", namespace: NS, value: utf8("v1") },
      { sourceType: "kv" as const, name: "b", namespace: NS, value: utf8("v2") },
      { sourceType: "kv" as const, name: "c", namespace: NS, value: utf8("v3") },
    ],
    windowStart: "2026-08-13T00:00:00.000Z",
    windowEnd: "2026-08-13T00:00:01.000Z",
    createdAt: "2026-08-13T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  for (const [k, v] of archive) store.set(k, v);

  const env = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: bucketOver(store),
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;

  // THE DEFECT. The convention binding KV_<ns> is absent (the operator attached under a chosen name) and
  // sourceBindings is empty (buildSourceBindingMap's presence-safe empty-on-fault return). Every record is
  // refused at sink resolution, so the plan can write nothing at all.
  const plan = (await runRestore(env, { runId: RUN_ID }, null, { sourceBindings: new Map() })) as RestorePlan;

  // POPULATION FIRST. Everything below is vacuous over a run that holds nothing, and a plan of nothing is
  // exactly the state this whole file exists to stop a surface from calling complete.
  ok("POPULATION: the run under test HOLDS three records", plan.recordsVerified === 3 || plan.skipped.length === 3);
  ok("the plan can write nothing: plannedWrites is 0", plan.plannedWrites === 0);
  ok("all three records are named, with the honest reason", plan.skipped.length === 3 && plan.skipped.every((s) => s.reason === "target binding not present"));
  ok("a plan that can write NOTHING is NOT ok", plan.ok === false);
  ok("a plan that can write NOTHING is NOT complete", plan.complete === false);

  // THE GREEN CONTROL, and it is the important one, because the cheap repair fails it. A GRANULAR restore
  // narrows on purpose: two of three records are skipped as "not the selected record", and that plan is
  // CORRECT and must stay ok. Reading skipped.length rather than the refusal count would redden this, which
  // is the same false claim in the opposite direction.
  const envOk = { ...(env as unknown as Record<string, unknown>), [`KV_${NS}`]: {
    async get() { return null; },
    async put() { return undefined; },
    async getWithMetadata() { return { value: null, metadata: null }; },
  } } as unknown as Env;
  const granular = (await runRestore(envOk, { runId: RUN_ID, recordName: "a" }, null, { sourceBindings: new Map() })) as RestorePlan;
  ok("CONTROL: a deliberate one-of-three granular restore plans exactly 1", granular.plannedWrites === 1);
  ok("CONTROL: and it is STILL ok, because the operator's own narrowing is not a refusal", granular.ok === true);
  ok("CONTROL: and its two unselected records carry the narrowing reason, not a refusal", granular.skipped.filter((s) => s.reason === "not the selected record").length === 2);

  // The whole-run restore over the SAME archive with the binding present: 3 of 3, ok and complete. This is
  // the positive control for the red case above, differing in exactly one thing, the presence of a binding.
  const whole = (await runRestore(envOk, { runId: RUN_ID }, null, { sourceBindings: new Map() })) as RestorePlan;
  ok("CONTROL: the same run with the binding PRESENT plans all 3, ok and complete", whole.plannedWrites === 3 && whole.ok === true && whole.complete === true);
}

// ============================================================================================
// C + D. A RUN THAT HOLDS NO RECORDS, AND WHAT THE DRILL SAYS ABOUT IT
// ============================================================================================

async function proofZeroRecordRun(signer: Signer, recipients: RecipientEntry[], breakGlassIdentity: Uint8Array, operationalPrivateB64: string, signerPrivateB64: string, verifier: Awaited<ReturnType<typeof verifierFrom>>): Promise<void> {
  console.log("\nC. A RUN THAT SEALED NOTHING, ON THE PATH EVERY ESTATE ACTUALLY RUNS");

  const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVR2";
  const dest = new MemDest();
  const master = rand(32);
  const wrapped = await wrapMaster(signerPrivateB64, RUN_ID, master);

  // THE SLICED PATH, which pipeline.ts's own header calls the default. A checkpoint with nextShardIndex 0
  // and zeroed counts IS a run whose source enumerated nothing; finaliseRun seals it with one empty parity
  // shard. No buildArchive is involved anywhere on this path, which is the whole point of section C.
  const cp: RunCheckpoint = {
    v: 1,
    downpipeId: DP_ID,
    downpipeName: "emptyrun",
    cadence: "3600s",
    sourceType: "kv",
    selector: { include: [], exclude: [] },
    runId: RUN_ID,
    runlogIndex: 1,
    prevRunId: null,
    startedAt: "2026-08-13T00:00:00.000Z",
    wrappedMaster: wrapped,
    cursor: null,
    sourceDone: true,
    nextRecordIndex: 0,
    nextShardIndex: 0,
    frontier: { count: 0, nodes: [] },
    counts: zeroCounts(),
    sliceCount: 1,
    partialRecord: null,
  };
  const deps: SliceDeps = {
    source: new KVSource(new EmptyKV() as unknown as KVNamespace, NS),
    dest,
    signer,
    recipients,
    budget: new SliceBudget({ subrequests: 200, wallMs: 60_000 }),
  };
  const noShards: ShardEntry[] = [];
  await finaliseRun(deps, cp, master, noShards, []);

  ok("the SLICED path sealed a run over an empty source without refusing", dest.map.size > 0);

  // It is a real, signed, openable archive: the reader verifies the signature, the shard hashes and the
  // Merkle root, and finds no records.
  const run = await openRun({ get: async (k: string) => (await dest.get(k))?.body ?? null } as never, RUN_ID, parseIdentity(breakGlassIdentity), verifier, {});
  ok("the zero-record archive OPENS and verifies (signature, shard hashes, merkle root)", run !== null);
  ok("POPULATION, INVERTED: it genuinely holds zero records", run.records.length === 0);
  run.dispose();

  // THE CONTRADICTION, ASSERTED RATHER THAN DESCRIBED. The BUFFERED writer refuses the identical state, and
  // its refusal is not incidental: it records the closed CUSTOMER-fault kind source-enumerated-zero so
  // support can say "your source produced nothing" instead of the customer being told the engine broke.
  let writerRefused: string | null = null;
  try {
    await buildArchive({
      downpipeId: DP_ID, downpipeName: "emptyrun", cadence: "3600s", runId: RUN_ID,
      master: rand(32), recipients, signer, records: [],
      windowStart: "2026-08-13T00:00:00.000Z", windowEnd: "2026-08-13T00:00:01.000Z", createdAt: "2026-08-13T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
  } catch (e) {
    writerRefused = (e as Error).message;
  }
  ok("THE BUFFERED PATH REFUSES THE IDENTICAL STATE ('an empty run is never valid')", writerRefused !== null && /at least one record/.test(writerRefused));
  ok("SO THE TWO SEAL PATHS ANSWER THE SAME QUESTION OPPOSITELY, and this is the finding, not the fixture", writerRefused !== null && dest.map.size > 0);

  console.log("\nD. WHAT THE DRILL SAYS ABOUT A REHEARSAL THAT DECRYPTED NOTHING");

  const env = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: bucketOver(dest.map),
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;

  // MANUAL mode.
  const manual = await runDrill(env, RUN_ID);
  ok("a MANUAL drill over a zero-record run is NOT ok", manual.ok === false);
  ok("it verified zero records, and says so", manual.recordsVerified === 0);
  ok("it is marked nothingToVerify, which is what keeps it out of the FAILURE branch", manual.nothingToVerify === true);
  ok("and it states the cause rather than a bare verdict", manual.reason === NOTHING_TO_VERIFY_REASON);
  // The sentence must point at the SOURCE, not the archive: nothing here says the backup is damaged.
  ok("the sentence names the source as the thing to check, and never claims a failure", /source/.test(manual.reason ?? "") && !/fail/i.test(manual.reason ?? ""));

  // WINDOWED mode, which is the one the scheduled restore test runs and therefore the one that stamps
  // lastRestoreTestOk and writes the drill-evidence note an auditor reads.
  const scheduled = await runDrill(env, RUN_ID, null, { cursor: 0, window: 8 });
  ok("the SCHEDULED (windowed) drill over the same run is NOT ok", scheduled.ok === false);
  ok("and it too is a deferral rather than a failure", scheduled.nothingToVerify === true);
  ok("so no surface can render 'scheduled restore test passed (records verified: 0)' from this result", scheduled.ok === false);

  console.log("\nE. WHAT THE MANUAL POST /admin/restore/verify ROUTE SAYS ABOUT THE SAME ARCHIVE");

  const verify = await runBlindRestoreTest(env, { runId: RUN_ID });
  ok("POST /admin/restore/verify over a zero-record run is NOT ok (unchanged: never was a false pass)", verify.ok === false);
  ok("it verified zero records, and says so", verify.recordsVerified === 0);
  ok("it is marked nothingToVerify, matching drill.ts's own verdict over the identical archive", verify.nothingToVerify === true);
  ok("and it states the cause rather than a bare {ok:false}", verify.reason === NOTHING_TO_VERIFY_REASON);
  ok("the sentence names the source as the thing to check, and never claims a failure", /source/.test(verify.reason ?? "") && !/fail/i.test(verify.reason ?? ""));
}

// The GREEN CONTROL for C+D: the same code path, the same drill, over a run that DOES hold records. If the
// zero-record clause were implemented as a blanket pessimism, this is the cell that would go red.
async function proofNonEmptyControl(signer: Signer, recipients: RecipientEntry[], operationalPrivateB64: string, signerPrivateB64: string): Promise<void> {
  console.log("\nCONTROL: THE SAME DRILL OVER A RUN THAT HOLDS RECORDS");

  const RUN_ID = "01BX5ZZKBKACTAV9WEVGEMMVR3";
  const store = new Map<string, Uint8Array>();
  const archive = await buildArchive({
    downpipeId: DP_ID, downpipeName: "emptyrun", cadence: "3600s", runId: RUN_ID,
    master: rand(32), recipients, signer,
    records: [
      { sourceType: "kv" as const, name: "a", namespace: NS, value: utf8("v1") },
      { sourceType: "kv" as const, name: "b", namespace: NS, value: utf8("v2") },
    ],
    windowStart: "2026-08-13T00:00:00.000Z", windowEnd: "2026-08-13T00:00:01.000Z", createdAt: "2026-08-13T00:00:01.000Z",
    runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
  });
  for (const [k, v] of archive) store.set(k, v);

  const env = {
    SCHEDULER: {} as unknown as DurableObjectNamespace,
    DEST_KIND: "r2",
    DEST_R2: bucketOver(store),
    SIGNER_PRIVATE: signerPrivateB64,
    OPERATIONAL_PRIVATE: operationalPrivateB64,
  } as unknown as Env;

  const manual = await runDrill(env, RUN_ID);
  ok("CONTROL: a manual drill over a 2-record run IS ok", manual.ok === true);
  ok("CONTROL: it verified the records", manual.recordsVerified === 2);
  ok("CONTROL: and it is NOT marked nothingToVerify", manual.nothingToVerify === undefined);
  ok("CONTROL: and it carries no refusal reason", manual.reason === undefined);

  const scheduled = await runDrill(env, RUN_ID, null, { cursor: 0, window: 8 });
  ok("CONTROL: the scheduled windowed drill over the same run IS ok", scheduled.ok === true);
  ok("CONTROL: and is not a deferral", scheduled.nothingToVerify === undefined);

  const verify = await runBlindRestoreTest(env, { runId: RUN_ID });
  ok("CONTROL: POST /admin/restore/verify over a 2-record run IS ok", verify.ok === true);
  ok("CONTROL: it verified the records", verify.recordsVerified === 2);
  ok("CONTROL: and is NOT marked nothingToVerify (so the clause is a discrimination, not a blanket pessimism)", verify.nothingToVerify === undefined);
  ok("CONTROL: and it carries no refusal reason", verify.reason === undefined);
}

async function main(): Promise<void> {
  const signerSeed = rand(64); // ed25519 seed(32) || ML-DSA seed(32)
  const signerPrivateB64 = b64urlEncode(signerSeed);
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const recipients = [breakGlass.entry, op.entry];
  const operationalPrivateB64 = b64urlEncode(op.identity);

  await proofR2BindingFallback();
  await proofPlanVerdict(signer, recipients, operationalPrivateB64, signerPrivateB64);
  await proofZeroRecordRun(signer, recipients, breakGlass.identity, operationalPrivateB64, signerPrivateB64, verifier);
  await proofNonEmptyControl(signer, recipients, operationalPrivateB64, signerPrivateB64);

  console.log(failures === 0 ? "\nRESTORE HONESTY PASS\n" : `\nRESTORE HONESTY FAIL (${failures})\n`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

await main();
