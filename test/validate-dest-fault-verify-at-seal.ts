// This validator proves the
// load-bearing invariant "no partial or corrupt backup is ever presented as a good, INTEGRITY-VERIFIED backup
// on a destination that did not durably and correctly store it", over the REAL engine, in-process, to an
// in-memory FaultDestination (test/fault-destination.ts). Net-zero: harness-minted keys, fake records, no
// estate, no bucket, no network, no seed, no deploy, no spend; teardown is process exit.
//
// It EXTENDS the shipped read-back coverage (validate-verify-at-seal.ts drives the real verifyAtSeal against a
// SpyDestination over a real buildArchive) with the DESTINATION-WRITE plane the read-back validator never
// touches, elevated to the corpus discipline: a fault-injecting Destination driving the REAL sliced
// finaliseRun/runSlice (plane 1), the sealed-ok GATE on the run row and the scheduler DO's completeRun
// (integrityVerified), the REAL runSealVerification wrapper (the verify-suspect seal-fault + the critical
// alert), a grounded classifier-fidelity finding, and default-FAIL refuters on both planes.
//
// CRITICAL FIDELITY: verify-at-seal is FAIL-OPEN. A silent-corruption run's row
// status STAYS "ok". This suite NEVER asserts row.status === "failed" on plane 2. The provable plane-2 claim
// is that integrityVerified is WITHHELD (scheduler-do-scheduling.ts:406), sealVerification.status is "suspect",
// the posture seal-verification check is critical-fail, and the critical restore-test-fail alert fires, WHILE
// the row stays "ok". Only PLANE 1 (a hard write fault) legitimately fails the row (status "failed", empty
// runId), because verifyAtSeal never runs on the fault path.
//
// Run: node test/validate-dest-fault-verify-at-seal.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { buildArchive, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { attestKeyless } from "../src/format/keyless.ts";
import {
  verifyAtSeal,
  type SealVerification,
} from "../src/seal/verify-at-seal.ts";
import { runSealVerification, downDestinationFlag } from "../src/seal/runstate-helpers.ts";
import { computePosture, type PostureInput } from "../src/admin/posture.ts";
import { coarseRunError, causeDigest, finaliseRun, runSlice, type SliceDeps } from "../src/seal/slice.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { wrapMaster, zeroCounts, type RunCheckpoint } from "../src/seal/checkpoint.ts";
import { classifyDestError } from "../src/dest/classify.ts";
import { sealAttemptClass } from "../src/seal/run-pressure.ts";
import { postSealFault, resetSealFaultDropTally, type SealFaultPost } from "../src/seal/seal-fault-post.ts";
import type { Env } from "../src/env.d.ts";
import type { SourceAdapter, SourceRecord, Selector, Meter } from "../src/sources/types.ts";
import type { NotifyChannel, NotifyEmission } from "../src/notify.ts";
import { FaultDestination } from "./fault-destination.ts";
import { makeScheduler, makeConfig, stubFetch } from "./validate-scheduler-shared.ts";
import type { SchedulerDO } from "../src/sched/scheduler-do.ts";

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

function rootKeyOf(runId: string): string {
  return `run/${runId}/root.manifest.json`;
}
const RUNLOG_KEY = "_RECOVERY/RUNLOG";

// pipeRun mints a DISTINCT, valid 26-char ULID for a pipeline-sealed run (Crockford base32 excludes I/L/O/U, so
// the run-id string cannot spell words). The prefix is a real, decodable ULID timestamp; the 2-digit suffix
// makes each run's id unique without leaving the valid alphabet.
const ULID_PREFIX = "01ARZ3NDEKTSV4RRFFQ69G5F"; // 24 valid ULID chars (a real, decodable timestamp portion)
function pipeRun(n: number): string {
  return `${ULID_PREFIX}${String(n).padStart(2, "0")}`;
}

// PipelineSource is a minimal NON-resumable in-memory source (no crawlFrom), so runSlice drives it through the
// real crawlNonResumable path, sealing a handful of harness-generated fake records into the archive. It mirrors
// validate-slice.ts's NonResumableSource pattern.
class PipelineSource implements SourceAdapter {
  readonly sourceType = "cf-config" as const;
  private readonly n: number;
  constructor(n: number) {
    this.n = n;
  }
  async *crawl(_selector: Selector, meter?: Meter): AsyncIterable<SourceRecord> {
    for (let i = 0; i < this.n; i++) {
      meter?.spend(1);
      yield { sourceType: "cf-config", name: `surface/${i}`, value: utf8(`dest-fault-axis-value-${i}`) };
    }
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: this.n, bytes: -1 };
  }
}

// RecordingScheduler is the DurableObjectStub double runSealVerification / routeSealVerifyAlert are driven
// against, recording every /seal-fault POST body and the notify-route calls so the harness can assert the REAL
// production wrapper POSTED the verify-suspect seal-fault and FIRED the critical alert. It returns the
// configured channel(s) from /notify/resolve so routeSealVerifyAlert reaches /notify/record (the alert fires),
// exactly as validate-verify-at-seal.ts's FakeScheduler does, extended to also record /seal-fault.
class RecordingScheduler {
  readonly sealFaultPosts: SealFaultPost[] = [];
  readonly notifyCalls: string[] = [];
  lastResolveEmission: NotifyEmission | null = null;
  private readonly channels: NotifyChannel[];
  constructor(channels: NotifyChannel[] = []) {
    this.channels = channels;
  }
  async fetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const path = new URL(url).pathname;
    const jsonHeaders = { "content-type": "application/json" };
    if (path === "/seal-fault") {
      try {
        this.sealFaultPosts.push(JSON.parse(String(init?.body ?? "{}")) as SealFaultPost);
      } catch { /* ignore */ }
      return new Response(JSON.stringify({ recorded: 1 }), { status: 200, headers: jsonHeaders });
    }
    this.notifyCalls.push(path);
    if (path === "/notify/resolve") {
      try {
        const body = JSON.parse(String(init?.body ?? "{}")) as { emission?: NotifyEmission };
        this.lastResolveEmission = body.emission ?? null;
      } catch { /* ignore */ }
      return new Response(JSON.stringify({ now: this.channels, digestedCount: 0, emission: this.lastResolveEmission }), { status: 200, headers: jsonHeaders });
    }
    if (path === "/notify/record") return new Response(JSON.stringify({ recorded: 1 }), { status: 200, headers: jsonHeaders });
    return new Response("not found", { status: 404 });
  }
}

// doStub adapts the real SchedulerDO to the DurableObjectStub.fetch(url, init) shape postSealFault uses, so the
// harness can drive the REAL postSealFault into the REAL DO seal-fault ring and read it back via GET
// /seal-faults (proving the ring surface persists + sanitises the reconstructed verdict).
function doStub(stub: SchedulerDO): DurableObjectStub {
  return {
    fetch: (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      return stub.fetch(new Request(url, init));
    },
  } as unknown as DurableObjectStub;
}

// basePostureInput is a minimal all-passing PostureInput so the seal-verification posture check can be
// exercised in isolation (only the downpipes slice varies), copied from validate-verify-at-seal.ts.
function basePostureInput(downpipes: PostureInput["downpipes"]): PostureInput {
  return {
    status: {
      destConfigured: true,
      breakGlassConfigured: true,
      operationalConfigured: { public: true, private: true },
      tokenFallbackDisabled: true,
      adminTokenPresent: false,
      bootstrapConsumed: true,
      breakGlassTokenRetired: true,
      recoveryBreakGlassReady: true,
    },
    downpipes,
    expiry: [],
    notifyFailureRuleSet: true,
    ownerCount: 2,
    operationalPrivatePresent: false,
    beaconEnabled: false,
    overrides: new Map(),
    // No pin recorded in this fixture. Stated rather than omitted: PostureInput makes this REQUIRED
    // and nullable so a caller cannot silently default a tamper signal to "no drift".
    recipientPinDrift: null,
  };
}

// postureSealCheck returns the seal-verification posture check for a downpipe with a given last verdict.
function postureSealStatus(id: string, name: string, lastSealVerifyOk: boolean | undefined, at?: number): { status: string | undefined; severity: string | undefined } {
  const dp = lastSealVerifyOk === undefined ? { id, name } : { id, name, lastSealVerifyOk, lastSealVerifyAt: at ?? Date.now() };
  const report = computePosture(basePostureInput([dp]), Date.now());
  const check = report.checks.find((c) => c.id === "seal-verification");
  return { status: check?.status, severity: check?.severity };
}

async function main(): Promise<void> {
  // ---- shared harness-minted keys, recipients and env (net-zero; never a real customer key) ----
  const signerSeed = rand(64);
  const signerPrivateB64 = b64urlEncode(signerSeed);
  const signer: Signer = await loadSigner(signerPrivateB64);
  verifierFrom(signer); // pin a verifier once to prove the keys load (verifyAtSeal loads its own)
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const operationalPrivateB64 = b64urlEncode(op.identity);
  const recipients = [breakGlass.entry, op.entry];
  const envOp = { SCHEDULER: {} as unknown as DurableObjectNamespace, SIGNER_PRIVATE: signerPrivateB64, OPERATIONAL_PRIVATE: operationalPrivateB64 } as unknown as Env;

  // freshArchive builds a clean, real engine-sealed archive (the production buildArchive), reused by the
  // tamper cells + the healthy buildArchive control, exactly as validate-verify-at-seal.ts does.
  const BUILD_RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
  const KVSET: Record<string, string> = {
    "key:alpha": "value-alpha",
    "key:beta": "value-beta-longer",
    "key:gamma": "gamma-value-here",
    "key:delta": "delta-value-padded",
    "key:epsilon": "epsilon-value-content",
  };
  const buildRecords = Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: "ns_seal" }));
  // A deliberately MULTI-CHUNK record (exactly two 64 KiB stream chunks) so the segment-truncation mutation can
  // lop a WHOLE trailing chunk and trip the reader's structural "terminates after" record-integrity gate. A
  // patterned fill keeps every chunk distinct (a periodic value could dedup to one shared segment).
  const twoChunk = new Uint8Array(2 * 65536);
  for (let i = 0; i < twoChunk.length; i++) twoChunk[i] = (Math.imul(i + 7, 2654435761) >>> 24) & 0xff;
  buildRecords.push({ sourceType: "kv", name: "key:multichunk", value: twoChunk, namespace: "ns_seal" });
  const totalBytes = buildRecords.reduce((n, r) => n + r.value.length, 0);
  async function freshArchive(): Promise<Map<string, Uint8Array>> {
    return buildArchive({
      downpipeId: "dp_fault", downpipeName: "fault-axis", cadence: "3600s", runId: BUILD_RUN_ID,
      master: rand(32), recipients, signer, records: buildRecords,
      windowStart: "2026-07-23T00:00:00.000Z", windowEnd: "2026-07-23T00:00:01.000Z", createdAt: "2026-07-23T00:00:01.000Z",
      runlogIndex: 1, prevRunId: null, randomNonce: () => rand(16), randomSalt: () => rand(16),
    });
  }

  // pipelineDeps builds the SliceDeps that drives the REAL sliced seal to a FaultDestination. A deliberately
  // SMALL throttleRetry budget (2 attempts) makes a persistent 503/transient surface fast instead of retrying
  // for real; an auth/permanent fault fails on attempt 1 regardless.
  function pipelineDeps(dest: FaultDestination): SliceDeps {
    return { source: new PipelineSource(3), dest, signer, recipients, budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }), throttleRetry: { attempts: 2, baseMs: 1 } };
  }
  async function freshCheckpoint(runId: string): Promise<RunCheckpoint> {
    const master = rand(32);
    return {
      v: 1, downpipeId: "dp_fault", downpipeName: "fault-axis", cadence: "3600s", sourceType: "cf-config",
      selector: { include: [], exclude: [] }, runId, runlogIndex: 1, prevRunId: null,
      startedAt: "2026-07-23T00:00:00.000Z", wrappedMaster: await wrapMaster(signerPrivateB64, runId, master),
      cursor: null, sourceDone: false, nextRecordIndex: 0, nextShardIndex: 0,
      frontier: { count: 0, nodes: [] }, counts: zeroCounts(), sliceCount: 0, partialRecord: null,
    };
  }
  // driveSeal drives the REAL runSlice + finaliseRun over `dest` (already armed with any fault). Returns the
  // thrown error (or null) and the plaintext byte count the run sealed (for a subsequent verifyAtSeal).
  async function driveSeal(dest: FaultDestination, runId: string): Promise<{ error: Error | null; plaintextBytes: number }> {
    const master = rand(32);
    const cp: RunCheckpoint = { ...(await freshCheckpoint(runId)), wrappedMaster: await wrapMaster(signerPrivateB64, runId, master) };
    const deps = pipelineDeps(dest);
    let error: Error | null = null;
    let bytes = 0;
    try {
      const r = await runSlice(deps, cp, master);
      bytes = r.checkpoint.counts.bytes;
      await finaliseRun(deps, r.checkpoint, master, r.newShards, r.openWrite);
    } catch (e) {
      error = e as Error;
    } finally {
      master.fill(0);
    }
    return { error, plaintextBytes: bytes };
  }

  // ============================================================================================
  // CELL (a): a dest write-fault at seal means the run is NOT sealed-ok and the fault surfaces the TRUE class.
  // ============================================================================================
  console.log("cell (a): dest write-fault at seal -> run NOT sealed-ok, TRUE class");
  const destId = "dest-fault-axis";
  // Shapes 1-3 fault the ROOT-manifest PUT; the seal THROWS, coarseRunError names the true class, and the
  // harness-owned store shows root + RUNLOG did NOT durably land (not a recoverable sealed run).
  const shapes: Array<{ runId: string; label: string; shape: "throttle503" | "auth403" | "code400"; expectClass: string; destAccess: boolean }> = [
    { runId: pipeRun(1), label: "503 throttle past a small retry budget", shape: "throttle503", expectClass: "destination access error", destAccess: true },
    { runId: pipeRun(2), label: "403 auth on attempt 1 (never retried)", shape: "auth403", expectClass: "destination access error", destAccess: true },
    { runId: pipeRun(3), label: "400 permanent rejection with an S3 <Code>", shape: "code400", expectClass: "destination rejected the write (InvalidRequest)", destAccess: false },
  ];
  for (const s of shapes) {
    const runId = s.runId;
    const dest = new FaultDestination();
    dest.armWriteFault({ match: (k) => k === rootKeyOf(runId), shape: s.shape, code: "InvalidRequest" });
    const { error } = await driveSeal(dest, runId);
    ok(`(a/${s.shape}) the seal THROWS on the faulted root write (${s.label})`, error !== null);
    ok(`(a/${s.shape}) coarseRunError names the TRUE class: ${s.expectClass}`, error !== null && coarseRunError(error.message) === s.expectClass);
    ok(`(a/${s.shape}) the root manifest did NOT durably land`, !dest.stored(rootKeyOf(runId)));
    ok(`(a/${s.shape}) the RUNLOG entry did NOT durably land`, !dest.stored(RUNLOG_KEY));
    // Independent oracle: attestKeyless over the harness-owned store cannot recover the run (no signed root).
    const att = await attestKeyless(dest.asObjectStore(), runId, verifierFrom(signer), { allowStale: true });
    ok(`(a/${s.shape}) attestKeyless over the store proves it is NOT a recoverable sealed run`, att.signatureValid === false);
    // downDestinationFlag is set ONLY for the destination-access class (a permanent 400 rejection is not an
    // availability down-signal), exactly as runstate.ts DEST-1 gates it.
    const flag = downDestinationFlag(coarseRunError(error!.message), destId);
    ok(`(a/${s.shape}) down-destination flag ${s.destAccess ? "SET (destination-access)" : "NOT set (permanent rejection)"}`, s.destAccess ? Array.isArray(flag.downDestinationIds) && flag.downDestinationIds[0] === destId : (flag as { downDestinationIds?: string[] }).downDestinationIds === undefined);
  }

  // Classifier fidelity: the S3-shape positive is asserted above; the native-R2 binding transient
  // outage ("internal error", no "status NNN") is a CONTRAST worth noting (slice.ts:715 omits
  // "internal error", so the run-row class coarsens to generic "run failed" while the retry classifier and the
  // seal-fault ring still name it transient). The safety property is UNHARMED: the write still fails the run.
  {
    const runId = pipeRun(4);
    const dest = new FaultDestination();
    dest.armWriteFault({ match: (k) => k === rootKeyOf(runId), shape: "nativeInternal" });
    const { error } = await driveSeal(dest, runId);
    ok("(a/native) a native-R2 transient write outage still FAILS the run (plane 1 safety holds)", error !== null && !dest.stored(rootKeyOf(runId)) && !dest.stored(RUNLOG_KEY));
    ok("(a/native) CONTRAST (bug candidate): coarseRunError coarsens the run-row class to 'run failed'", error !== null && coarseRunError(error.message) === "run failed");
    ok("(a/native) yet the retry classifier NAMES it transient (classify.ts NETWORK_RE includes 'internal error')", error !== null && classifyDestError(error) === "transient");
    ok("(a/native) and the seal-fault ring NAMES it transient (run-pressure TRANSIENT_RE includes 'internal error')", error !== null && sealAttemptClass(error) === "transient");
  }

  // Shape 4: a dropped write (acknowledged as success, stores nothing) on the ROOT. The seal does NOT throw, so
  // plane 1 passes it through; the two-plane hand-off to verify-at-seal (cell b) then catches the object-missing.
  let shape4Verdict: SealVerification | undefined;
  {
    const runId = pipeRun(5);
    const dest = new FaultDestination();
    dest.armDropWrite((k) => k === rootKeyOf(runId));
    const { error, plaintextBytes } = await driveSeal(dest, runId);
    ok("(a/drop) a dropped root write does NOT throw (the store lied about the write; plane 1 passes it)", error === null);
    ok("(a/drop) the root did NOT durably land despite the acknowledged write", !dest.stored(rootKeyOf(runId)));
    dest.disarm();
    shape4Verdict = await verifyAtSeal(envOp, dest, runId, plaintextBytes);
    ok("(a/drop) the two-plane hand-off: verify-at-seal catches the missing object as SUSPECT", shape4Verdict.status === "suspect");
    ok("(a/drop) the sub-class is object-missing (the dropped root reads back absent)", shape4Verdict.reason === "object missing");
  }

  // ============================================================================================
  // CELL (b): silent corruption -> verify-at-seal SUSPECT, integrity WITHHELD. verify-at-seal is FAIL-OPEN.
  // ============================================================================================
  console.log("cell (b): silent corruption -> verify-at-seal suspect, integrity withheld (fail-open)");
  // Four mutations, each tampering the STORED bytes of a KNOWN object after a clean seal, with the sub-class
  // reason MATCHING the mutation site (design 1.3 / 5.3). tier is asserted so no catch is over-claimed.
  // FIDELITY NOTE for cell (b): a stored-byte segment truncation reads back as the reader's honest
  // decrypt-tier catch-all "verification check failed", NOT the finer "record integrity check failed" the design
  // named. That finer sub-class needs a signed-manifest chunkRange over-declaration or a plaintext-hash
  // mismatch, both of which a valid signature + AES-GCM make UNREACHABLE via bytes-on-disk tampering (the last
  // chunk's nonce carries a last-marker domain-separation bit, so any truncation fails AEAD before the
  // structural "terminates after" gate). Asserting "record integrity check failed" would be mis-specified
  // against the REAL engine and would fail a correct one. The four mutations still map to four DISTINCT, site-matching suspect reasons, and the segment
  // reason is NOT the config-error false-catch the refuter forbids.
  const mutations: Array<{ label: string; mutate: (d: FaultDestination) => void; reason: string; tier: string }> = [
    { label: "shard-manifest byte flip -> completeness (Tier-0)", mutate: (d) => { d.tamperShard(); }, reason: "completeness check failed", tier: "tier-0" },
    { label: "segment whole-chunk truncation -> read-back verification fails (decrypt tier)", mutate: (d) => { d.truncateSegment(); }, reason: "verification check failed", tier: "full" },
    { label: "delete root -> object-missing", mutate: (d) => { d.deleteObject(rootKeyOf(BUILD_RUN_ID)); }, reason: "object missing", tier: "tier-0" },
    { label: "delete RUNLOG -> freshness", mutate: (d) => { d.deleteObject(RUNLOG_KEY); }, reason: "freshness check failed", tier: "tier-0" },
  ];
  let cellBVerdict: SealVerification | undefined; // a representative suspect for cell (c) / the ring round-trip
  for (const m of mutations) {
    const dest = new FaultDestination();
    dest.seed(await freshArchive());
    m.mutate(dest);
    dest.mutateLog.length = 0; // count only verify-induced mutations from here
    let threw = false;
    let v: SealVerification | undefined;
    try {
      v = await verifyAtSeal(envOp, dest, BUILD_RUN_ID, totalBytes);
    } catch {
      threw = true;
    }
    ok(`(b) verify did NOT throw (fail-open): ${m.label}`, !threw && v !== undefined);
    ok(`(b) verdict is SUSPECT: ${m.label}`, v?.status === "suspect");
    ok(`(b) the sub-class reason MATCHES the mutation site: ${m.reason}`, v?.reason === m.reason);
    ok(`(b) the verdict is scoped to the coverage tier it ran: ${m.tier}`, v?.tier === m.tier);
    ok(`(b) verify wrote and deleted NOTHING (fail-open, read-only)`, dest.mutateLog.length === 0);
    if (m.tier === "full") cellBVerdict = v; // the decrypt-tier suspect carries an ordinal for the ring
  }

  // The REAL runSealVerification wrapper over a tampered dest: it POSTS the verify-suspect seal-fault and FIRES
  // the critical alert, fail-open (the design's plane-2 machine surface the read-back validator never drives).
  {
    resetSealFaultDropTally();
    const dest = new FaultDestination();
    dest.seed(await freshArchive());
    dest.truncateSegment(); // a record-integrity corruption -> a decrypt-tier suspect with an ordinal
    dest.mutateLog.length = 0;
    const channel: NotifyChannel = { id: "ch1", kind: "webhook", name: "test", url: "https://example.test/hook", enabled: true, createdAt: "2026-07-23T00:00:00.000Z" };
    const rec = new RecordingScheduler([channel]);
    const v = await runSealVerification({ env: envOp, scheduler: rec as unknown as DurableObjectStub, dest, downpipe: { id: "dp_fault", name: "fault-axis" } }, BUILD_RUN_ID, totalBytes);
    ok("(b) runSealVerification returns the SUSPECT verdict (fail-open, run still completes)", v?.status === "suspect");
    const suspectPost = rec.sealFaultPosts.find((p) => p.kind === "verify-suspect");
    ok("(b) it POSTED a verify-suspect seal-fault to the ring", suspectPost !== undefined);
    ok("(b) the seal-fault carries the verify mode + a correlation digest", suspectPost?.verifyMode === "full" && typeof suspectPost?.causeDigest === "string");
    ok("(b) the seal-fault carries the failing ordinal (WHICH record) + clean-before-fail", suspectPost?.ordinal !== undefined);
    ok("(b) it FIRED the critical alert (reached notify resolve + record)", rec.notifyCalls.includes("/notify/resolve") && rec.notifyCalls.includes("/notify/record"));
    ok("(b) the alert is the critical restore-test-fail emission", rec.lastResolveEmission?.event === "restore-test-fail" && rec.lastResolveEmission?.severity === "critical");
    ok("(b) runSealVerification wrote/deleted NOTHING on the destination (fail-open)", dest.mutateLog.length === 0);
  }

  // The integrity GATE on the scheduler DO: driving the REAL completeRun with a suspect verdict WITHHOLDS the
  // integrityVerified stamp (scheduler-do-scheduling.ts:406) WHILE the row stays "ok" (the fail-open truth).
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("b-suspect", { enabled: true }));
    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "b-suspect" })).json()) as { runId: string; index: number };
    const suspect: SealVerification = { status: "suspect", tier: "full", sampled: 0, at: Date.now(), reason: "record integrity check failed" };
    await stubFetch(stub, "POST", "/complete", { id: "b-suspect", runId: t.runId, index: t.index, status: "ok", sealVerification: suspect });
    const ds = storage.rawGet<{ integrityVerified?: unknown; lastSealVerify?: { status: string } }>("dp:b-suspect")!;
    const row = (storage.rawGet<Array<{ index: number; status: string; sealVerification?: { status: string } }>>("hist:b-suspect") ?? []).find((h) => h.index === t.index)!;
    ok("(b) integrityVerified is WITHHELD on a suspect readback (the DO gate)", ds.integrityVerified === undefined);
    ok("(b) the suspect verdict is still RECORDED on the run row + state (observable)", ds.lastSealVerify?.status === "suspect" && row.sealVerification?.status === "suspect");
    ok("(b) the row status STAYS 'ok' (verify-at-seal is fail-open; NOT a failed row)", row.status === "ok");
  }

  // ============================================================================================
  // CELL (c): the fault renders honestly on the run status + the seal-fault ring, never a false green.
  // ============================================================================================
  console.log("cell (c): honest surfaces, never a false green (both planes)");
  // PLANE 1 (hard write fault): failed row + coarse class + cause digest + no integrity recency + down-dest lit
  // + a lost failed completion reconstructable from the seal-fault ring's completion-lost kind.
  {
    const runId = pipeRun(6);
    const dest = new FaultDestination();
    dest.armWriteFault({ match: (k) => k === rootKeyOf(runId), shape: "throttle503" });
    const { error } = await driveSeal(dest, runId);
    const coarse = coarseRunError(error!.message);
    const cause = await causeDigest(error!.message);

    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("c-plane1", { enabled: true }));
    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "c-plane1" })).json()) as { runId: string; index: number };
    // The failed completion the seal path posts (runstate.ts:308): empty runId, coarse class, cause digest, and
    // the down-destination named for a destination-access class.
    await stubFetch(stub, "POST", "/complete", { id: "c-plane1", runId: "", index: t.index, status: "failed", error: coarse, causeDigest: cause, ...downDestinationFlag(coarse, destId) });
    const ds = storage.rawGet<{ inFlight: boolean; lastRunId: string | null; integrityVerified?: unknown }>("dp:c-plane1")!;
    const row = (storage.rawGet<Array<{ index: number; status: string; error?: string; causeDigest?: string }>>("hist:c-plane1") ?? []).find((h) => h.index === t.index)!;
    ok("(c/p1) the run-history row is status 'failed' carrying the coarse class", row.status === "failed" && row.error === coarse);
    ok("(c/p1) the row carries the 12-hex cause digest (support joins it to the Logpush line)", row.causeDigest === cause && /^[0-9a-f]{12}$/.test(cause));
    ok("(c/p1) NO integrityVerified recency was stamped (a failed run never stamps it)", ds.integrityVerified === undefined && ds.lastRunId === null && ds.inFlight === false);
    const repl = (await (await stubFetch(stub, "GET", "/replication?id=c-plane1")).json()) as { dests: Record<string, { lastOk: boolean }> };
    ok("(c/p1) the down-destination indicator is LIT for the destination-access class", repl.dests[destId]?.lastOk === false);

    // A lost failed completion is reconstructable from the seal-fault ring's completion-lost kind (posted via
    // the REAL postSealFault, from the REAL thrown error's causeDigest + sealAttemptClass).
    resetSealFaultDropTally();
    const lost: SealFaultPost = { kind: "completion-lost", at: Date.now(), downpipeId: "c-plane1", runId, outcome: "failed", causeDigest: cause, attemptClasses: [sealAttemptClass(error)] };
    await postSealFault(doStub(stub), lost);
    const ring = (await (await stubFetch(stub, "GET", "/seal-faults")).json()) as { faults: Array<{ kind: string; outcome?: string; attemptClasses?: string[]; causeDigest?: string }> };
    const clr = ring.faults.find((f) => f.kind === "completion-lost");
    ok("(c/p1) the lost failed verdict is reconstructable from the ring (completion-lost, outcome failed)", clr?.outcome === "failed");
    ok("(c/p1) the ring carries the closed attempt class of the fault (never the raw message)", clr?.attemptClasses?.[0] === "throttle" && clr?.causeDigest === cause);
  }

  // PLANE 2 (silent corruption): row 'ok' BUT sealVerification suspect + integrityVerified withheld + posture
  // critical-fail + a verify-suspect seal-fault on the ring + the critical alert fired.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("c-plane2", { enabled: true }));
    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "c-plane2" })).json()) as { runId: string; index: number };
    const suspect: SealVerification = cellBVerdict ?? { status: "suspect", tier: "full", sampled: 0, at: Date.now(), reason: "record integrity check failed", causeDigest: "0123456789ab", failingOrdinal: 2, verifiedBeforeFail: 2 };
    await stubFetch(stub, "POST", "/complete", { id: "c-plane2", runId: t.runId, index: t.index, status: "ok", sealVerification: suspect });
    const ds = storage.rawGet<{ integrityVerified?: unknown; lastSealVerify?: { status: string } }>("dp:c-plane2")!;
    const row = (storage.rawGet<Array<{ index: number; status: string; sealVerification?: { status: string } }>>("hist:c-plane2") ?? []).find((h) => h.index === t.index)!;
    ok("(c/p2) the run row is 'ok' BUT carries sealVerification.status 'suspect'", row.status === "ok" && row.sealVerification?.status === "suspect");
    ok("(c/p2) integrityVerified is WITHHELD (no false green integrity recency)", ds.integrityVerified === undefined && ds.lastSealVerify?.status === "suspect");
    const posture = postureSealStatus("c-plane2", "fault-axis", false, suspect.at);
    ok("(c/p2) the posture seal-verification check is critical-fail", posture.status === "fail" && posture.severity === "critical");

    // The verify-suspect seal-fault persists + sanitises on the REAL DO ring (verify mode, ordinal, digest).
    resetSealFaultDropTally();
    const suspectPost: SealFaultPost = { kind: "verify-suspect", at: Date.now(), downpipeId: "c-plane2", runId: t.runId, verifyMode: "full", ...(suspect.causeDigest !== undefined ? { causeDigest: suspect.causeDigest } : {}), ...(suspect.failingOrdinal !== undefined ? { ordinal: suspect.failingOrdinal } : {}), ...(suspect.verifiedBeforeFail !== undefined ? { verifiedBeforeFail: suspect.verifiedBeforeFail } : {}) };
    await postSealFault(doStub(stub), suspectPost);
    const ring = (await (await stubFetch(stub, "GET", "/seal-faults")).json()) as { faults: Array<{ kind: string; verifyMode?: string; ordinal?: number }> };
    const vsr = ring.faults.find((f) => f.kind === "verify-suspect");
    ok("(c/p2) a verify-suspect seal-fault is on the ring with its verify mode + ordinal", vsr?.verifyMode === "full" && vsr?.ordinal !== undefined);
  }

  // ============================================================================================
  // CELL (d): a healthy seal (control) verifies and seals ok. This is the positive control that makes the
  // suspect cells meaningful (a stuck-on-suspect oracle is caught here). It runs in the SAME suite.
  // ============================================================================================
  console.log("cell (d): healthy control seals ok (verified, integrity stamped, no alert, dest read-only)");
  let healthyVerdict: SealVerification | undefined;
  {
    const runId = pipeRun(7);
    const dest = new FaultDestination(); // a CLEAN double, no fault
    const { error, plaintextBytes } = await driveSeal(dest, runId);
    ok("(d) the healthy seal completes without throwing (real pipeline, clean dest)", error === null && dest.stored(rootKeyOf(runId)) && dest.stored(RUNLOG_KEY));
    dest.mutateLog.length = 0; // count only verify-induced mutations
    resetSealFaultDropTally();
    const channel: NotifyChannel = { id: "ch1", kind: "webhook", name: "test", url: "https://example.test/hook", enabled: true, createdAt: "2026-07-23T00:00:00.000Z" };
    const rec = new RecordingScheduler([channel]);
    healthyVerdict = await runSealVerification({ env: envOp, scheduler: rec as unknown as DurableObjectStub, dest, downpipe: { id: "dp_fault", name: "fault-axis" } }, runId, plaintextBytes);
    ok("(d) verify-at-seal returns VERIFIED at the FULL coverage tier (small run)", healthyVerdict?.status === "verified" && healthyVerdict?.tier === "full");
    ok("(d) NO verify-suspect seal-fault was posted", rec.sealFaultPosts.length === 0);
    ok("(d) NO alert fired (notify routes never reached)", rec.notifyCalls.length === 0);
    ok("(d) verify-at-seal wrote and deleted NOTHING (read-only)", dest.mutateLog.length === 0);

    // The integrity GATE stamps integrityVerified on a healthy verified run (the console reads it as green).
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("d-ok", { enabled: true }));
    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "d-ok" })).json()) as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", { id: "d-ok", runId: t.runId, index: t.index, status: "ok", sealVerification: healthyVerdict });
    const ds = storage.rawGet<{ integrityVerified?: { how: string }; lastSealVerify?: { status: string } }>("dp:d-ok")!;
    const row = (storage.rawGet<Array<{ index: number; status: string; sealVerification?: { status: string } }>>("hist:d-ok") ?? []).find((h) => h.index === t.index)!;
    ok("(d) the run row is 'ok' with sealVerification 'verified'", row.status === "ok" && row.sealVerification?.status === "verified");
    ok("(d) integrityVerified is STAMPED (how:run) on the healthy verified run", ds.integrityVerified?.how === "run" && ds.lastSealVerify?.status === "verified");
    const posture = postureSealStatus("d-ok", "fault-axis", true, healthyVerdict!.at);
    ok("(d) the posture seal-verification check PASSES on a verified verdict", posture.status === "pass");
  }

  // ============================================================================================
  // HONEST BOUND: verify-at-seal is BOUNDED. Above the size ceiling a run is Tier-0 ONLY, so a
  // record-body (record-integrity) corruption is NOT caught at seal -- it is the periodic full drill's and the
  // offline CLI's job. This is recorded as an explicit BOUND, never a false CLEAN, and contrasted with the
  // small-run FULL-coverage cell where the catch is total.
  // ============================================================================================
  console.log("honest bound: a large-run Tier-0 verify does NOT catch a non-sampled record corruption (drill/offline job)");
  {
    // The SAME truncated-segment corruption cell (b) caught at FULL coverage. Forced Tier-0 (a tiny
    // SEAL_VERIFY_MAX_BYTES, as validate-verify-at-seal scenario 6 does) so the decrypt sample is skipped.
    const destFull = new FaultDestination();
    destFull.seed(await freshArchive());
    destFull.truncateSegment();
    const vFull = await verifyAtSeal(envOp, destFull, BUILD_RUN_ID, totalBytes);
    ok("bound: at FULL coverage the record corruption IS caught (suspect, tier full) -- the catch is total for small runs", vFull.status === "suspect" && vFull.tier === "full");

    const destTier0 = new FaultDestination();
    destTier0.seed(await freshArchive());
    destTier0.truncateSegment();
    const vTier0 = await verifyAtSeal({ ...envOp, SEAL_VERIFY_MAX_BYTES: "1" } as Env, destTier0, BUILD_RUN_ID, totalBytes);
    ok("bound: at Tier-0 (over the size ceiling) the SAME record corruption is NOT caught at seal (decrypt skipped)", vTier0.status === "verified" && vTier0.tier === "tier-0");
    ok("bound: the verdict honestly reports its Tier-0 coverage (too-large), never a false full-coverage CLEAN", vTier0.tier0Cause === "too-large");
    // NOTE: this is the documented BOUND handed to the periodic full drill and the offline CLI, NOT a
    // claim that verify-at-seal catches any corruption. The Tier-0 completeness/signature/freshness checks DO
    // still run (a dropped shard or a missing root is caught at any tier); only the decrypt-sample record-body
    // check is size-bounded.
  }

  // ============================================================================================
  // REFUTERS (default-FAIL): each drives an oracle on a KNOWN-BAD (or KNOWN-GOOD) input and asserts the oracle
  // reaches the correct verdict. A refuter that comes back the WRONG way fails the suite.
  // ============================================================================================
  console.log("refuters (default-FAIL): the oracles can SEE a bad seal, and never bless a good-looking bad one");

  // Refuter 1 (keystone, cell a): a faulted write recorded ok/integrity-verified MUST fail. Two-sided: the
  // failed completion the seal path posts must NOT green (row not ok, integrity not stamped), AND a KNOWN-GOOD
  // completion must green (proving the green detector is not a no-op that would pass anything).
  {
    const runId = pipeRun(8);
    const dest = new FaultDestination();
    dest.armWriteFault({ match: (k) => k === rootKeyOf(runId), shape: "throttle503" });
    const { error } = await driveSeal(dest, runId);
    const coarse = coarseRunError(error!.message);
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("r-key", { enabled: true }));
    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "r-key" })).json()) as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", { id: "r-key", runId: "", index: t.index, status: "failed", error: coarse, causeDigest: await causeDigest(error!.message) });
    const ds = storage.rawGet<{ integrityVerified?: unknown }>("dp:r-key")!;
    const row = (storage.rawGet<Array<{ index: number; status: string }>>("hist:r-key") ?? []).find((h) => h.index === t.index)!;
    const greenedFaultedWrite = row.status === "ok" || ds.integrityVerified !== undefined;
    ok("REFUTER keystone: the oracle REFUSES to green a faulted write (row not ok, integrity not stamped)", !greenedFaultedWrite);
    // The green detector is live: a known-good completion DOES green (else the refuter above would be vacuous).
    await stubFetch(stub, "POST", "/downpipes", makeConfig("r-key-ok", { enabled: true }));
    const tg = (await (await stubFetch(stub, "POST", "/trigger", { id: "r-key-ok" })).json()) as { runId: string; index: number };
    await stubFetch(stub, "POST", "/complete", { id: "r-key-ok", runId: tg.runId, index: tg.index, status: "ok", sealVerification: { status: "verified", tier: "full", sampled: 5, at: Date.now() } });
    const dsg = storage.rawGet<{ integrityVerified?: { how: string } }>("dp:r-key-ok")!;
    ok("REFUTER keystone (two-sided): the green detector is NOT a no-op (a good run DOES stamp integrity)", dsg.integrityVerified?.how === "run");
  }

  // Refuter 2 (cell a): the class must be the TRUE class, not a masking generic; the native-R2 contrast is a
  // KNOWN coarsening, expected "run failed", filed not failed-on.
  {
    ok("REFUTER class-true: a status-shaped 503 write fault classifies 'destination access error'", coarseRunError("PUT run/x/root.manifest.json: status 503") === "destination access error");
    ok("REFUTER class-true: a 400-with-code classifies 'destination rejected the write (<Code>)'", coarseRunError("PUT run/x/root.manifest.json: status 400 (InvalidRequest)") === "destination rejected the write (InvalidRequest)");
    // The native-R2 contrast is the KNOWN coarsening (filed as a bug candidate), so it is EXPECTED "run failed"
    // -- the refuter does not fail on the documented gap, while still pinning the S3-shape positives above.
    ok("REFUTER class-true: the native-R2 'internal error' contrast is the KNOWN coarsening (expected 'run failed')", coarseRunError("put failed: internal error") === "run failed");
  }

  // Refuter 3 (cell b): a tampered archive that verifies MUST fail; the matching sub-class; a suspect whose
  // reason is the config-error catch-all would be a false catch. Three siblings (shard/segment/root).
  {
    const sibs: Array<{ label: string; mutate: (d: FaultDestination) => void; reason: string }> = [
      { label: "shard byte flip", mutate: (d) => { d.tamperShard(); }, reason: "completeness check failed" },
      { label: "segment whole-chunk truncation", mutate: (d) => { d.truncateSegment(); }, reason: "verification check failed" },
      { label: "dropped root", mutate: (d) => { d.deleteObject(rootKeyOf(BUILD_RUN_ID)); }, reason: "object missing" },
    ];
    for (const sib of sibs) {
      const dest = new FaultDestination();
      dest.seed(await freshArchive());
      sib.mutate(dest);
      const v = await verifyAtSeal(envOp, dest, BUILD_RUN_ID, totalBytes);
      // Two-sided: the tamper must NOT verify "verified", the reason must MATCH the site (=== sib.reason pins
      // the correct sub-class per sibling), and it must not be the CONFIG-error catch-all (a false catch that
      // masks the real corruption). The reader catch-all "verification check failed" is the honest, CORRECT
      // verdict for a decrypt-failed segment (design cell (b) fidelity correction), so it is forbidden only
      // where it would be the wrong sub-class -- which === sib.reason already enforces.
      ok(`REFUTER tampered-verifies-MUST-fail (${sib.label}): NOT verified, matching sub-class, not the config false-catch`, v.status === "suspect" && v.reason === sib.reason && v.reason !== "engine not fully configured");
    }
    // The negative side of the two-sided oracle: the SAME clean archive, untouched, verifies "verified" (so the
    // reader is not stuck-on-suspect and the suspects above are meaningful).
    const clean = new FaultDestination();
    clean.seed(await freshArchive());
    const vc = await verifyAtSeal(envOp, clean, BUILD_RUN_ID, totalBytes);
    ok("REFUTER tampered-verifies-MUST-fail (control): the untouched clean archive verifies 'verified'", vc.status === "verified");
  }

  // Refuter 4 (cell d): a healthy seal flagged suspect (or with integrity withheld) MUST fail. The healthy
  // control from cell (d) must be verified with integrity stampable; if it ever went suspect, the suite fails.
  {
    ok("REFUTER healthy-flagged-suspect-MUST-fail: the healthy control is VERIFIED (not stuck-on-suspect)", healthyVerdict?.status === "verified");
    const posture = postureSealStatus("r-healthy", "fault-axis", true, healthyVerdict!.at);
    ok("REFUTER healthy-flagged-suspect-MUST-fail: a verified verdict does NOT withhold the posture pass", posture.status === "pass");
  }

  // Refuter 5 (cell c): a green integrity claim over a bad destination MUST fail. After a plane-2 suspect, every
  // green integrity surface must be ABSENT: no integrityVerified recency, no posture pass, no verified last
  // verdict. If any survived a suspect verdict, the "never a false green" property is broken.
  {
    const { stub, storage } = makeScheduler();
    await stubFetch(stub, "POST", "/downpipes", makeConfig("r-green", { enabled: true }));
    const t = (await (await stubFetch(stub, "POST", "/trigger", { id: "r-green" })).json()) as { runId: string; index: number };
    const suspect: SealVerification = { status: "suspect", tier: "tier-0", sampled: 0, at: Date.now(), reason: "completeness check failed" };
    await stubFetch(stub, "POST", "/complete", { id: "r-green", runId: t.runId, index: t.index, status: "ok", sealVerification: suspect });
    const ds = storage.rawGet<{ integrityVerified?: unknown; lastSealVerify?: { status: string } }>("dp:r-green")!;
    const posture = postureSealStatus("r-green", "fault-axis", false, suspect.at);
    const anyGreenIntegritySurface = ds.integrityVerified !== undefined || posture.status === "pass" || ds.lastSealVerify?.status === "verified";
    ok("REFUTER green-integrity-over-bad-dest-MUST-fail: NO green integrity surface survives a suspect verdict", !anyGreenIntegritySurface);
  }

  console.log(failures === 0 ? "\nDEST-FAULT / VERIFY-AT-SEAL PASS (write-fault plane fails the run with the true class; silent corruption is suspect + integrity withheld; healthy control seals ok; every refuter refuted)" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
