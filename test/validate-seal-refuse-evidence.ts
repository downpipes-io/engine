// Prove the SUPPORT-PACK evidence the seal subsystem records on its DATA-LOSS paths -- the refusals, the
// corrupt resumes and the lost verdicts -- and prove every byte of it is REDACTION-SAFE (NO-CUSTODY: a closed
// enum, a count, a clamped int, a boolean or a coarse class -- never a raw message, a key, an object name, a
// bucket, a token or a customer value). No network, no deploy, no live DO. Run:
//   node test/validate-seal-refuse-evidence.ts
//
// The gaps this closes:
//   Loud, self-describing refusals collapsed to a generic "run failed" -- or, worse, to a MISATTRIBUTED
//         "destination access error" that blamed the customer's bucket (and lit the map's down-destination
//         indicator) for a seal-DO handoff refusal, a fault entirely inside the engine's control plane.
//         -> coarseRunError gains seven closed classes; the refusing DO's FIXED error body is folded into a
//            closed handoff class (classifyHandoffRefusal); the body text itself never rides.
//   A corrupt checkpoint was abandoned silently: nothing said WHICH field failed, WHICH unwrap failed,
//         or how many slices of durable progress were thrown away (the mechanism behind "the big backup
//         restarts from scratch every night and never completes").
//         -> CheckpointInvalidError / CheckpointUnwrapError type the throws (messages verbatim), and the seal
//            DO records checkpoint-invalid / checkpoint-unwrap-failed / checkpoint-coerced / resume-abandoned.
//   The refuse-to-sign completeness guards' counts never reached the ring: a fan-out run that produced
//         NO ARCHIVE left only a raw message that coarsened to a generic failed row, so support could not size
//         the shortfall or tell tamper (a hash mismatch) from lifecycle eviction (a missing object).
//         -> the merge NOTES each guard into the run-observation ledger and the run-fault reporter drains it.
//   The engine COMPUTED the run's terminal outcome and lost it when the completion POST failed or was
//         refused: a perfect archive reads "abandoned", and a fully-sealed BUFFERED archive was booked FAILED
//         because postBufferedOk sat INSIDE the seal's failure catch.
//         -> postBufferedOk moved out of the catch; every lost/refused completion records completion-lost.
//   A missing RUNLOG on a destination with prior runs was silently normalised (the signed root chains
//         onto nothing and the history restarts). -> destinationLocalPrev notes runlog-absent.
//
// PART A: the seven classes, the handoff class, and the destination-misattribution fix.
// PART B: REDACTION -- customer sentinels planted in every raw message reach no returned class.
// PART C: the typed checkpoint faults, the coercion inspector, and the DO's four observe records.
// PART D: the merge's refuse-to-sign guards -> ledger -> drain -> posted seal-fault records.
// PART E: the DO's open-shard guards (the /start handoff refusal and the missing wrapped batch).
// PART F: a lost / refused completion records the computed verdict.
// PART G: an absent RUNLOG with prior runs records the history-chain restart.
// PART H  REDACTION: sanitiseSealFault is the chokepoint -- hostile values on EVERY new field are dropped.

import { coarseRunError } from "../src/seal/slice.ts";
import { classifyHandoffRefusal, HANDOFF_REFUSAL_CLASSES, isHandoffRefusalClass, sanitiseSealFault, SEAL_FAULT_KINDS } from "../src/seal/seal-faults.ts";
import { REASON_DESTINATION_ACCESS } from "../src/restore-reasons.ts";
import { downDestinationFlag } from "../src/seal/runstate-helpers.ts";
import { CHECKPOINT_FIELDS, CHECKPOINT_UNWRAP_CODES, CheckpointInvalidError, CheckpointUnwrapError, checkpointCoercions, checkpointInvalidOf, checkpointUnwrapOf } from "../src/seal/checkpoint-fault.ts";
import { unwrapMaster, validateCheckpoint, wrapMaster, zeroCounts } from "../src/seal/checkpoint.ts";
import { mergeStep, newMergeState } from "../src/seal/fanout.ts";
import { beginRunObservations, drainRunObservations, runObservations } from "../src/seal/run-observations.ts";
import { beginRunFaults, reportRunFaults } from "../src/seal/run-fault-report.ts";
import { destinationLocalPrev, noteHistoryChainRestart } from "../src/seal/pipeline.ts";
import { resetSealFaultDropTally } from "../src/seal/seal-fault-post.ts";
import { RunSealDO } from "../src/seal/runstate.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import type { Destination } from "../src/dest/types.ts";
import type { Env } from "../src/env.d.ts";
import type { SliceDeps } from "../src/seal/slice.ts";
import type { RunCheckpoint } from "../src/seal/checkpoint.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DP = "dp_huge";
const RUN = "01BX5ZZKBKACTAV9WEVGEMMVRY";

// The four customer-owned values planted INSIDE every raw fault this test throws: an email, a bucket, an
// object key and a secret. They sit exactly where a raw message would leak into the pack if a recording site
// failed to coarsen. Not one byte of any of them may reach a returned class or a recorded record.
const EMAIL = "ops@acme-corp.example";
const BUCKET = "acme-prod-backups-syd";
const OBJECT_KEY = "kv/tenants/acme/billing-2026-07.json";
const SECRET = "sk-live-CUSTOMER-TOKEN-abc123";
const SENTINELS = [EMAIL, BUCKET, OBJECT_KEY, SECRET];

// contaminated returns a string containing every sentinel: the worst-case raw message shape.
function contaminated(prefix: string): string {
  return `${prefix} [bucket=${BUCKET} key=${OBJECT_KEY} owner=${EMAIL} token=${SECRET}]`;
}

// clean asserts that not one byte of any planted sentinel appears in a recorded/returned value.
function clean(v: unknown): boolean {
  const s = JSON.stringify(v ?? null);
  return SENTINELS.every((sent) => !s.includes(sent));
}

// ---- doubles ------------------------------------------------------------------------------------

interface Call {
  path: string;
  body?: Record<string, unknown>;
}

// makeScheduler records every DO call. `completeStatus` drives three arms: 200 = the completion lands, a
// non-2xx = the scheduler REFUSED it (which never throws, so nothing sees it), "throw" = a DO outage.
function makeScheduler(completeStatus: number | "throw" = 200): { stub: DurableObjectStub; calls: Call[] } {
  const calls: Call[] = [];
  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const raw = init?.body ?? (input instanceof Request ? undefined : undefined);
      const body = raw ? (JSON.parse(String(raw)) as Record<string, unknown>) : undefined;
      calls.push({ path: url.pathname, ...(body !== undefined ? { body } : {}) });
      if (url.pathname === "/complete") {
        if (completeStatus === "throw") throw new Error(contaminated("scheduler DO unreachable"));
        return new Response("", { status: completeStatus });
      }
      if (url.pathname === "/heartbeat") return new Response(JSON.stringify({ owned: true }));
      return new Response(JSON.stringify({ ok: true }));
    },
  } as unknown as DurableObjectStub;
  return { stub, calls };
}

const sealFaults = (calls: Call[]): Record<string, unknown>[] => calls.filter((c) => c.path === "/seal-fault").map((c) => c.body ?? {});
const faultsOfKind = (calls: Call[], kind: string): Record<string, unknown>[] => sealFaults(calls).filter((f) => f.kind === kind);

// makeDOState: a Map-backed DurableObjectState (the fan-out validator's harness).
function makeDOState(): { state: DurableObjectState; storage: Map<string, unknown> } {
  const storage = new Map<string, unknown>();
  const state = {
    storage: {
      async get(key: string): Promise<unknown> {
        return storage.get(key);
      },
      async put(a: string | Record<string, unknown>, b?: unknown): Promise<void> {
        if (typeof a === "string") storage.set(a, b);
        else for (const [k, v] of Object.entries(a)) storage.set(k, v);
      },
      async delete(key: string | string[]): Promise<boolean | number> {
        if (Array.isArray(key)) {
          let n = 0;
          for (const k of key) if (storage.delete(k)) n += 1;
          return n;
        }
        return storage.delete(key);
      },
      async deleteAll(): Promise<void> {
        storage.clear();
      },
      async list<T>(opts?: { prefix?: string; startAfter?: string; limit?: number }): Promise<Map<string, T>> {
        const prefix = opts?.prefix ?? "";
        let keys = [...storage.keys()].filter((k) => k.startsWith(prefix)).sort();
        if (opts?.startAfter !== undefined) keys = keys.filter((k) => k > opts.startAfter!);
        const out = new Map<string, T>();
        for (const k of keys.slice(0, opts?.limit ?? keys.length)) out.set(k, storage.get(k) as T);
        return out;
      },
      async setAlarm(): Promise<void> {},
      async deleteAlarm(): Promise<void> {},
    },
  } as unknown as DurableObjectState;
  return { state, storage };
}

// A 64-byte signer seed in the b64url form wrapKey() demands (the checkpoint wrap key is HKDF-derived from it).
function signerSeed(fill: number): string {
  return b64urlEncode(new Uint8Array(64).fill(fill));
}

function makeDO(sched: DurableObjectStub, seed = signerSeed(7)): { obj: RunSealDO; storage: Map<string, unknown> } {
  const { state, storage } = makeDOState();
  const env = {
    SCHEDULER: { idFromName: () => ({}), get: () => sched } as unknown as DurableObjectNamespace,
    SIGNER_PRIVATE: seed,
  } as unknown as Env;
  return { obj: new RunSealDO(state, env), storage };
}

// A STORED checkpoint doc in the legacy plaintext-cursor form (so openStoredCheckpoint validates it directly,
// with no crypto): the shape the seal DO's resume path actually reads back.
function storedCheckpoint(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    downpipeId: DP,
    downpipeName: "huge",
    cadence: "86400s",
    sourceType: "kv",
    selector: { include: [], exclude: [] },
    runId: RUN,
    runlogIndex: 12,
    prevRunId: null,
    startedAt: "2026-07-01T00:00:00.000Z",
    wrappedMaster: { iv: "aaaa", ct: "bbbb" },
    cursor: null,
    sourceDone: false,
    nextRecordIndex: 41_000,
    nextShardIndex: 9,
    frontier: { count: 0, nodes: [] },
    counts: { ...zeroCounts(), records: 41_000 },
    sliceCount: 137,
    partialRecord: null,
    ...over,
  };
}

// ---- PART A: G106 -- the seven closed classes + the handoff misattribution fix -------------------
function partA(): void {
  console.log("\nPART A: self-describing refusals get their own CLOSED class (they were 'run failed'):");

  ok(
    "an over-ceiling record is 'record over the in-band size ceiling' (was: 'source read error')",
    coarseRunError(`record ${OBJECT_KEY} (6442450944 bytes) exceeds the 5368709120-byte single-invocation in-band capture limit and cannot be sealed in one slice; recover it out of band`) ===
      "record over the in-band size ceiling (recover it out of band)",
  );
  ok(
    "a source that cannot range-read is named as such, and WINS over the size branch (the actionable fact)",
    coarseRunError(`record ${OBJECT_KEY} exceeds the 268435456-byte single-segment limit and its source cannot range-read`) === "source cannot range-read (chunked capture unavailable)",
  );
  ok("a shard-id overflow is named (it was the sharpest latent archive-corruption risk, reading as 'run failed')", coarseRunError("shard id index 100000 is outside the 5-digit shard-id range [0, 100000); refusing to seal an archive whose shard ids would overflow and silently reorder the signed root") === "shard id overflow (refused to seal a misordered archive)");
  ok("a fan-out local-index overflow maps to the same class", coarseRunError("fan-out local record index 10000000000 is outside the 10-digit per-range range [0, 10000000000); refusing to mint a composite recordId") === "shard id overflow (refused to seal a misordered archive)");
  ok("a mid-record resume divergence is named", coarseRunError("mid-record resume index mismatch: partial at 902, slice at 903") === "resume state divergent (mid-record resume refused)");
  ok("an engine invariant refusal is named (an engine bug, not a customer misconfiguration)", coarseRunError("internal invariant: source reported done while a record is still mid-record-partial") === "internal invariant violated");
  ok('a non-resumable source that produced a partial maps to the invariant class', coarseRunError('a non-resumable "d1" source produced a mid-record partial, which it cannot resume') === "internal invariant violated");
  ok("an unsupported source type is a CONFIG class, not a 'source read error'", coarseRunError("unsupported source type") === "unsupported source type");

  console.log("\n  the seal-DO handoff refusal (never blames the customer's bucket):");
  // A handoff refusal must NOT be swept into the generic status catch-all -- which is the DESTINATION class, and
  // which DEST-1 turns into "this customer's bucket is down". Both halves are pinned here: the catch-all still
  // behaves that way for a real destination fault, and the handoff refusal does not reach it.
  ok("a REAL destination fault still classifies as a destination fault (the catch-all is untouched)", coarseRunError("PUT seg/0001: status 500") === REASON_DESTINATION_ACCESS);
  ok("...and DEST-1 names that destination down, as it should", JSON.stringify(downDestinationFlag(coarseRunError("PUT seg/0001: status 500"), "dest_r2_syd")) === JSON.stringify({ downDestinationIds: ["dest_r2_syd"] }));
  const legacy = "seal DO /start refused the handoff: status 500";
  ok("a handoff refusal is NO LONGER swept into that destination class (it is an engine control-plane fault)", coarseRunError(legacy) !== REASON_DESTINATION_ACCESS && coarseRunError(legacy) === "seal DO handoff refused");
  ok("...so DEST-1 no longer names the customer's bucket down for an engine-internal refusal", JSON.stringify(downDestinationFlag(coarseRunError(legacy), "dest_r2_syd")) === "{}");
  for (const cls of HANDOFF_REFUSAL_CLASSES) {
    const m = `seal DO handoff refused: ${cls}`;
    ok(`the new form classifies as 'seal DO handoff refused (${cls})'`, coarseRunError(m) === `seal DO handoff refused (${cls})`);
    ok(`...and it NO LONGER names the destination down (${cls})`, JSON.stringify(downDestinationFlag(coarseRunError(m), "dest_r2_syd")) === "{}");
  }
  ok("a DRIFTED sub-class is re-gated: it degrades to the bare class, it never rides as text", coarseRunError(`seal DO handoff refused: ${OBJECT_KEY.replace(/[^a-z-]/g, "")}`) === "seal DO handoff refused");
  ok("a worker's refused /range-done report is a handoff refusal, not a destination outage", coarseRunError("coordinator /range-done refused: status 500") === "seal DO handoff refused");

  console.log("\n  classifyHandoffRefusal reads the DO's FIXED body ONLY to select a closed member:");
  ok("a refused open-shard handoff -> invalid-payload", classifyHandoffRefusal(400, "open-shard buffer does not match the checkpoint count") === "invalid-payload");
  ok("a refused worker spawn -> worker-spawn-refused", classifyHandoffRefusal(500, "fan-out worker spawn refused") === "worker-spawn-refused");
  ok("a 400 with no body -> invalid-payload", classifyHandoffRefusal(400) === "invalid-payload");
  ok("a 500 with no body -> do-error", classifyHandoffRefusal(500) === "do-error");
  ok("a thrown fetch (status 0) -> unreachable", classifyHandoffRefusal(0) === "unreachable");
  ok("EVERY returned value is a member of the closed vocabulary", [classifyHandoffRefusal(400), classifyHandoffRefusal(500), classifyHandoffRefusal(0), classifyHandoffRefusal(503, contaminated("hostile"))].every(isHandoffRefusalClass));
  ok("a HOSTILE body cannot invent a class (it falls to do-error, and its bytes do not ride)", classifyHandoffRefusal(503, contaminated("hostile")) === "do-error");
}

// ---- PART B: G106 REDACTION ---------------------------------------------------------------------
function partB(): void {
  console.log("\nPART B: REDACTION -- customer sentinels planted in every raw refusal reach no class:");
  const messages = [
    contaminated("record exceeds the 5368709120-byte single-invocation in-band capture limit"),
    contaminated("exceeds the 268435456-byte single-segment limit and its source cannot range-read"),
    contaminated("shard id index 100000 is outside the 5-digit shard-id range"),
    contaminated("mid-record resume index mismatch: partial at 1, slice at 2"),
    contaminated("internal invariant: source reported done"),
    contaminated("unsupported source type"),
    contaminated("seal DO handoff refused: do-error"),
  ];
  for (const m of messages) {
    const cls = coarseRunError(m);
    ok(`the class of a contaminated message carries NO sentinel: ${cls}`, clean(cls));
  }
  ok("every class the new branches return is a bounded, human-readable engine string (no interpolation)", messages.every((m) => coarseRunError(m).length < 80));
}

// ---- PART C: G107 -- the typed checkpoint faults + the DO's observes -----------------------------
async function partC(): Promise<void> {
  console.log("\nPART C: a corrupt checkpoint names the FIELD, the UNWRAP and the PROGRESS it discards:");

  // C1: validateCheckpoint types each refusal with its CLOSED field (the message stays verbatim).
  const cases: { over: Record<string, unknown>; field: string }[] = [
    { over: { v: 2 }, field: "version" },
    { over: { runId: 7 }, field: "identity" },
    { over: { wrappedMaster: { iv: 1 } }, field: "wrapped-master" },
    { over: { nextShardIndex: "9" }, field: "progress" },
    { over: { cursor: 42 }, field: "cursor" },
    { over: { frontier: { count: "0", nodes: [] } }, field: "frontier" },
    { over: { counts: { ...zeroCounts(), records: "many" } }, field: "counts" },
    { over: { partialRecord: { recordIndex: 1, offsetSealed: -5, meta: {}, segments: [] } }, field: "partial-record" },
    { over: { openShard: { count: -1 } }, field: "open-shard" },
    { over: { rangeIndex: -3 }, field: "range-index" },
  ];
  for (const c of cases) {
    let field: string | null = null;
    let stillAnError = false;
    try {
      validateCheckpoint(storedCheckpoint(c.over));
    } catch (e) {
      field = checkpointInvalidOf(e);
      stillAnError = e instanceof Error && (e as Error).message.length > 0;
    }
    ok(`a malformed '${c.field}' is typed with that CLOSED field (and stays a loud Error)`, field === c.field && stillAnError);
  }
  ok("every field a throw carries is a member of CHECKPOINT_FIELDS", cases.every((c) => (CHECKPOINT_FIELDS as readonly string[]).includes(c.field)));

  // C2: the unwrap sub-codes -- a SIGNER ROTATION and a corrupted write are different investigations.
  const master = new Uint8Array(32).fill(3);
  const wrapped = await wrapMaster(signerSeed(1), RUN, master);
  let code: string | null = null;
  try {
    await unwrapMaster(signerSeed(2), RUN, wrapped); // a DIFFERENT signer: the rotation-strands-runs case
  } catch (e) {
    code = checkpointUnwrapOf(e);
  }
  ok("a checkpoint wrapped under a PRIOR signer types as 'master-unwrap' (the rotation strand)", code === "master-unwrap");
  const short = await wrapMaster(signerSeed(1), RUN, new Uint8Array(16).fill(9)); // a corrupted 16-byte master
  let shortCode: string | null = null;
  try {
    await unwrapMaster(signerSeed(1), RUN, short);
  } catch (e) {
    shortCode = checkpointUnwrapOf(e);
  }
  ok("an AEAD that SUCCEEDS onto a non-32-byte master types as 'wrong-length' (a corrupt write, NOT a rotation)", shortCode === "wrong-length");
  ok("both codes are members of CHECKPOINT_UNWRAP_CODES", (CHECKPOINT_UNWRAP_CODES as readonly string[]).includes(code ?? "") && (CHECKPOINT_UNWRAP_CODES as readonly string[]).includes(shortCode ?? ""));
  ok("neither typed error carries a sentinel (no key, no ciphertext, no plaintext)", clean(new CheckpointUnwrapError("master-unwrap", "x").message) && clean(new CheckpointInvalidError("counts", "x").message));

  // C3: the coercion inspector -- a LEGACY doc and a CORRUPTED doc are no longer identical.
  const legacyDoc = storedCheckpoint({ counts: { records: 5, bytes: 5, objectsWritten: 1, objectsSkipped: 0, archiveBytesWritten: 5, recordsSkippedChanged: 0, durationMs: 1, opCounts: {} } });
  const corruptDoc = storedCheckpoint({ counts: { ...zeroCounts(), recordsIncomplete: "lots", incompleteByMarker: "[object Object]" } });
  const legacyC = checkpointCoercions(legacyDoc);
  const corruptC = checkpointCoercions(corruptDoc);
  ok("a LEGACY doc's absent counters are reported as legacyAbsent:true (benign, forward-compatible)", legacyC.length === 4 && legacyC.every((c) => c.legacyAbsent));
  ok("a CORRUPTED doc's present-but-malformed counters are legacyAbsent:false (a miscounted archive waiting)", corruptC.length === 2 && corruptC.every((c) => !c.legacyAbsent));
  ok("a clean, current-format doc reports NO coercion at all (the healthy steady state is silence)", checkpointCoercions(storedCheckpoint()).length === 0);

  // C4: THE WIRING. The seal DO's resume path must OBSERVE all of it into the ring.
  console.log("\n  the seal DO's resume path posts the evidence to the ring (the pack read path: GET /seal-faults):");
  const sched = makeScheduler();
  const { obj } = makeDO(sched.stub);
  const badDoc = { config: { id: DP, name: "huge" }, checkpoint: storedCheckpoint({ nextShardIndex: "nine" }), attempt: 0 };
  let threw = false;
  try {
    await (obj as unknown as { openCheckpointForResume(s: DurableObjectStub, k: string, d: unknown): Promise<unknown> }).openCheckpointForResume(sched.stub, signerSeed(7), badDoc);
  } catch {
    threw = true;
  }
  ok("the corrupt resume still fails LOUDLY (the observe is additive: it never rescues a bad checkpoint)", threw);
  const invalid = faultsOfKind(sched.calls, "checkpoint-invalid")[0];
  ok("a 'checkpoint-invalid' record lands, naming the CLOSED field", invalid !== undefined && invalid.checkpointField === "progress" && invalid.downpipeId === DP && invalid.runId === RUN);
  const abandoned = faultsOfKind(sched.calls, "resume-abandoned")[0];
  ok("a 'resume-abandoned' record SIZES the loss: 137 slices and 41000 records thrown away", abandoned !== undefined && abandoned.slicesDiscarded === 137 && abandoned.recordsDiscarded === 41_000);
  ok("every posted record is redaction-clean", clean(sealFaults(sched.calls)));

  const sched2 = makeScheduler();
  const { obj: obj2 } = makeDO(sched2.stub, signerSeed(2));
  const rotated = { config: { id: DP, name: "huge" }, checkpoint: storedCheckpoint({ wrappedMaster: wrapped }), attempt: 0 };
  try {
    await (obj2 as unknown as { openCheckpointForResume(s: DurableObjectStub, k: string, d: unknown): Promise<unknown> }).openCheckpointForResume(sched2.stub, signerSeed(2), rotated);
  } catch {
    /* expected: the checkpoint was wrapped under signer 1 */
  }
  const unwrapFault = faultsOfKind(sched2.calls, "checkpoint-unwrap-failed")[0];
  ok("a signer-rotation strand posts 'checkpoint-unwrap-failed' with unwrapCode 'master-unwrap'", unwrapFault !== undefined && unwrapFault.unwrapCode === "master-unwrap");
  ok("...and the resume-abandoned discard rides with it", faultsOfKind(sched2.calls, "resume-abandoned").length === 1);

  const sched3 = makeScheduler();
  const { obj: obj3 } = makeDO(sched3.stub);
  try {
    await (obj3 as unknown as { openCheckpointForResume(s: DurableObjectStub, k: string, d: unknown): Promise<unknown> }).openCheckpointForResume(sched3.stub, signerSeed(7), { config: { id: DP, name: "huge" }, checkpoint: corruptDoc, attempt: 0 });
  } catch {
    /* the corrupt counters are COERCED, not rejected: this doc opens fine */
  }
  const coerced = faultsOfKind(sched3.calls, "checkpoint-coerced")[0];
  ok("a CORRUPTED counter is recorded as checkpoint-coerced with legacyAbsent:false (it is not a legacy default)", coerced !== undefined && coerced.legacyAbsent === false && coerced.coerced === 2);
}

// ---- PART D: G108 -- the merge's refuse-to-sign guards reach the ring ----------------------------

// MemDest: the minimal Destination the merge reads. `drop` removes an object (the lifecycle-eviction case);
// `corrupt` rewrites its bytes (the tamper case). Both raise the refusals whose counts must reach the ring.
function memDest(objects: Map<string, Uint8Array>): Destination {
  return {
    async get(key: string) {
      const body = objects.get(key);
      return body === undefined ? null : { body, etag: "e" };
    },
    async put(key: string, body: Uint8Array) {
      objects.set(key, body);
      return { ok: true };
    },
    async putConditional() {
      return { ok: true };
    },
    async delete() {},
    async list() {
      return { keys: [], truncated: false };
    },
  } as unknown as Destination;
}

// The merge's finalise path seals a parity shard and signs a root, so the count guards are only REACHABLE
// with a real signer + recipient. Built once (the validate-fanout harness, trimmed).
let SIGNER: Signer;
let RECIPIENTS: RecipientEntry[];
async function buildKeys(): Promise<void> {
  SIGNER = await loadSigner(b64urlEncode(concat(new Uint8Array(32).fill(4), new Uint8Array(32).fill(5))));
  const xk = x25519.keygen();
  RECIPIENTS = [{ role: "break-glass", pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(new Uint8Array(64).fill(6)).encapKey } }];
}

function mergeDeps(dest: Destination): SliceDeps {
  return {
    dest,
    signer: SIGNER,
    recipients: RECIPIENTS,
    budget: new SliceBudget({ subrequests: 700, wallMs: 60_000 }),
    nowIso: () => "2026-07-01T00:00:05.000Z",
    randomNonce: () => new Uint8Array(16).fill(7),
    randomSalt: () => new Uint8Array(16).fill(9),
  } as unknown as SliceDeps;
}

function mergeCp(records: number): RunCheckpoint {
  return {
    v: 1,
    downpipeId: DP,
    downpipeName: "huge",
    cadence: "86400s",
    sourceType: "kv",
    selector: { include: [], exclude: [] },
    runId: RUN,
    runlogIndex: 3,
    prevRunId: null,
    startedAt: "2026-07-01T00:00:00.000Z",
    wrappedMaster: { iv: "", ct: "" },
    cursor: null,
    sourceDone: true,
    nextRecordIndex: records,
    nextShardIndex: 0,
    frontier: { count: 0, nodes: [] },
    counts: { ...zeroCounts(), records },
    sliceCount: 1,
    partialRecord: null,
  } as unknown as RunCheckpoint;
}

async function partD(): Promise<void> {
  console.log("\nPART D: the merge REFUSED TO SIGN (no archive at all) and the counts now reach the ring:");

  // D1: a scratch shard the destination no longer holds -- the lifecycle-eviction / never-written case.
  beginRunObservations();
  const dest = memDest(new Map()); // every scratch object is GONE
  const scratch = [
    { id: "0000000000", object: "run/x/shard/0.dpe", sha384: "aa" },
    { id: "0000000001", object: "run/x/shard/1.dpe", sha384: "bb" },
    { id: "0000100000", object: "run/x/shard/2.dpe", sha384: "cc" },
  ];
  let missingLoud = false;
  try {
    await mergeStep(mergeDeps(dest), mergeCp(9), new Uint8Array(32), newMergeState(scratch), []);
  } catch (e) {
    missingLoud = /is missing; refusing to sign a truncated archive/.test((e as Error).message);
  }
  ok("a missing scratch shard still REFUSES TO SIGN, loudly (the guard is unchanged)", missingLoud);
  const obs = drainRunObservations();
  const note = obs.completeness[0];
  ok("...and it is NOTED as 'scratch-shard-missing' with found=0 merged of expected=3 (the shortfall is sized)", note !== undefined && note.kind === "scratch-shard-missing" && note.found === 0 && note.expected === 3 && note.ordinal === 0);

  // D2: a scratch shard whose bytes CHANGED -- corruption/tamper, which read identically to a missing one.
  beginRunObservations();
  const objs = new Map<string, Uint8Array>([["run/x/shard/0.dpe", new Uint8Array([1, 2, 3])]]);
  let hashLoud = false;
  try {
    await mergeStep(mergeDeps(memDest(objs)), mergeCp(9), new Uint8Array(32), newMergeState([{ id: "0000000000", object: "run/x/shard/0.dpe", sha384: "not-the-reported-hash" }]), []);
  } catch (e) {
    hashLoud = /hash does not match the worker report/.test((e as Error).message);
  }
  const hashNote = runObservations().completeness[0];
  ok("a scratch shard whose BYTES CHANGED is a DIFFERENT kind ('scratch-hash-mismatch': tamper, not eviction)", hashLoud && hashNote !== undefined && hashNote.kind === "scratch-hash-mismatch");

  // D3: THE DRAIN. The ledger is nothing unless the reporter posts it -- that is the whole gap.
  const sched = makeScheduler();
  await reportRunFaults(sched.stub, DP);
  const posted = faultsOfKind(sched.calls, "scratch-hash-mismatch")[0];
  ok("the run-fault reporter DRAINS it onto the ring (POST /seal-fault -> the pack's sealFaults[])", posted !== undefined && posted.downpipeId === DP && posted.found === 0 && posted.expected === 1);
  ok("the posted record carries no object key, no bucket and no message", clean(sealFaults(sched.calls)));

  // D4: the count guards -- merged-vs-declared and encountered-vs-counted.
  beginRunObservations();
  let countLoud = false;
  try {
    // A run declaring 500 records whose scratch set is EMPTY: the merge finds 0 and refuses the count.
    await mergeStep(mergeDeps(memDest(new Map())), mergeCp(500), new Uint8Array(32), newMergeState([]), []);
  } catch (e) {
    countLoud = /refusing to sign a count the shards do not hold/.test((e as Error).message);
  }
  const countNote = runObservations().completeness[0];
  ok("a merged-vs-declared mismatch refuses to sign AND records found=0 / expected=500", countLoud && countNote !== undefined && countNote.kind === "merge-count-mismatch" && countNote.found === 0 && countNote.expected === 500);

  beginRunObservations();
  let underLoud = false;
  try {
    // A SCAN-planned run: the count pass found 900 in-scope keys, the workers encountered 0.
    await mergeStep(mergeDeps(memDest(new Map())), mergeCp(0), new Uint8Array(32), newMergeState([], 900), []);
  } catch (e) {
    underLoud = /refusing to sign a run short of its authoritative key count/.test((e as Error).message);
  }
  const underNote = runObservations().completeness.find((c) => c.kind === "under-crawl");
  ok("an UNDER-CRAWL refuses to sign AND records encountered=0 / counted=900 (the delta that tells bulk-delete from a dropped range)", underLoud && underNote !== undefined && underNote.found === 0 && underNote.expected === 900);
  beginRunObservations();
}

// ---- PART E: G108 -- the DO's own open-shard completeness guards ---------------------------------
async function partE(): Promise<void> {
  console.log("\nPART E: the seal DO's open-shard guards (the handoff refusal and the lost batch):");

  const sched = makeScheduler();
  const { obj } = makeDO(sched.stub);
  // A handoff whose checkpoint declares 4 buffered lines and carries NONE: the DO refuses it (400).
  const resp = await obj.fetch(
    new Request("https://runseal.internal/start", {
      method: "POST",
      body: JSON.stringify({ config: { id: DP, name: "huge" }, checkpoint: { ...storedCheckpoint({ openShard: { count: 4 } }), cursor: null }, shards: [], openShardLines: [] }),
      headers: { "content-type": "application/json" },
    }),
  );
  ok("the DO still REFUSES the inconsistent handoff (400): the guard is unchanged", resp.status === 400);
  const mismatch = faultsOfKind(sched.calls, "open-shard-count-mismatch")[0];
  ok("...and now records open-shard-count-mismatch found=0 / expected=4 (the run died before a single slice)", mismatch !== undefined && mismatch.found === 0 && mismatch.expected === 4 && mismatch.downpipeId === DP);

  const sched2 = makeScheduler();
  const { obj: obj2 } = makeDO(sched2.stub);
  // A live open-shard range [0,3) with NO wrapped batches in storage: DO storage lost the rows.
  let batchLoud = false;
  try {
    await (obj2 as unknown as { loadOpenLines(k: string, r: string, a: number, b: number, d?: string): Promise<unknown> }).loadOpenLines(signerSeed(7), RUN, 0, 3, DP);
  } catch (e) {
    batchLoud = /is missing from the live range/.test((e as Error).message);
  }
  const batch = faultsOfKind(sched2.calls, "open-batch-missing")[0];
  ok("a wrapped open-shard batch missing from the LIVE range still fails loud, and records found=0 / expected=3", batchLoud && batch !== undefined && batch.found === 0 && batch.expected === 3 && batch.runId === RUN);
  ok("every DO-side completeness record is redaction-clean", clean(sealFaults(sched.calls)) && clean(sealFaults(sched2.calls)));
}

// ---- PART F: G109 -- a lost or refused verdict is recorded ---------------------------------------
async function partF(): Promise<void> {
  console.log("\nPART F: the engine COMPUTED the terminal outcome and the completion POST did not land:");

  // F1: the scheduler REFUSES the ok completion (a non-2xx). It never throws, so nothing sees it unless recorded:
  // the archive is complete, the run row later resolves as a generic "abandoned", and the pack contradicts the
  // bucket. This is the "run shows abandoned but the archive restores fine" ticket.
  const refuse = makeScheduler(503);
  const { obj } = makeDO(refuse.stub);
  const cp = { ...storedCheckpoint(), counts: { ...zeroCounts(), records: 41_000 } };
  await (obj as unknown as { complete(s: DurableObjectStub, c: unknown, st: string, o?: unknown): Promise<void> }).complete(refuse.stub, cp, "ok", { destinationId: "dest_r2_syd" });
  const lostOk = faultsOfKind(refuse.calls, "completion-lost")[0];
  ok("a REFUSED ok completion records completion-lost{outcome:ok} (never silently vanishes)", lostOk !== undefined && lostOk.outcome === "ok" && lostOk.runId === RUN && lostOk.downpipeId === DP);

  // F2: a FAILED verdict lost to a scheduler-DO outage: the run's real cause dies with the POST and the row
  // resolves as a generic "abandoned" -- "we lost track of it" instead of "it failed for THIS reason".
  const outage = makeScheduler("throw");
  const { obj: obj2 } = makeDO(outage.stub);
  const doc = { config: { id: DP, name: "huge" }, checkpoint: cp, attempt: 7, pressure: undefined };
  await (obj2 as unknown as { handleHardFault(s: DurableObjectStub, d: unknown, m: string): Promise<void> }).handleHardFault(outage.stub, doc, contaminated("PUT seg/0001 failed: status 403 AccessDenied"));
  const lostFailed = faultsOfKind(outage.calls, "completion-lost")[0];
  ok("a LOST failed completion records completion-lost{outcome:failed}", lostFailed !== undefined && lostFailed.outcome === "failed");
  ok("...carrying the CLOSED coarse class (never the raw message) and the 12-hex cause digest", Array.isArray(lostFailed?.attemptClasses) && (lostFailed.attemptClasses as string[]).length === 1 && /^[0-9a-f]{12}$/.test(String(lostFailed?.causeDigest)));
  ok("the raw fault carried a bucket, an object key, an email AND a token: not one byte reached the record", clean(sealFaults(outage.calls)));
}

// ---- PART G: G283 -- an absent RUNLOG with prior runs --------------------------------------------
async function partG(): Promise<void> {
  console.log("\nPART G: a downpipe repointed at a RE-CREATED or WRONG bucket restarts its history chain:");

  const empty = memDest(new Map()); // the destination holds NO RUNLOG at all
  ok("the behaviour is UNCHANGED: with no RUNLOG there is nothing to chain onto (prevRunId stays null)", (await destinationLocalPrev(empty, DP, 12)) === null);

  // THE PRECISION. An absent RUNLOG on its own is NOT evidence: a brand-new downpipe's first run on a fresh
  // bucket reads identically, and so does a run whose index merely advanced past failed attempts. The signal is
  // "the SCHEDULER says a prior run SUCCEEDED (prevRunId), and this destination has no entry for it".
  beginRunFaults();
  noteHistoryChainRestart(null, null, 12); // no prior SUCCESSFUL run: a genuine first seal here
  const sched0 = makeScheduler();
  await reportRunFaults(sched0.stub, DP);
  ok("a downpipe with NO prior successful run records nothing (a fresh bucket is not an incident)", faultsOfKind(sched0.calls, "runlog-absent").length === 0);

  beginRunFaults();
  noteHistoryChainRestart(null, "01ARZ3NDEKTSV4RRFFQ69G5FA0", 12); // run 12 succeeded; this bucket has no entry
  const sched = makeScheduler();
  await reportRunFaults(sched.stub, DP);
  const absent = faultsOfKind(sched.calls, "runlog-absent")[0];
  ok("a prior run SUCCEEDED but the destination has no RUNLOG entry: runlog-absent{priorRuns:12, historyChainRestarted:true}", absent !== undefined && absent.priorRuns === 12 && absent.historyChainRestarted === true && absent.downpipeId === DP);
  ok("the record carries no bucket, no key and no run-tree path", clean(sealFaults(sched.calls)));

  beginRunFaults();
  noteHistoryChainRestart("01ARZ3NDEKTSV4RRFFQ69G5FA0", "01ARZ3NDEKTSV4RRFFQ69G5FA0", 12); // the healthy chain
  const sched2 = makeScheduler();
  await reportRunFaults(sched2.stub, DP);
  ok("a healthy chain (the prior entry IS on this destination) records nothing at all", faultsOfKind(sched2.calls, "runlog-absent").length === 0);
}

// ---- PART H: REDACTION -- sanitiseSealFault is the one chokepoint --------------------------------
function partH(): void {
  console.log("\nPART H: REDACTION -- sanitiseSealFault DROPS hostile values on every new field:");

  const hostile = sanitiseSealFault(
    {
      kind: "checkpoint-invalid",
      at: 1,
      downpipeId: DP,
      runId: RUN,
      checkpointField: contaminated("cursor"), // an out-of-vocabulary field carrying every sentinel
      unwrapCode: OBJECT_KEY,
      coerced: Number.NaN,
      legacyAbsent: SECRET,
      slicesDiscarded: -50,
      recordsDiscarded: "41000",
      priorRuns: 1e30,
      historyChainRestarted: BUCKET,
    },
    1,
  );
  ok("a hostile checkpointField is DROPPED (not coerced, not carried as text)", hostile !== null && hostile.checkpointField === undefined);
  ok("a hostile unwrapCode is DROPPED", hostile?.unwrapCode === undefined);
  ok("a NaN count clamps to 0 and raises the countsMalformed sentinel (a clamp is not a measurement)", hostile?.coerced === 0 && hostile?.countsMalformed === true);
  ok("a truthy non-boolean legacyAbsent becomes a STRICT false", hostile?.legacyAbsent === false);
  ok("a negative slicesDiscarded clamps to 0; a string recordsDiscarded clamps to 0", hostile?.slicesDiscarded === 0 && hostile?.recordsDiscarded === 0);
  ok("an absurd priorRuns is bounded", typeof hostile?.priorRuns === "number" && hostile.priorRuns <= 1_000_000_000);
  ok("a non-boolean historyChainRestarted becomes a STRICT false", hostile?.historyChainRestarted === false);
  ok("NOT ONE SENTINEL survives into the recorded record", clean(hostile));

  const good = sanitiseSealFault({ kind: "resume-abandoned", at: 5, downpipeId: DP, runId: RUN, slicesDiscarded: 137, recordsDiscarded: 41_000 }, 5);
  ok("a well-formed record round-trips its counts intact", good?.slicesDiscarded === 137 && good?.recordsDiscarded === 41_000);
  for (const k of ["checkpoint-invalid", "checkpoint-coerced", "resume-abandoned", "scratch-shard-missing", "scratch-hash-mismatch", "scratch-preamble-mismatch", "merge-count-mismatch", "under-crawl", "open-shard-count-mismatch", "open-batch-missing", "completion-lost", "runlog-absent"]) {
    ok(`'${k}' is a member of the CLOSED ring vocabulary (the DO re-gates every kind)`, (SEAL_FAULT_KINDS as readonly string[]).includes(k) && sanitiseSealFault({ kind: k, at: 1 }, 1) !== null);
  }
  ok("an out-of-vocabulary kind is still DROPPED entirely", sanitiseSealFault({ kind: contaminated("checkpoint-invalid"), at: 1 }, 1) === null);
}

async function main(): Promise<void> {
  console.log("validate-seal-refuse-evidence: the seal subsystem's DATA-LOSS evidence");
  resetSealFaultDropTally();
  await buildKeys();
  partA();
  partB();
  await partC();
  await partD();
  await partE();
  await partF();
  await partG();
  partH();
  console.log(failures === 0 ? "\nAll seal refuse/resume/completion evidence checks passed." : `\n${failures} check(s) FAILED.`);
  if (failures > 0) process.exitCode = 1;
  process.exit(failures === 0 ? 0 : 1);
}

void main();
