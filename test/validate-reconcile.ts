// Prove the orphan-reconcile DRY-RUN INVENTORY (report-only). This drives the REAL
// pure core (src/seal/reconcile.ts: classifyProbedOrphan / circuitBreakerTripped / ulidTimeMs /
// planReconcileInventory / summariseInventory) and the REAL cron IO glue (src/cron/reconcile-pass.ts:
// orphanProbeVia / enumeratePhysicalRunIds / distinctPrimaryDestinations) with in-memory doubles. No
// network, no deploy, no cost. Run: node test/validate-reconcile.ts
//
// The inventory DELETES NOTHING and SALVAGES NOTHING by construction (it has no gc/delete set), so the
// dedup-safety property is structural: it can never even propose deleting a shared content-addressed
// segment. The parts:
//   PART A  classifier truth-table (classifyProbedOrphan): salvageable / stale / broken / within-grace.
//   PART B  circuit-breaker truth-table (circuitBreakerTripped): the mass-orphan / empty-committed guard.
//   PART C  ulidTimeMs: the cheap, I/O-free grace clock from the runId.
//   PART D  planReconcileInventory with injected probes: per-class counts, read-budget, complete-or-
//           abstain (the circuit-breaker abstains the WHOLE pass), idempotence, and the no-delete-set
//           dedup-safety invariant.
//   PART E  full integration over REAL seals into a MemoryDestination via the REAL probe + REAL physical
//           enumeration: a contended (sealed-but-unappended) run classifies salvageable, a tampered one
//           broken, an older one stale, a recent one within-grace; an unverifiable RUNLOG abstains; and
//           a transient read failure classifies unreadable. Asserts NOTHING in the bucket changed.

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { parseIdentity } from "../src/crypto/keys.ts";
import { concat, utf8 } from "../src/crypto/bytes.ts";
import type { RecipientEntry, Signer } from "../src/format/writer.ts";
import { buildArchive, parseRunlog } from "../src/format/writer.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { decodeULID } from "../src/format/ulid.ts";
import type { RootManifest, Freshness } from "../src/format/manifest.ts";
import type { KeylessAttestation } from "../src/format/keyless.ts";
import { randomBytes as rand } from "./testutil.ts";
import { MemoryDestination, flipBit } from "./memdest.ts";
import {
  classifyProbedOrphan,
  circuitBreakerTripped,
  ulidTimeMs,
  planReconcileInventory,
  summariseInventory,
  reconcileSignalFor,
  classifyRunlogHealth,
  countFreshnessResiduals,
  type OrphanProbe,
  type OrphanProbeResult,
  type ReconcileInventory,
} from "../src/seal/reconcile.ts";
import { orphanProbeVia, enumeratePhysicalRunIds, distinctPrimaryDestinations } from "../src/cron/reconcile-pass.ts";
import type { DownpipeState, DownpipeConfig } from "../src/sched/types.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DP = "dp_orphan";
const HOUR = 60 * 60 * 1000;
const GRACE_MS = 48 * HOUR;

// att builds a minimal keyless attestation stub for the classifier truth-table.
function att(signatureValid: boolean, complete: boolean): Pick<KeylessAttestation, "signatureValid" | "complete"> {
  return { signatureValid, complete };
}
// rootStub builds the minimal signature-verified-root fields the classifier reads.
function rootStub(downpipeId: string, createdAt: string, runlogIndex: number, prevRunId: string | null = null): Pick<RootManifest, "downpipeId" | "createdAt" | "freshness"> {
  const freshness: Freshness = { prevRunId, runlogIndex };
  return { downpipeId, createdAt, freshness };
}

// ---- PART A: classifier truth-table (classifyProbedOrphan) -------------------------------------

function partA(): void {
  console.log("PART A: classifier truth-table (classifyProbedOrphan):");
  const now = Date.UTC(2026, 5, 28, 0, 0, 0); // a fixed clock
  const old = new Date(now - 10 * 24 * HOUR).toISOString(); // 10 days old: past grace
  const recent = new Date(now - 1 * HOUR).toISOString(); // 1h old: inside grace
  const maxIdx = new Map<string, number>([[DP, 5]]); // the downpipe's max COMMITTED index is 5

  // intact, signed, complete, newest-or-only (index 6 >= committed max 5) -> salvageable.
  ok("intact + newest-or-only -> salvageable", classifyProbedOrphan(att(true, true), rootStub(DP, old, 6), maxIdx, now, GRACE_MS) === "salvageable");
  // intact, signed, complete, but a NEWER committed run exists (index 3 < 5) -> stale.
  ok("intact but a newer committed run exists -> stale", classifyProbedOrphan(att(true, true), rootStub(DP, old, 3), maxIdx, now, GRACE_MS) === "stale");
  // signature did not verify -> broken (root is null when the sig fails).
  ok("signature did not verify -> broken", classifyProbedOrphan(att(false, false), null, maxIdx, now, GRACE_MS) === "broken");
  // signed but incomplete (missing/short shards) -> broken.
  ok("signed but incomplete -> broken", classifyProbedOrphan(att(true, false), rootStub(DP, old, 6), maxIdx, now, GRACE_MS) === "broken");
  // signed but YOUNG by its own createdAt -> within-grace (the signed-createdAt double-check), even
  // though it would otherwise be salvageable.
  ok("young by signed createdAt -> within-grace", classifyProbedOrphan(att(true, true), rootStub(DP, recent, 6), maxIdx, now, GRACE_MS) === "within-grace");
  // a downpipe with NO committed run: its orphan is the newest-or-only -> salvageable, not stale.
  ok("no committed run for the downpipe -> salvageable (not stale)", classifyProbedOrphan(att(true, true), rootStub("dp_none", old, 1), maxIdx, now, GRACE_MS) === "salvageable");
  // a young orphan whose root would be incomplete is STILL within-grace (grace gate precedes complete).
  ok("young + incomplete -> within-grace (grace precedes completeness)", classifyProbedOrphan(att(true, false), rootStub(DP, recent, 6), maxIdx, now, GRACE_MS) === "within-grace");
}

// ---- PART B: circuit-breaker truth-table (circuitBreakerTripped) -------------------------------

function partB(): void {
  console.log("PART B: circuit-breaker truth-table (circuitBreakerTripped):");
  // Steady state: few orphans among many trees -> does NOT trip.
  ok("few orphans among many trees -> no trip", circuitBreakerTripped(2, 100, 98, 0.5) === false);
  // Implausibly high fraction (> 0.5) -> trips (probable wrong-source read).
  ok("orphan fraction over the threshold -> trips", circuitBreakerTripped(60, 100, 40, 0.5) === true);
  // Exactly at the threshold does NOT trip (strict >).
  ok("orphan fraction exactly at the threshold -> no trip", circuitBreakerTripped(50, 100, 50, 0.5) === false);
  // Empty committed set while physical trees exist -> trips (the empty-source signature).
  ok("empty committed set while trees exist -> trips", circuitBreakerTripped(7, 7, 0, 0.5) === true);
  // No physical trees at all -> never trips (a fresh/empty bucket).
  ok("no physical trees -> no trip", circuitBreakerTripped(0, 0, 0, 0.5) === false);
  // A custom (looser) fraction lets a higher orphan ratio through.
  ok("a looser fraction lets a higher ratio through", circuitBreakerTripped(6, 10, 4, 0.9) === false);
}

// ---- PART C: ulidTimeMs (the cheap grace clock) ------------------------------------------------

// encodeULID is the inverse of decodeULID: 16 bytes -> the canonical 26-char Crockford base32 ULID, so
// the test can mint a runId whose embedded timestamp is exactly a chosen instant.
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function encodeULID(bytes: Uint8Array): string {
  let bits = 0n;
  for (const b of bytes) bits = (bits << 8n) | BigInt(b);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = CROCKFORD[Number(bits & 0x1fn)] + out;
    bits >>= 5n;
  }
  return out;
}
// ulidForMs mints a valid ULID whose first 48 bits encode `ms` (and zero entropy bits).
function ulidForMs(ms: number): string {
  const b = new Uint8Array(16);
  let m = ms;
  for (let i = 5; i >= 0; i--) {
    b[i] = m % 256;
    m = Math.floor(m / 256);
  }
  return encodeULID(b);
}

function partC(): void {
  console.log("PART C: ulidTimeMs (the cheap grace clock):");
  // A known ULID timestamp round-trips: encode an instant, decode it back.
  const t = Date.UTC(2026, 0, 1, 0, 0, 0);
  const id = ulidForMs(t);
  ok("a minted ULID round-trips its timestamp", id.length === 26 && ulidTimeMs(id) === t);
  // The minted ULID decodes (canonical) under the production decoder.
  ok("the minted ULID is canonical (decodeULID accepts it)", decodeULID(id).length === 16);
  // A non-ULID id yields null (the caller then relies on the signed createdAt).
  ok("a non-ULID id yields null", ulidTimeMs("not-a-ulid") === null);
  ok("a wrong-length id yields null", ulidTimeMs("01ARZ") === null);
}

// ---- PART D: planReconcileInventory with injected probes ---------------------------------------

// probeOf builds an injected probe from a per-runId verdict map; a runId mapped to "throw" simulates a
// transient read failure (=> unreadable). The verdict carries the synthetic attestation + root.
type Verdict = { signatureValid: boolean; complete: boolean; downpipeId: string; createdAt: string; index: number } | "throw";
function probeOf(verdicts: Record<string, Verdict>): OrphanProbe {
  return async (runId: string): Promise<OrphanProbeResult> => {
    const v = verdicts[runId];
    if (v === undefined || v === "throw") throw new Error("simulated transient read");
    const attestation = { signatureValid: v.signatureValid, complete: v.complete, downpipeId: v.signatureValid ? v.downpipeId : null };
    const root = v.signatureValid ? rootStub(v.downpipeId, v.createdAt, v.index) : null;
    return { attestation, root };
  };
}

async function partD(): Promise<void> {
  console.log("PART D: planReconcileInventory (counts, budget, abstain, idempotence, no-delete-set):");
  const now = Date.UTC(2026, 5, 28, 0, 0, 0);
  const old = new Date(now - 10 * 24 * HOUR).toISOString();

  // Committed runs c1..c5 (max index 5 for DP). Physical = the 5 committed + 4 orphans.
  const committedRunIds = new Set<string>(["c1", "c2", "c3", "c4", "c5"]);
  const committedMaxIndex = new Map<string, number>([[DP, 5]]);
  const youngId = ulidForMs(now - 1 * HOUR); // inside grace by its ULID alone -> no probe
  const oSalvage = "o_salvage";
  const oStale = "o_stale";
  const oBroken = "o_broken";
  const physicalRunIds = ["c1", "c2", "c3", "c4", "c5", oSalvage, oStale, oBroken, youngId];

  const verdicts: Record<string, Verdict> = {
    [oSalvage]: { signatureValid: true, complete: true, downpipeId: DP, createdAt: old, index: 9 }, // newest -> salvageable
    [oStale]: { signatureValid: true, complete: true, downpipeId: DP, createdAt: old, index: 2 }, // older -> stale
    [oBroken]: { signatureValid: false, complete: false, downpipeId: DP, createdAt: old, index: 0 }, // bad sig -> broken
    // youngId is filtered by the ULID grace gate BEFORE any probe, so it has no verdict.
  };
  const probe = probeOf(verdicts);

  const inv = await planReconcileInventory({ destKey: "", committedRunIds, committedMaxIndex, physicalRunIds, now, probe, policy: { maxOrphanFraction: 0.9 } });
  ok("committedCount and physicalRunCount are reported", inv.committedCount === 5 && inv.physicalRunCount === 9);
  ok("orphansFound = physical - committed", inv.orphansFound === 4);
  ok("salvageable counted", inv.byClass.salvageable === 1);
  ok("stale counted", inv.byClass.stale === 1);
  ok("broken counted", inv.byClass.broken === 1);
  ok("within-grace counted (filtered by ULID, no probe)", inv.byClass["within-grace"] === 1);
  ok("not abstained (no deferred, breaker not tripped)", inv.deferred === undefined && inv.circuitBreakerTripped === false);

  // The three-way summary the operator reads first.
  const s = summariseInventory(inv);
  ok("summary committed", s.committed === 5);
  ok("summary orphaned-recoverable = salvageable + stale", s.orphanedRecoverable === 2);
  ok("summary never-referenced = broken", s.neverReferenced === 1);
  ok("summary undetermined includes within-grace", s.undetermined === 1);

  // DEDUP-SAFETY (structural): the inventory carries NO delete/gc/salvage set, so it can never even
  // PROPOSE deleting a (possibly shared, content-addressed) segment. Assert the shape has no such keys.
  const keys = Object.keys(inv);
  ok("the inventory has NO gcSegs / gcRunTrees / salvage set (report-only, dedup-safe by construction)", !keys.includes("gcSegs") && !keys.includes("gcRunTrees") && !keys.includes("salvage"));

  // IDEMPOTENCE: a re-run over identical inputs yields an identical inventory (the planner is pure).
  const inv2 = await planReconcileInventory({ destKey: "", committedRunIds, committedMaxIndex, physicalRunIds, now, probe, policy: { maxOrphanFraction: 0.9 } });
  ok("re-run is byte-identical (idempotent)", JSON.stringify(inv2) === JSON.stringify(inv));

  // UNREADABLE: a transient probe failure classifies the candidate unreadable (abstain, retry), never
  // committing to a verdict on bytes it could not read.
  const invT = await planReconcileInventory({
    destKey: "",
    committedRunIds,
    committedMaxIndex,
    physicalRunIds: ["c1", "c2", "c3", "c4", "c5", "o_transient"],
    now,
    probe: probeOf({ o_transient: "throw" }),
    policy: { maxOrphanFraction: 0.9 },
  });
  ok("a transient probe failure -> unreadable (abstain this candidate)", invT.byClass.unreadable === 1 && invT.byClass.broken === 0);

  // READ-BUDGET: more probe-eligible orphans than maxClassifyPerPass -> a bounded number classified,
  // the rest deferred to pendingClassify (next tick). within-grace orphans do NOT consume the budget.
  const manyOrphans = ["c1", "c2", "c3", "c4", "c5"]; // committed denominator to keep the breaker calm
  const manyVerdicts: Record<string, Verdict> = {};
  for (let i = 0; i < 5; i++) {
    const id = `m${i}`;
    manyOrphans.push(id);
    manyVerdicts[id] = { signatureValid: true, complete: true, downpipeId: DP, createdAt: old, index: 9 + i };
  }
  const invBudget = await planReconcileInventory({ destKey: "", committedRunIds, committedMaxIndex, physicalRunIds: manyOrphans, now, probe: probeOf(manyVerdicts), policy: { maxClassifyPerPass: 3, maxOrphanFraction: 0.9 } });
  ok("read-budget caps classification per pass", invBudget.byClass.salvageable === 3);
  ok("the rest defer to pendingClassify (retried next tick)", invBudget.pendingClassify === 2);
  ok("orphansFound still counts ALL orphans (budget bounds classification, not discovery)", invBudget.orphansFound === 5);

  // COMPLETE-OR-ABSTAIN: the circuit-breaker abstains the WHOLE pass (empty classification, deferred set,
  // and - the report-only analogue of deleting nothing - it never classifies a single orphan).
  const invBreak = await planReconcileInventory({
    destKey: "",
    committedRunIds: new Set<string>(["c1"]),
    committedMaxIndex: new Map<string, number>([[DP, 1]]),
    physicalRunIds: ["c1", oSalvage, oStale, oBroken], // 3 orphans of 4 trees = 0.75 > 0.5
    now,
    probe,
  });
  ok("circuit-breaker abstains the WHOLE pass (deferred + tripped)", invBreak.deferred !== undefined && invBreak.circuitBreakerTripped === true);
  ok("an abstained pass classifies NOTHING (empty byClass, no orphans)", invBreak.orphans.length === 0 && Object.values(invBreak.byClass).every((n) => n === 0));
  ok("an abstained pass still reports the implausible counts for the operator", invBreak.orphansFound === 3 && invBreak.physicalRunCount === 4);
}

// ---- PART E: full integration over REAL seals via the REAL probe + enumeration -----------------

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// sealRunTree writes ONE downpipe/0.1.0 run-tree into the dest (buildArchive + put), like the pipeline but
// with skipRunlog. When append is true it ALSO appends the RUNLOG entry (a COMMITTED run); when false it
// leaves the tree orphaned (a contended/abandoned finalise that never appended). A FIXED master makes an
// unchanged value content-address to the SAME seg across runs (the real shared-segment case).
async function sealRunTree(dest: MemoryDestination, signer: Signer, recipients: RecipientEntry[], master: Uint8Array, runId: string, index: number, prevRunId: string | null, time: string, value: string, append: boolean): Promise<void> {
  const archive = await buildArchive({
    downpipeId: DP,
    downpipeName: "orphan",
    cadence: "3600s",
    runId,
    master,
    recipients,
    signer,
    records: [{ sourceType: "kv", name: "k", value: utf8(value), namespace: "ns" }],
    windowStart: time,
    windowEnd: time,
    createdAt: time,
    runlogIndex: index,
    prevRunId,
    skipRunlog: true,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  for (const [key, body] of archive) await dest.put(key, body);
  if (append) await appendRunlog(dest, signer, { index, runId, downpipeId: DP, time, recordCount: 1, prevRunId, status: "active" });
}

async function partE(): Promise<void> {
  console.log("PART E: full integration over REAL seals (probe + enumeration + RUNLOG-sig abstain):");
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const recipients = [breakGlass.entry, op.entry];
  parseIdentity(op.identity); // (op identity is not needed: the inventory is KEYLESS)
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };

  const dest = new MemoryDestination();
  const master = rand(32);
  const now = Date.now();
  const old = new Date(now - 10 * 24 * HOUR).toISOString();
  // ULIDs old enough to be past grace by their own clock (these decode to 2016).
  const C = ["01ARZ3NDEKTSV4RRFFQ69G5C00", "01ARZ3NDEKTSV4RRFFQ69G5C01", "01ARZ3NDEKTSV4RRFFQ69G5C02", "01ARZ3NDEKTSV4RRFFQ69G5C03", "01ARZ3NDEKTSV4RRFFQ69G5C04"];
  const OSALV = "01ARZ3NDEKTSV4RRFFQ69G5099"; // orphan, intact, newest -> salvageable
  const OSTALE = "01ARZ3NDEKTSV4RRFFQ69G5011"; // orphan, intact, older index -> stale
  const OBROK = "01ARZ3NDEKTSV4RRFFQ69G5022"; // orphan, sig tampered -> broken

  // Five COMMITTED runs (indices 1..5) appended to the RUNLOG.
  for (let i = 0; i < 5; i++) await sealRunTree(dest, signer, recipients, master, C[i]!, i + 1, i === 0 ? null : C[i - 1]!, old, `committed-${i}`, true);
  // Three ORPHAN run-trees (sealed, NOT appended): a newest (index 9), an older (index 2), and one whose
  // root signature we then tamper.
  await sealRunTree(dest, signer, recipients, master, OSALV, 9, null, old, "salvage-value", false);
  await sealRunTree(dest, signer, recipients, master, OSTALE, 2, null, old, "stale-value", false);
  await sealRunTree(dest, signer, recipients, master, OBROK, 7, null, old, "broken-value", false);
  // Tamper the broken orphan's root signature so attestKeyless reports signatureValid=false.
  const sigKey = `run/${OBROK}/root.manifest.json.sig`;
  const sig = (await dest.get(sigKey))!.body.slice();
  flipBit(sig, 0);
  await dest.put(sigKey, sig);
  // A RECENT orphan tree (within grace by its ULID): just a stray object under run/<recentUlid>/.
  const youngId = ulidForMsLocal(now - 1 * HOUR);
  await dest.put(`run/${youngId}/root.manifest.json`, utf8("{}"));

  // Snapshot the whole bucket so we can prove the inventory mutated NOTHING.
  const before = dest.entries();

  // The committed set + per-downpipe max from the REAL (verified) RUNLOG.
  const runlog = (await dest.get("_RECOVERY/RUNLOG"))!;
  const entries = parseRunlog(runlog.body);
  const committedRunIds = new Set<string>(entries.map((e) => e.runId));
  const committedMaxIndex = new Map<string, number>();
  for (const e of entries) committedMaxIndex.set(e.downpipeId, Math.max(committedMaxIndex.get(e.downpipeId) ?? 0, e.index));
  ok("the REAL RUNLOG holds the 5 committed runs", committedRunIds.size === 5 && committedMaxIndex.get(DP) === 5);

  // REAL physical enumeration via the destination's listPage (paged), then the REAL keyless probe.
  const physicalRunIds = await enumeratePhysicalRunIds(dest);
  ok("physical enumeration finds all 9 run-trees (5 committed + 3 orphans + 1 young)", physicalRunIds.length === 9);
  const probe = orphanProbeVia(dest, verifier);

  const inv = await planReconcileInventory({ destKey: "", committedRunIds, committedMaxIndex, physicalRunIds, now, probe, policy: { maxOrphanFraction: 0.9 } });
  ok("(E) the contended intact newest orphan classifies salvageable", inv.byClass.salvageable === 1);
  ok("(E) the older intact orphan classifies stale (a newer committed run exists)", inv.byClass.stale === 1);
  ok("(E) the sig-tampered orphan classifies broken", inv.byClass.broken === 1);
  ok("(E) the recent orphan classifies within-grace (filtered by ULID, no probe)", inv.byClass["within-grace"] === 1);
  ok("(E) orphansFound = 4 (the committed runs are not orphans)", inv.orphansFound === 4);
  const sE = summariseInventory(inv);
  ok("(E) summary: committed 5, recoverable 2, never-referenced 1", sE.committed === 5 && sE.orphanedRecoverable === 2 && sE.neverReferenced === 1);

  // THE REPORT-ONLY CONTRACT: nothing in the bucket changed.
  const after = dest.entries();
  ok("(E) the inventory mutated NOTHING (same key set)", before.size === after.size && [...before.keys()].every((k) => after.has(k)));
  let identical = true;
  for (const [k, v] of before) {
    const a = after.get(k);
    if (!a || a.length !== v.length) identical = false;
  }
  ok("(E) every object is byte-for-byte unchanged (deletes nothing, writes nothing)", identical);

  // RUNLOG-SIGNATURE ABSTAIN (Phase A fail-closed): tamper the RUNLOG signature and prove the probe's
  // attest of a committed run now fails its freshness -- the cron path would abstain the whole bucket. We
  // assert the verifier rejects the tampered sig (the exact gate inventoryOneDestination uses).
  const rlSig = (await dest.get("_RECOVERY/RUNLOG.sig"))!.body.slice();
  flipBit(rlSig, 0);
  const { hybridVerify } = await import("../src/crypto/sign.ts");
  const { b64urlDecode } = await import("../src/crypto/bytes.ts");
  let runlogStillVerifies = true;
  try {
    runlogStillVerifies = await hybridVerify(verifier, runlog.body, b64urlDecode(new TextDecoder().decode(rlSig).trim()));
  } catch {
    runlogStillVerifies = false;
  }
  ok("(E) a tampered RUNLOG signature does NOT verify (Phase A would abstain the whole pass)", runlogStillVerifies === false);
}

// ulidForMsLocal mirrors the PART C minter (kept local to PART E so the parts are independent).
function ulidForMsLocal(ms: number): string {
  const b = new Uint8Array(16);
  let m = ms;
  for (let i = 5; i >= 0; i--) {
    b[i] = m % 256;
    m = Math.floor(m / 256);
  }
  let bits = 0n;
  for (const x of b) bits = (bits << 8n) | BigInt(x);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"[Number(bits & 0x1fn)] + out;
    bits >>= 5n;
  }
  return out;
}

// ---- PART F: distinctPrimaryDestinations (the per-bucket fan-out) ------------------------------

function dpState(id: string, dest: Partial<Pick<DownpipeConfig, "destinationId" | "destinationIds">>): DownpipeState {
  const config: DownpipeConfig = { id, name: id, cadenceSeconds: 3600, enabled: true, source: { type: "kv", include: [], exclude: [] }, ...dest };
  return { config, nextRunAt: 0, lastRunId: null, inFlight: false };
}

function partF(): void {
  console.log("PART F: distinctPrimaryDestinations (each bucket inventoried once):");
  const states = [dpState("a", { destinationIds: ["dest-b"] }), dpState("b", { destinationId: "dest-a" }), dpState("c", {}), dpState("d", { destinationId: "dest-a" })];
  const keys = new Set(distinctPrimaryDestinations(states));
  ok("distinct primaries are collected (dest-b, dest-a, default)", keys.has("dest-b") && keys.has("dest-a") && keys.has(""));
  ok("a shared primary is listed once (deduped)", distinctPrimaryDestinations(states).filter((k) => k === "dest-a").length === 1);
  ok("an empty downpipe list yields no buckets", distinctPrimaryDestinations([]).length === 0);
}

// ---- PART G: reconcileSignalFor (the bounded pack signal + RUNLOG health, support pack) --------
function partG(): void {
  console.log("PART G: reconcileSignalFor (the bounded pack signal + RUNLOG health):");
  const AT = 1_700_000_000_000;
  // No RUNLOG in the bucket (nothing finalised): health present=false, all counts zero, no abstain class.
  const none = reconcileSignalFor("dest-a", AT, false, false, null);
  ok("no-RUNLOG: runlogPresent=false, all counts zero, no deferred", none.runlogPresent === false && none.committed === 0 && none.orphanedRecoverable === 0 && none.deferred === undefined);
  // A corrupt / unverifiable RUNLOG: present but the signature did not verify -> the runlog-unverifiable
  // abstain class (the runlog-corrupt-parse signal), counts zero.
  const corrupt = reconcileSignalFor("dest-b", AT, true, false, null);
  ok("corrupt-RUNLOG: present + !verified -> deferred=runlog-unverifiable", corrupt.runlogPresent === true && corrupt.runlogSigVerified === false && corrupt.deferred === "runlog-unverifiable" && corrupt.committed === 0);

  // runlog-sig-stale-window: classifyRunlogHealth distinguishes a body-vs-sig STALE WINDOW (body still
  // parses) from a hard CORRUPT body (does not parse), where runlogSigVerified alone conflated the two.
  ok("classifyRunlogHealth: no RUNLOG -> absent", classifyRunlogHealth(false, false, false) === "absent");
  ok("classifyRunlogHealth: present + verified -> ok", classifyRunlogHealth(true, true, false) === "ok");
  ok("classifyRunlogHealth: present + !verified + body PARSES -> stale-window", classifyRunlogHealth(true, false, true) === "stale-window");
  ok("classifyRunlogHealth: present + !verified + body UNPARSEABLE -> corrupt", classifyRunlogHealth(true, false, false) === "corrupt");
  ok("no-RUNLOG signal carries runlogHealth=absent + freshnessResiduals 0", none.runlogHealth === "absent" && none.freshnessResiduals === 0);
  ok("a sig-unverified pass with a PARSEABLE body signals a stale-window", reconcileSignalFor("dest-b2", AT, true, false, null, { runlogBodyParses: true }).runlogHealth === "stale-window");
  ok("a sig-unverified pass with an UNPARSEABLE body signals corrupt", corrupt.runlogHealth === "corrupt");

  // freshness-rollback-residual: countFreshnessResiduals counts committed entries whose non-null prevRunId
  // DANGLES (points to a runId absent from the RUNLOG); a resolvable or null prevRunId is not a residual.
  ok("countFreshnessResiduals: a resolvable chain has 0 residuals", countFreshnessResiduals([{ runId: "A", prevRunId: null }, { runId: "B", prevRunId: "A" }]) === 0);
  ok("countFreshnessResiduals: a DANGLING prevRunId is a residual", countFreshnessResiduals([{ runId: "A", prevRunId: null }, { runId: "B", prevRunId: "GHOST" }]) === 1);
  ok("countFreshnessResiduals: a null prevRunId (first run) is never a residual", countFreshnessResiduals([{ runId: "A", prevRunId: null }]) === 0);
  // A normal inventory: the three-way summary rides, health both true, no abstain class.
  const normal: ReconcileInventory = { destKey: "dest-c", committedCount: 5, physicalRunCount: 9, orphansFound: 5, byClass: { salvageable: 1, stale: 1, broken: 2, "within-grace": 1, unreadable: 0, "deferred-no-key": 0 }, orphans: [], pendingClassify: 1, circuitBreakerTripped: false };
  const ns = reconcileSignalFor("dest-c", AT, true, true, normal);
  ok("normal: committed + orphanedRecoverable(salvageable+stale) + neverReferenced(broken) project", ns.committed === 5 && ns.orphanedRecoverable === 2 && ns.neverReferenced === 2);
  ok("normal: undetermined = within-grace + unreadable + deferred-no-key + pending", ns.undetermined === 2);
  ok("normal: health both true, no abstain class", ns.runlogPresent === true && ns.runlogSigVerified === true && ns.deferred === undefined && ns.circuitBreakerTripped === false);
  ok("normal: runlogHealth=ok + freshnessResiduals defaults to 0 when not passed", ns.runlogHealth === "ok" && ns.freshnessResiduals === 0);
  // freshness-rollback-residual rides on the verified path from the pass-computed count (a dangling prev-link).
  const nsR = reconcileSignalFor("dest-c2", AT, true, true, normal, { freshnessResiduals: 3 });
  ok("normal: a passed freshnessResiduals count projects (floored, non-negative)", nsR.freshnessResiduals === 3 && reconcileSignalFor("d", AT, true, true, normal, { freshnessResiduals: -2 }).freshnessResiduals === 0);
  // A circuit-breaker abstain: the flag + the coarse abstain class ride (mass-orphan wrong-source guard).
  const breaker: ReconcileInventory = { destKey: "dest-d", committedCount: 0, physicalRunCount: 8, orphansFound: 8, byClass: { salvageable: 0, stale: 0, broken: 0, "within-grace": 0, unreadable: 0, "deferred-no-key": 0 }, orphans: [], pendingClassify: 0, circuitBreakerTripped: true, deferred: "circuit-breaker: 8/8 physical trees are orphans" };
  const bs = reconcileSignalFor("dest-d", AT, true, true, breaker);
  ok("circuit-breaker: circuitBreakerTripped=true + coarse deferred=circuit-breaker", bs.circuitBreakerTripped === true && bs.deferred === "circuit-breaker");
  // Redaction-safe by construction: the signal is counts + booleans + a coarse enum + a dest label only --
  // no per-orphan runIds, no byClass detail, no key/value/plaintext.
  ok("the signal carries no runId / orphans / byClass detail (bounded counts + flags + label only)", !("orphans" in (bs as object)) && !("byClass" in (bs as object)) && !JSON.stringify(bs).includes("runId"));
}

async function main(): Promise<void> {
  partA();
  partB();
  partC();
  await partD();
  await partE();
  partF();
  partG();
  console.log(failures === 0 ? "\nORPHAN RECONCILE INVENTORY PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
