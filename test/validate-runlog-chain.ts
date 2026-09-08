// Cross-implementation parity for the RUNLOG freshness chain (SPEC 10, 8.7):
// the TS engine reader must accept and reject the same chain shapes the Go reader does
// even when the RUNLOG is validly signed and the restored run agrees with the signed root.
// This drives the REAL production checkRunlogFreshness (src/format/freshness.ts) with a
// genuine hybrid signature so the signature gate passes and the chain check is what fires,
// mirroring the Go reader's TestCheckFreshnessAllocationGapAccepted and
// TestCheckFreshnessChainAnomalies under the amended SPEC 10 (per-downpipe prevRunId
// linearity replaced index contiguity; indices are account-globally allocated and a failed
// run consumes one without appending an entry, so an index gap is benign):
//   - a well-linked chain (with a retained superseded predecessor) passes clean,
//   - a benign allocation gap (1 then 3, linear prevRunId) is ACCEPTED, with and without
//     an interleaving second downpipe holding the missing index,
//   - a linearity break (an entry chaining to its grandparent while the parent remains
//     present) is rejected as a rewritten chain,
//   - a dangling prevRunId is rejected as a rewritten chain,
//   - a forked prevRunId (two entries sharing a predecessor across downpipes) is rejected,
//   - interleaved line order is accepted (concurrent finalises) and a duplicated
//     index is rejected as a corrupted or hand-assembled log,
//   - and --allow-stale acknowledges each anomaly rather than throwing.
//
// If the chain-anomaly detection is removed from the production reader, the rejection
// assertions below FAIL (they would pass freshness with ok:true); if index contiguity is
// reintroduced, the allocation-gap acceptances FAIL. Run:
//   node test/validate-runlog-chain.ts
// In-memory doubles only; no network, no deploy, no cost.

import { mldsaKeygen } from "../src/crypto/pq.ts";
import { signRunlog, type RunlogEntry } from "../src/format/writer.ts";
import { checkRunlogFreshness, type FreshnessOptions } from "../src/format/freshness.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import type { RootManifest } from "../src/format/manifest.ts";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";

const DP = "dp";
const DP2 = "dp_other";
const R1 = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const R2 = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
const R3 = "01ARZ3NDEKTSV4RRFFQ69G5FC1";
const OX = "01ARZ3NDEKTSV4RRFFQ69G5FD2";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// entry builds one RUNLOG line with the exact field set the format requires; entryFor
// builds the same line for a second downpipe (the interleave and cross-downpipe shapes).
function entry(index: number, runId: string, prevRunId: string | null, status: string): RunlogEntry {
  return { index, runId, downpipeId: DP, time: `t${index}`, recordCount: 1, prevRunId, status };
}
function entryFor(downpipeId: string, index: number, runId: string, prevRunId: string | null, status: string): RunlogEntry {
  return { index, runId, downpipeId, time: `t${index}`, recordCount: 1, prevRunId, status };
}

// signerCtx holds the Ed25519 private CryptoKey and the ML-DSA secret used to sign the
// RUNLOG, plus the matching public verifier the production check is pinned to.
interface SignerCtx {
  edPrivate: CryptoKey;
  mldsaSecret: Uint8Array;
  verifier: HybridVerifier;
}

async function makeSigner(): Promise<SignerCtx> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, mldsaSecret: mldsa.secretKey, verifier: { ed: edPublic, mldsa: mldsa.publicKey } };
}

// storeFor signs the entries with the pinned signer and returns an ObjectStore that serves
// the signed RUNLOG and its base64url signature text exactly as the in-account destination
// would, so checkRunlogFreshness exercises its real signature + parse + chain path.
async function storeFor(signer: SignerCtx, entries: RunlogEntry[]): Promise<ObjectStore> {
  const { runlog, sig } = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
  const objects = new Map<string, Uint8Array>([
    ["_RECOVERY/RUNLOG", runlog],
    ["_RECOVERY/RUNLOG.sig", utf8(b64urlEncode(sig))],
  ]);
  return {
    get: async (k: string) => {
      const v = objects.get(k);
      if (!v) throw new Error(`missing ${k}`);
      return v;
    },
  };
}

// rootFor builds the minimal RootManifest the freshness check reads: the downpipe id and the
// signed freshness anchor (the restored run's own index and prevRunId).
function rootFor(runlogIndex: number, prevRunId: string | null): RootManifest {
  return { downpipeId: DP, freshness: { runlogIndex, prevRunId } } as unknown as RootManifest;
}

async function check(signer: SignerCtx, entries: RunlogEntry[], runId: string, root: RootManifest, opts: FreshnessOptions = {}) {
  const store = await storeFor(signer, entries);
  return checkRunlogFreshness(store, runId, root, signer.verifier, opts);
}

async function proofWellLinked(signer: SignerCtx): Promise<void> {
  // ---- A 1->2->3 chain, restoring the latest run, passes clean ----
  // The retained superseded predecessors (1 and 2) prove a correctly pruned chain does not
  // false-positive the linearity or dangling checks.
  const good = [entry(1, R1, null, "superseded"), entry(2, R2, R1, "superseded"), entry(3, R3, R2, "active")];
  const okRes = await check(signer, good, R3, rootFor(3, R2));
  ok("well-linked chain passes (ok:true)", okRes.ok === true);
  ok("well-linked chain reports the latest run for the downpipe", okRes.isLatestForDownpipe === true && okRes.maxIndexForDownpipe === 3);
  ok("well-linked chain raises no reason", okRes.reason === undefined);
}

async function proofAllocGap(signer: SignerCtx): Promise<void> {
  // ---- A benign allocation gap (index 2 never appended) is ACCEPTED ----
  // Indices come from one account-global counter and an entry is appended only on a
  // successful finalise, so a failed run leaves exactly this hole; the prevRunId chain is
  // linear (3 chains to 1), so the document is well-formed (SPEC 10). A reader that still
  // enforces per-downpipe index contiguity rejects this, so the acceptance fails closed
  // against that regression.
  const allocGap = [entry(1, R1, null, "superseded"), entry(3, R3, R1, "active")];
  const gapRes = await check(signer, allocGap, R3, rootFor(3, R1));
  ok("benign allocation gap is accepted (ok:true)", gapRes.ok === true);
  ok("benign allocation gap reports the latest run", gapRes.isLatestForDownpipe === true && gapRes.maxIndexForDownpipe === 3);
  ok("benign allocation gap raises no reason", gapRes.reason === undefined);
}

async function proofInterleaved(signer: SignerCtx): Promise<void> {
  // ---- An interleaving second downpipe holding index 2 is ACCEPTED ----
  // The production shape of the global allocator: dp holds 1 and 3, dp_other holds 2, and
  // each downpipe's own prevRunId chain is linear.
  const interleaved = [entry(1, R1, null, "superseded"), entryFor(DP2, 2, OX, null, "active"), entry(3, R3, R1, "active")];
  const interRes = await check(signer, interleaved, R3, rootFor(3, R1));
  ok("interleaved two-downpipe runlog is accepted (ok:true)", interRes.ok === true);
  ok("interleaved runlog reports the latest run for the restored downpipe", interRes.isLatestForDownpipe === true && interRes.maxIndexForDownpipe === 3);
  ok("interleaved runlog raises no reason", interRes.reason === undefined);
}

async function proofLinearityBreak(signer: SignerCtx): Promise<void> {
  // ---- A linearity break: entry 3 chains to its grandparent R1 while parent R2 stays ----
  // The shape is also a fork of R1 (entries 2 and 3 share it), but the linearity pass
  // reports it first; indices are monotonic and every prevRunId resolves, so no other
  // branch can account for the rejection, and the restored run is still the maximum for
  // its downpipe. The root agrees with the restored run's own prevRunId (R1), so the
  // run-vs-root checks pass first.
  const skipped = [entry(1, R1, null, "superseded"), entry(2, R2, R1, "superseded"), entry(3, R3, R1, "active")];
  const skipRes = await check(signer, skipped, R3, rootFor(3, R1));
  ok("linearity break (grandparent link) is rejected (ok:false)", skipRes.ok === false);
  ok("linearity reason names the broken link", /does not chain to the prior retained entry/.test(skipRes.reason ?? ""));
  const skipStale = await check(signer, skipped, R3, rootFor(3, R1), { allowStale: true });
  ok("linearity break is acknowledged under allowStale (ok:true, reason kept)", skipStale.ok === true && /does not chain to the prior retained entry/.test(skipStale.reason ?? ""));
}

async function proofDangling(signer: SignerCtx): Promise<void> {
  // ---- A dangling prevRunId: dp_other's first entry points at OX, which no entry carries ----
  // A downpipe's first retained entry is exempt from the linearity rule and the indices
  // are monotonic, so only the dangling check can fire; the restored run's own chain is
  // clean and the root agrees with its prevRunId (R1).
  const dangling = [entry(1, R1, null, "superseded"), entry(2, R2, R1, "active"), entryFor(DP2, 3, R3, OX, "active")];
  const dangRes = await check(signer, dangling, R2, rootFor(2, R1));
  ok("dangling prevRunId is rejected (ok:false)", dangRes.ok === false);
  ok("dangling reason names the dangling pointer", /dangling prevRunId/.test(dangRes.reason ?? ""));
  const dangStale = await check(signer, dangling, R2, rootFor(2, R1), { allowStale: true });
  ok("dangling prevRunId is acknowledged under allowStale", dangStale.ok === true && /dangling prevRunId/.test(dangStale.reason ?? ""));
}

async function proofForked(signer: SignerCtx): Promise<void> {
  // ---- A forked chain: dp's entry 2 and dp_other's first entry both link back to R1 ----
  // Within one downpipe any fork is reported by the linearity pass first, so the
  // cross-downpipe shape is what exercises the fork branch itself: each downpipe's own
  // chain is linear, the indices are monotonic and every prevRunId resolves.
  const forked = [entry(1, R1, null, "superseded"), entry(2, R2, R1, "active"), entryFor(DP2, 3, R3, R1, "active")];
  const forkRes = await check(signer, forked, R2, rootFor(2, R1));
  ok("forked prevRunId is rejected (ok:false)", forkRes.ok === false);
  ok("forked reason names the shared predecessor", /share prevRunId/.test(forkRes.reason ?? ""));
  const forkStale = await check(signer, forked, R2, rootFor(2, R1), { allowStale: true });
  ok("forked prevRunId is acknowledged under allowStale", forkStale.ok === true && /share prevRunId/.test(forkStale.reason ?? ""));
}

async function proofOutOfOrderAndDuplicate(signer: SignerCtx): Promise<void> {
  // ---- INTERLEAVED line order is ACCEPTED (the concurrent-fleet shape) ----
  // Entries land at FINALISE time, so concurrent runs append out of allocation order as
  // a matter of course (the first production fleet produced this within its first hour);
  // the checks sort by index and the signature anchors the bytes (SPEC 10, amended).
  const outOfOrderLines = [entry(2, R2, R1, "active"), entry(1, R1, null, "superseded")];
  const outOfOrderRes = await check(signer, outOfOrderLines, R2, rootFor(2, R1));
  ok("interleaved append order is accepted (ok:true)", outOfOrderRes.ok === true);

  // ---- A DUPLICATED index is the real index-axis corruption signal ----
  // The account-global counter never reissues one; two entries sharing an index mean the
  // log was corrupted or hand-assembled.
  const duplicated = [entry(1, R1, null, "superseded"), entry(2, R2, R1, "active"), entryFor(DP2, 2, R3, null, "active")];
  const dupRes = await check(signer, duplicated, R2, rootFor(2, R1));
  ok("a duplicated index is rejected (ok:false)", dupRes.ok === false);
  ok("the duplicate reason names the repeated index", /appears twice/.test(dupRes.reason ?? ""));
  const dupStale = await check(signer, duplicated, R2, rootFor(2, R1), { allowStale: true });
  ok("a duplicated index is acknowledged under allowStale", dupStale.ok === true && /appears twice/.test(dupStale.reason ?? ""));
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  await proofWellLinked(signer);
  await proofAllocGap(signer);
  await proofInterleaved(signer);
  await proofLinearityBreak(signer);
  await proofDangling(signer);
  await proofForked(signer);
  await proofOutOfOrderAndDuplicate(signer);

  console.log(failures === 0 ? "\nRUNLOG CHAIN PARITY VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
