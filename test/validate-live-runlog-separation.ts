// Measured. Does the SHARED harness archive bucket explain the forked RUNLOG, and
// would giving each estate its own bucket clear it?
//
// The four documents under test/fixtures/bucket-split-runlogs/ are REAL, read read-only off the Cloudflare R2
// S3 endpoint with the account-read half of the `harness-dest-r2` credential (tools/r2snap.mjs
// get). Nothing was written to, repaired, reset or cleaned in any bucket. They are:
//
//   harness-archive-a.ndjson           the SHARED fixture bucket all seven dest-fixtures name
//   harness-archive-crud-e1.ndjson     crud's OWN deploy-time DEST_R2 bucket
//   harness-archive-genesis-e1.ndjson  genesis's OWN deploy-time DEST_R2 bucket
//   harness-archive-channel-e1.ndjson  channel's OWN deploy-time DEST_R2 bucket
//
// (harness-archive-probe-e1 is deliberately ABSENT: probe was under another pass's live supervisor and its
// bucket was not touched, not even read.)
//
// WHAT THIS SETTLES. The premise handed to this pass was that seven engines append to ONE `_RECOVERY/RUNLOG`
// because seven fixtures name one bucket, and that splitting the fixtures is the repair. The live bindings
// say otherwise: every harness engine binds DEST_R2 to its own `harness-archive-<estate>-e1`, and every
// non-probe estate carries ZERO console-set destinations, so its effective destination IS its own bucket.
// This validator drives the production reader over the real documents to show the consequence: the SHARED
// bucket is forked and each estate's OWN bucket is already chain-clean.
//
// It drives the REAL `checkRunlogFreshness` (src/format/freshness.ts) rather than the module-private
// detectChainAnomaly, with a genuine hybrid signature over the real entry sequence so the signature gate
// passes and the CHAIN check is what fires. Re-signing is honest here because the signature is not the
// property under test: signRunlog re-signs the whole document on every append by design, so a fresh
// signature over the same entries is exactly what the last real writer produced.
//
// THE CONTROLS, because a clean verdict on three buckets is an ABSENCE and an absence holds just as well
// over a reader that is not looking:
//
//   P1 KNOWN POSITIVE   the shared bucket's real document must be REFUSED, with the estate's verbatim
//                       "runlog index 2 appears twice (log corrupted or rewritten)" and rollbackDetected.
//   P2 POPULATION       each clean document must carry at least one entry, so "no anomaly" cannot hold
//                       over an empty file (the R1 shape).
//   P3 NOT VACUOUS      genesis (6, 7, 9) and channel (1, 2, 4) carry index GAPS and are still clean, so
//                       the clean verdict is a real judgement about a non-trivial document and not the
//                       reader accepting anything contiguous.
//   P4 MUTATION         re-index one entry of crud's CLEAN document onto an index it already carries and
//                       the same reader must now REFUSE it. This is the control that can fail: it proves
//                       the clean verdicts in P2/P3 came from a detector that was able to say no.
//   P5 ALLOW-STALE      the shared bucket's refusal survives allowStale, so the fork is not a staleness
//                       verdict that a tolerant caller clears.
//
// Run: node test/validate-live-runlog-separation.ts
// In-memory doubles only; no network, no deploy, no estate driven, no cost.
//
// House style: Australian English, no em dashes, no rule-of-three, no AI attribution.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import type { HybridVerifier } from "../src/crypto/sign.ts";
import { checkRunlogFreshness, type FreshnessOptions } from "../src/format/freshness.ts";
import type { RootManifest } from "../src/format/manifest.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import { type RunlogEntry, signRunlog } from "../src/format/writer.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const FIXTURE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "bucket-split-runlogs");

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

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

// loadLive reads one banked live document. Parsed with the same field set writer-runlog.ts declares, so a
// document that has drifted out of shape fails here rather than being silently coerced.
function loadLive(bucket: string): RunlogEntry[] {
  const text = readFileSync(path.join(FIXTURE_DIR, `${bucket}.ndjson`), "utf8");
  return text
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as RunlogEntry);
}

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

// checkAgainst runs the production reader with the root anchored to one entry the document really carries,
// so the read reaches the chain check rather than short-circuiting on a root disagreement.
async function checkAgainst(signer: SignerCtx, entries: RunlogEntry[], anchor: RunlogEntry, opts: FreshnessOptions = {}) {
  const store = await storeFor(signer, entries);
  const root = { downpipeId: anchor.downpipeId, freshness: { runlogIndex: anchor.index, prevRunId: anchor.prevRunId ?? null } } as unknown as RootManifest;
  return checkRunlogFreshness(store, anchor.runId, root, signer.verifier, opts);
}

// duplicateIndexCount reports how many indices the document carries more than once, the fact the shared
// bucket and the per-estate buckets are meant to differ on.
function duplicateIndexCount(entries: RunlogEntry[]): number {
  const seen = new Map<number, number>();
  for (const e of entries) seen.set(e.index, (seen.get(e.index) ?? 0) + 1);
  return [...seen.values()].filter((n) => n > 1).length;
}

// hasIndexGap says whether the document skips an index, which SPEC 10 declares benign. Used to prove the
// clean documents are not trivially contiguous.
function hasIndexGap(entries: RunlogEntry[]): boolean {
  const idx = [...entries].map((e) => e.index).sort((a, b) => a - b);
  return idx.some((v, i) => i > 0 && v > (idx[i - 1] as number) + 1);
}

// P1: the shared bucket is forked, and the production reader says so in the estate's own words.
async function proofSharedBucketIsForked(signer: SignerCtx): Promise<void> {
  const entries = loadLive("harness-archive-a");
  ok("KNOWN POSITIVE: the shared bucket document is populated", entries.length > 0);
  ok(`KNOWN POSITIVE: the shared bucket carries duplicate indices (${duplicateIndexCount(entries)} of them)`, duplicateIndexCount(entries) > 0);

  // Anchor on the FIRST entry, whose index (1) is unique, so the refusal cannot be an artefact of anchoring
  // the root on one half of a duplicated pair.
  const anchor = [...entries].sort((a, b) => a.index - b.index)[0] as RunlogEntry;
  ok("KNOWN POSITIVE: the anchor entry's own index is unique in the document", entries.filter((e) => e.index === anchor.index).length === 1);

  const res = await checkAgainst(signer, entries, anchor);
  ok("KNOWN POSITIVE: the shared bucket is REFUSED (ok:false)", res.ok === false);
  ok("KNOWN POSITIVE: the refusal is a rollback verdict", res.rollbackDetected === true);
  ok(`KNOWN POSITIVE: the reason is the estate's verbatim string (got: ${res.reason})`, res.reason === "runlog index 2 appears twice (log corrupted or rewritten)");
  ok("KNOWN POSITIVE: the check actually ran", res.checked === true);
}

// P5: the fork is not a staleness verdict a tolerant caller clears.
async function proofForkSurvivesAllowStale(signer: SignerCtx): Promise<void> {
  const entries = loadLive("harness-archive-a");
  const anchor = [...entries].sort((a, b) => a.index - b.index)[0] as RunlogEntry;
  const res = await checkAgainst(signer, entries, anchor, { allowStale: true });
  ok("allowStale does not clear the fork's rollback verdict", res.rollbackDetected === true);
  ok("allowStale does not change the fork's reason", res.reason === "runlog index 2 appears twice (log corrupted or rewritten)");
}

// P2 and P3: each estate's OWN bucket is already chain-clean, over a populated and non-trivial document.
async function proofPerEstateBucketsAreClean(signer: SignerCtx): Promise<void> {
  for (const bucket of ["harness-archive-crud-e1", "harness-archive-genesis-e1", "harness-archive-channel-e1"]) {
    const entries = loadLive(bucket);
    ok(`POPULATION: ${bucket} carries at least one entry (${entries.length})`, entries.length > 0);
    ok(`${bucket} carries NO duplicate index`, duplicateIndexCount(entries) === 0);

    const anchor = [...entries].sort((a, b) => b.index - a.index)[0] as RunlogEntry;
    const res = await checkAgainst(signer, entries, anchor);
    ok(`${bucket} raises no chain anomaly`, res.rollbackDetected === false);
    ok(`${bucket} reason is not the duplicate-index refusal (got: ${res.reason})`, res.reason !== "runlog index 2 appears twice (log corrupted or rewritten)");
  }

  // NOT VACUOUS: two of the three skip indices and are still accepted, so the clean verdict is a judgement
  // about a real document rather than the reader waving through anything contiguous.
  ok("NOT VACUOUS: genesis's clean document carries an index gap", hasIndexGap(loadLive("harness-archive-genesis-e1")));
  ok("NOT VACUOUS: channel's clean document carries an index gap", hasIndexGap(loadLive("harness-archive-channel-e1")));
}

// P4: the control that can fail. Fork a clean per-estate document the way a second engine sharing its bucket
// would, and the SAME reader must refuse it.
async function proofMutationOfACleanBucketIsCaught(signer: SignerCtx): Promise<void> {
  const clean = loadLive("harness-archive-genesis-e1");
  const anchor = [...clean].sort((a, b) => a.index - b.index)[0] as RunlogEntry;

  const before = await checkAgainst(signer, clean, anchor);
  ok("MUTATION: genesis's untouched document is accepted before the mutation", before.rollbackDetected === false);

  // A second writer with its own counter reissuing an index this document already holds, on a different run.
  const collided = [...clean, { ...clean[1] as RunlogEntry, index: (clean[0] as RunlogEntry).index, runId: "01ARZ3NDEKTSV4RRFFQ69G5FZZ", prevRunId: null }];
  const after = await checkAgainst(signer, collided, anchor);
  ok("MUTATION: the same reader REFUSES genesis's document once an index is reissued", after.rollbackDetected === true);
  ok(`MUTATION: and refuses it as a duplicate index (got: ${after.reason})`, (after.reason ?? "").includes("appears twice (log corrupted or rewritten)"));
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  await proofSharedBucketIsForked(signer);
  await proofForkSurvivesAllowStale(signer);
  await proofPerEstateBucketsAreClean(signer);
  await proofMutationOfACleanBucketIsCaught(signer);

  console.log(failures === 0 ? "\nLIVE RUNLOG SEPARATION VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
