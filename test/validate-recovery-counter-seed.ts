// RUNLOG-FORKS-ON-THE-RECOVERY-PATH, the fix. validate-runlog-fork-on-recovery.ts
// proved the defect: a rebuilt SchedulerDO's runlogCounter starts at zero against a surviving destination
// bucket, so the recovery path's own first trigger() forks the customer's signed RUNLOG. This proves the
// repair: readVerifiedRunlogMaxIndex (format/freshness.ts) reads the bucket's own RUNLOG, verified under the
// operator's pinned signer, and setControlPlaneRecoveryRequired (scheduler-do-control-plane.ts) anchors the
// DO's runlogCounter to it, monotonically, before the latch is set -- so the next real trigger() allocates
// the index the log actually expects, through the REAL routed HTTP surface (stubFetch), not a hand-fed index.
//
// Cell A is the reader in isolation, with its own negative controls (wrong verifier, absent document,
// corrupt signature) so the seed can be shown to withhold an answer, not merely to produce one.
// Cell B drives the full recovery path through a real SchedulerDO: unseeded (today's shape, unchanged) vs
// seeded (the fix), reading the ALLOCATED index off trigger()'s own response, never off a source variable.
// Cell C closes the loop against the real writer: the seeded index is used to seal an actual run into the
// bucket that already holds the three pre-loss entries, and the resulting document is asserted clean AND
// the pre-loss run stays attestable, the collateral damage validate-runlog-fork-on-recovery.ts's
// cell A found.
//
// Run: node test/validate-recovery-counter-seed.ts
// Run against unfixed code (pre-fix): the same command on a worktree without this patch fails cell B and C.

import { x25519 } from "@noble/curves/ed25519.js";
import { utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import { readVerifiedRunlogMaxIndex } from "../src/format/freshness.ts";
import { attestKeyless } from "../src/format/keyless.ts";
import type { ObjectStore } from "../src/format/reader.ts";
import { parseRunlog, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { type RunClock, type RunConfig, runBackup } from "../src/seal/pipeline.ts";
import type { Selector, SourceAdapter, SourceRecord } from "../src/sources/types.ts";
import { MemoryDestination } from "./memdest.ts";
import { makeConfig, makeScheduler, stubFetch } from "./validate-scheduler-shared.ts";

const A1 = "01ARZ3NDEKTSV4RRFFQ69G5FA1";
const A2 = "01ARZ3NDEKTSV4RRFFQ69G5FA2";
const A3 = "01ARZ3NDEKTSV4RRFFQ69G5FA3";
const B_SEEDED = "01ARZ3NDEKTSV4RRFFQ69G5FB4"; // the post-recovery run, sealed at the SEEDED index.
const DP = "dp_recovered";

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));

class FakeSource implements SourceAdapter {
  readonly sourceType = "kv" as const;
  private readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  async *crawl(_sel: Selector): AsyncIterable<SourceRecord> {
    yield { sourceType: "kv", name: "k", value: utf8(this.value), namespace: "ns" };
  }
  async estimate(): Promise<{ records: number; bytes: number }> {
    return { records: 1, bytes: -1 };
  }
}

function makeRecipient(role: string): RecipientEntry {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } };
}

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

function storeOf(dest: MemoryDestination): ObjectStore {
  return {
    get: async (k: string) => {
      const r = await dest.get(k);
      if (!r) throw new Error(`missing ${k}`);
      return r.body;
    },
  };
}

// cloneDest copies every object into a fresh MemoryDestination, so cells run against independent copies of
// the same surviving state (memdest.ts carries no snapshot() of its own).
async function cloneDest(src: MemoryDestination): Promise<MemoryDestination> {
  const copy = new MemoryDestination();
  for (const [k, v] of src.entries()) await copy.put(k, v);
  return copy;
}

async function main(): Promise<void> {
  const recipients = [makeRecipient("break-glass"), makeRecipient("operational")];
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const verifier = { ed: edPublic, mldsa: mldsa.publicKey };
  const cfg: RunConfig = { downpipeId: DP, downpipeName: "recovered", cadence: "3600s", selector: { include: [], exclude: [] }, recipients };
  const clockBase = { randomNonce: () => rand(16), randomSalt: () => rand(16) };

  // The customer's surviving bucket: three ordinary pre-loss runs, exactly as the fork validator builds it.
  const original = new MemoryDestination();
  await runBackup([new FakeSource("one")], cfg, signer, original, { ...clockBase, runId: A1, runlogIndex: 1, prevRunId: null, now: "2026-08-01T00:00:00.000Z", master: rand(32) } as RunClock);
  await runBackup([new FakeSource("two")], cfg, signer, original, { ...clockBase, runId: A2, runlogIndex: 2, prevRunId: A1, now: "2026-08-02T00:00:00.000Z", master: rand(32) } as RunClock);
  await runBackup([new FakeSource("three")], cfg, signer, original, { ...clockBase, runId: A3, runlogIndex: 3, prevRunId: A2, now: "2026-08-03T00:00:00.000Z", master: rand(32) } as RunClock);

  // ---- CELL A: readVerifiedRunlogMaxIndex in isolation, with negative controls. -------------------
  {
    const getObject = (key: string): Promise<Uint8Array | null> => original.get(key).then((r) => r?.body ?? null);
    const seed = await readVerifiedRunlogMaxIndex(getObject, verifier);
    ok("A: the verified reader returns the document's true high-water mark (3)", seed === 3);

    const wrongVerifier = { ed: new Uint8Array(edPublic.length), mldsa: mldsa.publicKey };
    const underWrongKey = await readVerifiedRunlogMaxIndex(getObject, wrongVerifier);
    ok("A: a verifier that does not match the signer yields NO seed (null, never 0)", underWrongKey === null);

    const emptyBucket = new MemoryDestination();
    const overEmpty = await readVerifiedRunlogMaxIndex((k) => emptyBucket.get(k).then((r) => r?.body ?? null), verifier);
    ok("A: an absent RUNLOG yields NO seed (null)", overEmpty === null);

    const tampered = new MemoryDestination();
    for (const [k, v] of [["_RECOVERY/RUNLOG", await original.get("_RECOVERY/RUNLOG")], ["_RECOVERY/RUNLOG.sig", await original.get("_RECOVERY/RUNLOG.sig")]] as const) {
      if (v) await tampered.put(k, v.body);
    }
    const runlogRaw = await tampered.get("_RECOVERY/RUNLOG");
    if (runlogRaw) {
      const mutated = new Uint8Array(runlogRaw.body);
      mutated[0] = (mutated[0] ?? 0) ^ 0xff;
      await tampered.put("_RECOVERY/RUNLOG", mutated);
    }
    const overTampered = await readVerifiedRunlogMaxIndex((k) => tampered.get(k).then((r) => r?.body ?? null), verifier);
    ok("A: a tampered document (signature no longer verifies) yields NO seed (null)", overTampered === null);
  }

  // ---- CELL B: the real recovery path, through the routed SchedulerDO HTTP surface. ----------------
  {
    // B1: UNSEEDED, today's shape, unchanged. No customer-reachable regression: an amnesia detection that
    // cannot establish a seed (offline here; unreadable/unsigned bucket in production) behaves exactly as
    // it did before this fix.
    const { stub: unseeded } = makeScheduler();
    await stubFetch(unseeded, "POST", "/downpipes", makeConfig("dp-unseeded"));
    await stubFetch(unseeded, "POST", "/control-plane/recovery-required", { reason: "amnesia, no seed established" });
    const t0 = (await (await stubFetch(unseeded, "POST", "/trigger", { id: "dp-unseeded" })).json()) as { index: number };
    ok("B1: with no seed, the recovered DO still allocates index 1 (unchanged behaviour)", t0.index === 1);

    // B2: SEEDED with the reader's own verified answer from Cell A (3), carried exactly as
    // runControlPlaneHealthPass now carries it in the POST body.
    const { stub: seeded } = makeScheduler();
    await stubFetch(seeded, "POST", "/downpipes", makeConfig(DP));
    const getObject = (key: string): Promise<Uint8Array | null> => original.get(key).then((r) => r?.body ?? null);
    const runlogSeed = await readVerifiedRunlogMaxIndex(getObject, verifier);
    ok("B2: precondition -- the seed computed from the bucket is 3", runlogSeed === 3);
    await stubFetch(seeded, "POST", "/control-plane/recovery-required", { reason: "amnesia, seed established", runlogSeed });
    const t1 = (await (await stubFetch(seeded, "POST", "/trigger", { id: DP })).json()) as { index: number };
    ok("B2: a recovered DO seeded from the verified RUNLOG allocates index 4, NOT 1", t1.index === 4);

    // B3: idempotence / monotonicity -- a second recovery-required call with a LOWER seed never regresses
    // an already-anchored counter (setControlPlaneRecoveryRequired's monotonic-max write). A SECOND
    // downpipe is used because the runlogCounter is account-global, not per-downpipe, and the first is
    // still in flight (trigger() coalesces a repeat call on the same downpipe rather than allocating).
    await stubFetch(seeded, "POST", "/downpipes", makeConfig("dp-seeded-second"));
    await stubFetch(seeded, "POST", "/control-plane/recovery-required", { reason: "re-latched", runlogSeed: 1 });
    const t2 = (await (await stubFetch(seeded, "POST", "/trigger", { id: "dp-seeded-second" })).json()) as { index: number };
    ok("B3: a later, LOWER seed does not regress the counter (still past 4)", t2.index === 5);
  }

  // ---- CELL C: close the loop against the real writer -- the seeded index actually seals cleanly. ------
  {
    const dest = await cloneDest(original);
    await runBackup([new FakeSource("post-recovery-seeded")], cfg, signer, dest, { ...clockBase, runId: B_SEEDED, runlogIndex: 4, prevRunId: A3, now: "2026-08-04T00:00:00.000Z", master: rand(32) } as RunClock);
    const log = await dest.get("_RECOVERY/RUNLOG");
    const entries = log ? parseRunlog(log.body) : [];
    ok("C: four entries, four distinct indices -- no fork", entries.length === 4 && new Set(entries.map((e) => e.index)).size === 4);

    const attNew = await attestKeyless(storeOf(dest), B_SEEDED, verifier, { allowStale: false });
    ok("C: the post-recovery run attests CLEAN", attNew.signatureValid === true && attNew.complete === true && attNew.notRolledBack === true);
    ok("C: and carries no reason", attNew.reason === undefined || attNew.reason === null || attNew.reason === "");

    // The collateral damage the original finding proved: A3 stops being the LATEST run for its downpipe
    // once B_SEEDED exists (index 4), and attestKeyless's notRolledBack REQUIRES latest-ness unconditionally
    // (keyless.ts: `freshness.ok && freshness.isLatestForDownpipe && !freshness.rollbackDetected`) -- so A3
    // legitimately refuses under BOTH allowStale settings, and that is correct, ordinary product behaviour
    // present on every multi-run downpipe, fork or no fork. What the original defect added on top was a
    // SEPARATE, unconditional, allowStale-proof refusal class (the chain anomaly: "log corrupted or
    // rewritten" / "prevRunId disagrees with the signed root"), because rollbackDetected -- which
    // allowStale can never clear -- was true. The fix does not, and should not, make a non-latest run
    // attestable; it removes the anomaly, so the ONLY reason A3 refuses is now the ordinary one, under
    // either allowStale setting, never the fork's verbatim strings.
    const attOldStrict = await attestKeyless(storeOf(dest), A3, verifier, { allowStale: false });
    ok(
      "C: A3 refuses under allowStale:false for ORDINARY staleness, not a chain anomaly",
      attOldStrict.notRolledBack === false && attOldStrict.signatureValid === true && attOldStrict.reason !== "runlog index 3 appears twice (log corrupted or rewritten)" && !/prevRunId disagrees with the signed root/.test(attOldStrict.reason ?? ""),
    );
    const attOldStale = await attestKeyless(storeOf(dest), A3, verifier, { allowStale: true });
    ok(
      "C: A3 refuses under allowStale:true too (still not latest), but STILL never the fork's chain-anomaly reason",
      attOldStale.notRolledBack === false && attOldStale.signatureValid === true && attOldStale.reason !== "runlog index 3 appears twice (log corrupted or rewritten)" && !/prevRunId disagrees with the signed root/.test(attOldStale.reason ?? ""),
    );
  }

  console.log(failures === 0 ? "\nPASS: the recovery-path seed anchors the counter and the fork does not occur." : `\nFAIL: ${failures} assertion(s)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
