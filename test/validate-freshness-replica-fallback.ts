// A destination that lost its own _RECOVERY/RUNLOG must not take the other two copies down with it -- and the
// replica that serves instead must never do it quietly.
//
// WHAT THIS GUARDS
// ----------------
// The freshness gate refuses an open on two different things, and conflating them told the restore side they were one:
//
//   a check that RAN and found a rollback   -- a FINDING about the run. Terminal on every destination:
//                                              walking to a second copy after that is how a rollback is masked.
//   a check that COULD NOT RUN              -- an UNKNOWN about ONE destination's own RUNLOG.
//
// The second is not the same class of fact, because _RECOVERY/RUNLOG is not the same document on every
// destination. appendRunlogBody's relinkLocalPrev relinks the downpipe's whole chain from THIS destination's
// own read and signs THIS destination's own copy, and mirrorRunToReplica writes each replica its own. So the
// sentence that correctly excludes every integrity failure -- "a replica holds the same signed run" -- is
// simply not true of the RUNLOG. openVerifiedRun opens with verifyFreshness:true, so before this split a
// customer whose primary had lost its RUNLOG (deleted, denied after a credential rotation, throttled, moved to
// a cold tier) was refused the whole restore, including the two copies that would have verified end to end.
//
// THE THREE THINGS THAT MUST ALL HOLD, AND EACH IS DRIVEN HERE
// -----------------------------------------------------------
//   1. The refusal on the destination the fault was found on is UNCHANGED. The reader still throws. Nothing
//      that used to refuse now opens, and a check that reached a VERDICT is still terminal everywhere.
//   2. The fallback happens when it should and NOT when it should not, driven through the production
//      withRunDestFallback against real sealed archives on two real destinations.
//   3. The fallback is NEVER silent. A restore not served by its first choice says so on the result AND
//      inside the receipt's signed core, and a fallback whose walk is stripped does not hash the same.
//
// A silent success from a replica would be a different defect of the same family as the one this whole area
// was just fixed for: a check that established nothing reporting that nothing was wrong.
//
// CONTROL AND FIX
// ----------------
// Section 5 drives the production walk with the reason a reader that does not distinguish these two cases
// would produce (freshnessError -> REASON_FRESHNESS), and proves it stops on the primary after ONE attempt
// with the healthy replica never read. Section 6 then drives the identical two-destination estate through the
// real restore and reaches the replica on attempt 2.
//
// Real hybrid crypto, real buildArchive, real appendRunlog, the real verifying reader, the real classifier,
// the real 3-2-1 walk, the real runRestore and the real receipt. In-memory destinations and an in-memory
// scheduler double only: no network, no deploy, no cost.
// Run: node test/validate-freshness-replica-fallback.ts

import { x25519 } from "@noble/curves/ed25519.js";

import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { runRestore } from "../src/admin/restore.ts";
import { makeRestoreReceipt, restoreReceiptDigestHex } from "../src/admin/restore-receipt.ts";
import type { RestoreDestFallback, RestoreReceiptRecord, RestoreResult } from "../src/admin/restore-types.ts";
import { withRunDestFallback } from "../src/admin/router-sources.ts";
import type { Env } from "../src/env.d.ts";
import { freshnessError, integrityCategoryOf } from "../src/format/integrity-error.ts";
import { openRun, type ObjectStore } from "../src/format/reader.ts";
import { buildArchive, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { loadIdentity, loadSigner, verifierFrom } from "../src/keys-env.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import {
  classifyRestoreFailure,
  isReplicaFallbackReason,
  REASON_FRESHNESS,
  REASON_FRESHNESS_UNVERIFIABLE,
  REASON_INTEGRITY,
} from "../src/restore-reasons.ts";
import { MemoryDestination } from "./memdest.ts";

const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const OTHER_RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
const DP = "dp_freshness_fallback";
const NS = "ns_throwaway";
const RUNLOG_KEY = "_RECOVERY/RUNLOG";
const RUNLOG_SIG_KEY = "_RECOVERY/RUNLOG.sig";
const KVSET: Record<string, string> = { a: "alpha-value", b: "beta-value", "user:42": "gamma-value-longer" };

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

// A destination double built from a MemoryDestination, so every read below goes through the SAME production
// R2 dest factory the engine uses (DEST_KIND r2 + a DEST_R2 binding). Only the binding is a double.
function r2For(dest: MemoryDestination): R2Bucket {
  return {
    get: async (key: string) => {
      const v = await dest.get(key);
      if (!v) return null;
      return {
        arrayBuffer: async () => {
          const ab = new ArrayBuffer(v.body.byteLength);
          new Uint8Array(ab).set(v.body);
          return ab;
        },
        etag: v.etag,
      };
    },
    head: async (key: string) => ((await dest.get(key)) ? { etag: "x" } : null),
  } as unknown as R2Bucket;
}

// The scheduler double the production walk resolves its candidate list and per-destination config through.
// Every destination answers with a COMPLETE stored config, so fetchDestConfig returns non-null for each and
// the OP is what decides the outcome -- never a configuration hole standing in for a refusal.
function schedulerStub(destinationIds: string[]): DurableObjectStub {
  const json = (body: unknown): Response => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  return {
    fetch: (input: RequestInfo | URL): Promise<Response> => {
      const raw = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
      const u = new URL(raw);
      if (u.pathname === "/downpipes/dests-for-run") return Promise.resolve(json({ destinationIds }));
      if (u.pathname === "/dest-config") {
        // bucket carries the destination id, so the op below can tell WHICH destination the walk handed it.
        return Promise.resolve(json({ config: { endpoint: "https://s3.example", bucket: u.searchParams.get("id") ?? "", region: "us-east-1", accessKeyId: "AK", secretAccessKey: "SK" } }));
      }
      return Promise.resolve(new Response("not found", { status: 404 }));
    },
  } as unknown as DurableObjectStub;
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const opIdentity = loadIdentity(b64urlEncode(op.identity));
  const operationalPrivateB64 = b64urlEncode(op.identity);

  // A REAL sealed archive, then a REAL signed RUNLOG appended to each destination through the production
  // appendRunlog with relinkLocalPrev -- which is the mechanism the whole split rests on, so the probe uses
  // it rather than hand-writing the document.
  async function seal(prevRunId: string | null): Promise<Map<string, Uint8Array>> {
    return await buildArchive({
      downpipeId: DP,
      downpipeName: "freshness-fallback",
      cadence: "3600s",
      runId: RUN_ID,
      master: rand(32),
      recipients: [breakGlass.entry, op.entry],
      signer,
      records: Object.entries(KVSET).map(([name, v]) => ({ sourceType: "kv", name, value: utf8(v), namespace: NS })),
      windowStart: "2026-06-07T00:00:00.000Z",
      windowEnd: "2026-06-07T00:00:01.000Z",
      createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    });
  }
  async function destFrom(objs: Map<string, Uint8Array>, entryPrevRunId: string | null = null): Promise<MemoryDestination> {
    const d = new MemoryDestination();
    for (const [k, b] of objs) await d.put(k, b);
    const entry: RunlogEntry = { index: 1, runId: RUN_ID, downpipeId: DP, time: "2026-06-07T00:00:01.000Z", recordCount: Object.keys(KVSET).length, prevRunId: entryPrevRunId, status: "active" };
    await appendRunlog(d, signer, entry, undefined, { relinkLocalPrev: true });
    return d;
  }
  const objs = await seal(null);
  const storeOf = (d: MemoryDestination): ObjectStore => ({
    get: async (k: string) => {
      const v = await d.get(k);
      if (!v) throw new Error(`object ${k} is missing`);
      return v.body;
    },
  });

  console.log("-- 1. the RUNLOG really is a PER-DESTINATION document, which is the whole ground for the split --");
  {
    const primary = await destFrom(objs);
    const replica = await destFrom(objs);
    ok("both destinations hold their OWN signed RUNLOG", (await primary.get(RUNLOG_KEY)) !== null && (await replica.get(RUNLOG_KEY)) !== null);
    await primary.put(RUNLOG_KEY, new Uint8Array(0));
    // Emptying one destination's document leaves the other's untouched. A shared document could not do this,
    // and if it could not, falling back would be masking rather than recovering.
    const replicaStill = await replica.get(RUNLOG_KEY);
    ok("emptying the primary's RUNLOG leaves the replica's intact (they are separate documents)", replicaStill !== null && replicaStill.body.byteLength > 0);
  }

  console.log("-- 2. a freshness check that COULD NOT RUN refuses the open, with its own category --");
  for (const [label, mutate] of [
    ["the RUNLOG is gone", async (d: MemoryDestination) => { await d.delete(RUNLOG_KEY); }],
    ["the RUNLOG signature does not verify", async (d: MemoryDestination) => { await d.put(RUNLOG_SIG_KEY, utf8("bm90LWEtc2lnbmF0dXJl")); }],
    ["the RUNLOG no longer carries this run", async (d: MemoryDestination) => {
      const rl = (await d.get(RUNLOG_KEY))!.body;
      const kept = new TextDecoder().decode(rl).split("\n").filter((l) => l.trim() !== "" && !l.includes(RUN_ID)).join("\n");
      await d.put(RUNLOG_KEY, utf8(kept === "" ? "" : `${kept}\n`));
    }],
  ] as [string, (d: MemoryDestination) => Promise<void>][]) {
    const d = await destFrom(objs);
    await mutate(d);
    let caught: unknown;
    try {
      await openRun(storeOf(d), RUN_ID, opIdentity, verifier, { verifyFreshness: true, allowStale: true });
    } catch (e) {
      caught = e;
    }
    // THE FIX UNDERNEATH IS NOT WEAKENED: the destination the fault was found on still REFUSES.
    ok(`${label}: the reader still REFUSES the open on this destination`, caught !== undefined);
    ok(`${label}: the structured category is 'freshness-unverifiable'`, integrityCategoryOf(caught) === "freshness-unverifiable");
    ok(`${label}: it classifies to REASON_FRESHNESS_UNVERIFIABLE`, classifyRestoreFailure(caught) === REASON_FRESHNESS_UNVERIFIABLE);
    ok(`${label}: that reason IS replica-fallback-eligible`, isReplicaFallbackReason(classifyRestoreFailure(caught)) === true);
  }

  console.log("-- 3. a freshness check that RAN TO A VERDICT stays terminal on every destination --");
  {
    // The out-of-band min-runlog-index pin is positive proof of rollback and the check RAN to reach it, so it
    // is a FINDING about the run. It must not earn a replica walk, and it is the benign control the previous
    // fix in this area used, so it is the one most worth re-asserting here.
    const d = await destFrom(objs);
    let caught: unknown;
    try {
      await openRun(storeOf(d), RUN_ID, opIdentity, verifier, { verifyFreshness: true, allowStale: true, minRunlogIndex: 5 });
    } catch (e) {
      caught = e;
    }
    ok("a below-the-pin run is REFUSED", caught !== undefined);
    ok("its structured category is 'freshness' (the check RAN)", integrityCategoryOf(caught) === "freshness");
    ok("it classifies to REASON_FRESHNESS", classifyRestoreFailure(caught) === REASON_FRESHNESS);
    ok("REASON_FRESHNESS is NOT replica-fallback-eligible: a verdict of rollback is terminal everywhere", isReplicaFallbackReason(REASON_FRESHNESS) === false);
  }

  console.log("-- 4. the deliberately-preserved path is untouched: prevRunId disagreement still OPENS --");
  {
    // A replica that skipped a run carries a copied reference, so a signed root whose prevRunId disagrees with
    // the destination-local chain is a state the ENGINE ITSELF writes. Refusing it would block restore from
    // exactly the diverged replica a three-copy restore reaches for. It reports the check as having RUN.
    const diverged = await seal(OTHER_RUN_ID); // the signed root claims a previous run
    const d = await destFrom(diverged, null); // relinkLocalPrev makes the stored chain say there was none
    const run = await openRun(storeOf(d), RUN_ID, opIdentity, verifier, { verifyFreshness: true, allowStale: true });
    ok("a prevRunId disagreement still OPENS the run", run.records.length === Object.keys(KVSET).length);
    ok("it reports the check as having RUN (checked:true), so it never reaches the new throw", run.freshness?.checked === true);
    ok("it keeps its note", run.freshness?.reason === "RUNLOG prevRunId disagrees with the signed root");
    ok("and it is not reported as a rollback", run.freshness?.rollbackDetected === false);
  }

  // The two-destination estate every walk below runs against.
  const envFor = (d: MemoryDestination): Env =>
    ({
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: r2For(d),
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: operationalPrivateB64,
      [`KV_${NS}`]: { put: async () => {}, get: async () => null, delete: async () => {} } as unknown as KVNamespace,
    }) as unknown as Env;

  console.log("-- 5. CONTROL: a reader that conflates the two refusal reasons stops the walk on the primary --");
  {
    // If the !checked arm threw a plain freshnessError, a lost RUNLOG would classify to REASON_FRESHNESS.
    // Driven through the production walk, that is one attempt and a healthy replica never read: the exact cost
    // the freshness-unverifiable category exists to remove.
    const preChange = classifyRestoreFailure(freshnessError("freshness: RUNLOG absent"));
    ok("a bare freshness error classifies as REASON_FRESHNESS", preChange === REASON_FRESHNESS);
    let tries = 0;
    const stopped = await withRunDestFallback(schedulerStub(["primary", "replica"]), RUN_ID, undefined, async () => {
      tries++;
      return tries === 1 ? { ok: false, reason: preChange } : { ok: true };
    });
    ok("the pre-change reason stops the walk on the primary after ONE attempt", tries === 1 && stopped.ok === false);
    ok("so the healthy replica was never read, and the restore failed", (stopped as { reason?: string }).reason === REASON_FRESHNESS);
    ok("a first-choice refusal carries NO walk (absence, not a boolean nobody reads)", (stopped as { destFallback?: RestoreDestFallback }).destFallback === undefined);
  }

  console.log("-- 6. GREEN: a primary that lost its RUNLOG falls to a replica that VERIFIES, and says so --");
  let fallbackReceiptDigest = "";
  {
    const primary = await destFrom(objs);
    await primary.delete(RUNLOG_KEY);
    const replica = await destFrom(objs);
    const byId: Record<string, MemoryDestination> = { primary, replica };
    let served = "";
    const attempts: string[] = [];
    const result = (await withRunDestFallback(schedulerStub(["primary", "replica"]), RUN_ID, undefined, async (cfg, destFallback) => {
      const which = cfg?.bucket ?? "primary";
      attempts.push(which);
      served = which;
      // The REAL restore, opening THIS destination's own bytes: its own root, signature, shards, record
      // hashes and its own RUNLOG. Nothing is inherited from the refused attempt except the walk record.
      return (await runRestore(envFor(byId[which]!), { runId: RUN_ID, confirm: true }, null, { ...(destFallback !== undefined ? { destFallback } : {}) })) as RestoreResult;
    })) as RestoreResult;

    ok("the walk tried the primary and then the replica, in order", attempts.join(",") === "primary,replica");
    ok("the replica SERVED the restore and it VERIFIED end to end", result.ok === true && served === "replica");
    ok("every record it restored verified against the signed hashes", result.receipt?.summary.allVerified === true && result.recordsRestored === Object.keys(KVSET).length);

    // THE FALLBACK IS NOT SILENT.
    const fb = result.destFallback;
    ok("the result carries the walk", fb !== undefined);
    ok("it names the position the result came from, and it is never 1", fb?.servedAt === 2);
    ok("it names WHICH destination served the customer", fb?.servedDestinationId === "replica");
    ok("it names the destination that refused", fb?.refused.length === 1 && fb.refused[0]?.destinationId === "primary");
    ok("it names WHY the primary refused, in the engine's own reason vocabulary", fb?.refused[0]?.reason === REASON_FRESHNESS_UNVERIFIABLE);

    // AND IT IS INSIDE THE SIGNED CORE, so it cannot be stripped from the artefact the customer keeps.
    const receipt = result.receipt!;
    ok("the receipt carries the same walk as the result", JSON.stringify(receipt.destFallback) === JSON.stringify(fb));
    fallbackReceiptDigest = receipt.receiptSha384;
    ok("the receipt's digest is over a core that INCLUDES the walk", (await restoreReceiptDigestHex(receipt)) === receipt.receiptSha384);
    const { destFallback: _dropped, ...stripped } = receipt;
    ok("stripping the walk CHANGES the digest, so a replica-served receipt cannot pass as primary-served", (await restoreReceiptDigestHex(stripped)) !== receipt.receiptSha384);
  }

  console.log("-- 7. it does NOT fall back when it should not, and a first-choice restore is unchanged --");
  {
    // 7a. A first-choice restore: the replica is never read and NO walk is recorded anywhere.
    const primary = await destFrom(objs);
    const replica = await destFrom(objs);
    const byId: Record<string, MemoryDestination> = { primary, replica };
    const attempts: string[] = [];
    const clean = (await withRunDestFallback(schedulerStub(["primary", "replica"]), RUN_ID, undefined, async (cfg, destFallback) => {
      const which = cfg?.bucket ?? "primary";
      attempts.push(which);
      return (await runRestore(envFor(byId[which]!), { runId: RUN_ID, confirm: true }, null, { ...(destFallback !== undefined ? { destFallback } : {}) })) as RestoreResult;
    })) as RestoreResult;
    ok("a healthy primary serves the restore and the replica is never read", clean.ok === true && attempts.join(",") === "primary");
    ok("a first-choice result carries no walk at all", clean.destFallback === undefined);
    ok("and neither does its receipt, so it canonicalises as it did before this field existed", clean.receipt !== undefined && clean.receipt.destFallback === undefined);
    ok("a first-choice receipt digest differs from the replica-served one for the same run", clean.receipt?.receiptSha384 !== fallbackReceiptDigest);

    // 7b. An INTEGRITY fault on the primary is still terminal: a replica holds the SAME signed run, so reading
    // it could only mask the corruption. The walk must stop where it found it.
    const corrupt = await destFrom(objs);
    const segKey = [...objs.keys()].find((k) => k.startsWith("seg/"))!;
    await corrupt.delete(segKey);
    const corruptById: Record<string, MemoryDestination> = { primary: corrupt, replica };
    const tampAttempts: string[] = [];
    const tampered = (await withRunDestFallback(schedulerStub(["primary", "replica"]), RUN_ID, undefined, async (cfg, destFallback) => {
      const which = cfg?.bucket ?? "primary";
      tampAttempts.push(which);
      return (await runRestore(envFor(corruptById[which]!), { runId: RUN_ID, confirm: false }, null, { ...(destFallback !== undefined ? { destFallback } : {}) })) as RestoreResult;
    })) as RestoreResult;
    ok("a deleted segment on the primary reports the non-fallback integrity reason", tampered.ok === false && tampered.reason === REASON_INTEGRITY);
    ok("and the walk STOPS there: the replica is never read", tampAttempts.join(",") === "primary");
    ok("a terminal first-choice refusal records no walk", tampered.destFallback === undefined);
  }

  console.log("-- 8. when EVERY copy has lost its RUNLOG, the refusal reports the whole walk --");
  {
    // An operator told only that the restore failed, on a run whose copies failed for different reasons, has
    // been told the least useful version of what happened. The exhausted tail stamps the walk it made.
    const primary = await destFrom(objs);
    await primary.delete(RUNLOG_KEY);
    const replica = await destFrom(objs);
    await replica.put(RUNLOG_SIG_KEY, utf8("bm90LWEtc2lnbmF0dXJl"));
    const byId: Record<string, MemoryDestination> = { primary, replica };
    const attempts: string[] = [];
    const exhausted = (await withRunDestFallback(schedulerStub(["primary", "replica"]), RUN_ID, undefined, async (cfg, destFallback) => {
      const which = cfg?.bucket ?? "primary";
      attempts.push(which);
      return (await runRestore(envFor(byId[which]!), { runId: RUN_ID, confirm: false }, null, { ...(destFallback !== undefined ? { destFallback } : {}) })) as RestoreResult;
    })) as RestoreResult;
    ok("both destinations were tried", attempts.join(",") === "primary,replica");
    ok("the restore still REFUSES: no copy could be verified", exhausted.ok === false);
    ok("the refusal carries the walk rather than losing it", exhausted.destFallback?.servedAt === 2 && exhausted.destFallback.servedDestinationId === "replica");
    ok("and it names the destination that refused first, with its reason", exhausted.destFallback?.refused[0]?.destinationId === "primary" && exhausted.destFallback.refused[0]?.reason === REASON_FRESHNESS_UNVERIFIABLE);
  }

  console.log("-- 9. the receipt core: the walk moves the digest, and its absence restores the old bytes --");
  {
    const env = envFor(await destFrom(objs));
    const records: RestoreReceiptRecord[] = [{ name: "a", sourceType: "kv", expectedSha384: "aa", verifiedSha384: "aa", verified: true, via: "buffered-readback" }];
    const plain = await makeRestoreReceipt(env, RUN_ID, true, records, 1, 11);
    const walked = await makeRestoreReceipt(env, RUN_ID, true, records, 1, 11, 0, {}, { servedAt: 2, servedDestinationId: "replica", refused: [{ destinationId: "primary", reason: REASON_FRESHNESS_UNVERIFIABLE }] });
    ok("a receipt built without a walk declares no destFallback", plain.destFallback === undefined);
    ok("a receipt built WITH a walk declares it", walked.destFallback?.servedAt === 2);
    ok("the two digests DIFFER, so the walk is inside the hashed core and not beside it", plain.receiptSha384 !== walked.receiptSha384);
    ok("both receipts are self-consistent under the production digest", (await restoreReceiptDigestHex(plain)) === plain.receiptSha384 && (await restoreReceiptDigestHex(walked)) === walked.receiptSha384);
  }

  console.log(failures === 0 ? "\nFRESHNESS REPLICA FALLBACK PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

await main();
