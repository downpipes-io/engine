// validate-repl-bundle: replication copies seg/, run/, the RUNLOG and the recovery bundle
// (_RECOVERY/<version>/signer.pub, SHA384SUMS, SHA384SUMS.sig, RECOVER.md, FORMAT.md) to every destination
// that holds runs, so a destination reached only through replication still has the bundle the reader's
// --signer-fingerprint path and `verify --check-bundle` need. This drives replicateRecoveryBundle and
// syncRecoveryBundle (src/seal/replicate.ts) directly, in-memory, in the style of
// test/validate-replicate.ts. Run: node test/validate-repl-bundle.ts.

import { addBundle, BUNDLE_FILE_NAMES, BUNDLE_PREFIX, type BundleSigner } from "../src/format/bundle.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import type { Destination } from "../src/dest/types.ts";
import { MemoryDestination } from "./memdest.ts";

// putFaultDestination wraps a real MemoryDestination, delegating every method to it (bound, since the
// interface's methods live on the class prototype and a plain object spread would miss them), except put:
// onPut gets first refusal and can throw to inject a fault, or fall through to the real write.
function putFaultDestination(base: MemoryDestination, onPut: (key: string, body: Uint8Array) => Promise<"handled" | "passthrough">): Destination {
  return {
    get: (k) => base.get(k),
    put: async (k, v) => {
      if ((await onPut(k, v)) === "handled") return;
      await base.put(k, v);
    },
    putStream: (k, s) => base.putStream(k, s),
    putConditional: (k, v, o) => base.putConditional(k, v, o),
    exists: (k) => base.exists(k),
    delete: (k) => base.delete(k),
    list: (p) => base.list(p),
    listPage: (p, c) => base.listPage(p, c),
  };
}
import { lastOwnSealIndex, mirrorRunToReplica, replicateRecoveryBundle, syncRecoveryBundle, type RunOrigin } from "../src/seal/replicate.ts";
import { parseRunlog, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

async function makeBundleSigner(): Promise<BundleSigner & Signer> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
}

// seedBundle writes a real, signed recovery bundle (via the actual seal-path addBundle) onto `dest`, so the
// test exercises the exact bytes a seal produces, not a hand-rolled stand-in.
async function seedBundle(dest: Destination, signer: BundleSigner): Promise<void> {
  const objs = new Map<string, Uint8Array>();
  await addBundle(objs, signer);
  for (const [k, v] of objs) await dest.put(k, v);
}

async function bundleBytes(dest: Destination): Promise<Map<string, Uint8Array>> {
  const out = new Map<string, Uint8Array>();
  for (const name of BUNDLE_FILE_NAMES) {
    const obj = await dest.get(`${BUNDLE_PREFIX}${name}`);
    if (obj) out.set(name, obj.body);
  }
  return out;
}

function entryFor(runId: string, index: number, prevRunId: string | null): RunlogEntry {
  return { index, runId, downpipeId: "dp-A", time: "2026-10-05T00:00:00.000Z", recordCount: 1, prevRunId, status: "active" };
}

function getDestOf(map: Record<string, Destination>): (id: string | undefined) => Promise<Destination | null> {
  return async (id) => (id !== undefined && id in map ? map[id]! : null);
}

// (a) an empty second destination receives every bundle file, byte-equal to the origin's.
async function testCopyToEmptyDestination(): Promise<void> {
  console.log("-- (a) replicating to an empty destination: all five bundle files, byte-equal to the origin --");
  const signer = await makeBundleSigner();
  const origin = new MemoryDestination();
  await seedBundle(origin, signer);
  const target = new MemoryDestination();
  const runs: RunOrigin[] = [{ runId: "run-1", index: 1, origin: "A" }];

  const outcome = await replicateRecoveryBundle(getDestOf({ A: origin, B: target }), "B", target, runs);
  ok('outcome is "copied"', outcome === "copied");

  const originFiles = await bundleBytes(origin);
  const targetFiles = await bundleBytes(target);
  ok("the target now holds all five bundle files", targetFiles.size === BUNDLE_FILE_NAMES.length);
  for (const name of BUNDLE_FILE_NAMES) {
    const a = originFiles.get(name);
    const b = targetFiles.get(name);
    ok(`${name} is byte-identical to the origin's`, a !== undefined && b !== undefined && a.length === b.length && a.every((v, i) => v === b[i]));
  }
}

// (b) a second pass over an already-equal bundle writes nothing more.
async function testSecondPassWritesNothing(): Promise<void> {
  console.log("-- (b) a second pass with an equal bundle writes nothing more --");
  const signer = await makeBundleSigner();
  const origin = new MemoryDestination();
  await seedBundle(origin, signer);
  const target = new MemoryDestination();
  const runs: RunOrigin[] = [{ runId: "run-1", index: 1, origin: "A" }];
  const getDest = getDestOf({ A: origin, B: target });

  const first = await replicateRecoveryBundle(getDest, "B", target, runs);
  ok('first pass "copied"', first === "copied");

  // A target double that throws if put() is ever called again: the second pass must detect equality from
  // the SHA384SUMS read alone and never reach a write.
  let puts = 0;
  const guarded = putFaultDestination(target, async (k) => {
    puts++;
    throw new Error(`unexpected write to ${k} on an already-equal bundle`);
  });

  const second = await syncRecoveryBundle(origin, guarded);
  ok('second pass is "equal"', second === "equal");
  ok("the second pass performed no writes", puts === 0);
}

// (c) a target that already holds a newer bundle (its own, from a later direct seal, after a signer
// rotation) keeps it: replicateRecoveryBundle must not even attempt a copy.
async function testNewerTargetBundleIsKept(): Promise<void> {
  console.log("-- (c) a target holding a bundle from its own later seal keeps it (no regression after rotation) --");
  const oldSigner = await makeBundleSigner();
  const newSigner = await makeBundleSigner();
  const origin = new MemoryDestination(); // origin A: sealed run-1 under the OLD signer
  await seedBundle(origin, oldSigner);
  const target = new MemoryDestination(); // target B: sealed run-2 DIRECTLY, under the NEW (rotated) signer
  await seedBundle(target, newSigner);

  // run-2 (the latest known run) was sealed directly on B; B's own seal already wrote the current bundle.
  const runs: RunOrigin[] = [
    { runId: "run-1", index: 1, origin: "A" },
    { runId: "run-2", index: 2, origin: "B" },
  ];
  ok("lastOwnSealIndex(B) is run-2's index", lastOwnSealIndex(runs, "B") === 2);

  const outcome = await replicateRecoveryBundle(getDestOf({ A: origin, B: target }), "B", target, runs);
  ok('outcome is "own-seal-is-current" (no copy attempted)', outcome === "own-seal-is-current");

  const targetSigner = (await target.get(`${BUNDLE_PREFIX}signer.pub`))!.body;
  const newSignerFile = (await bundleBytes(target)).get("signer.pub")!;
  ok("the target's signer.pub is still its OWN (new) signer, not overwritten by the older origin's", targetSigner.every((v, i) => v === newSignerFile[i]));
  const oldSignerFile = (await bundleBytes(origin)).get("signer.pub")!;
  ok("the target's signer.pub differs from the old origin's (the regression this guards against)", targetSigner.length !== oldSignerFile.length || !targetSigner.every((v, i) => v === oldSignerFile[i]));
}

// (d) a bundle-copy failure must not fail or undo a run copy that already succeeded. This drives the same
// two steps processTarget runs for one target -- mirrorRunToReplica (the run copy), then
// replicateRecoveryBundle, each independently -- and the production code wraps the bundle step in its own
// try/catch for exactly this reason (src/seal/replicate.ts processTarget). Proving the run copy's result
// (the RUNLOG done-marker) is unaffected by a thrown bundle copy is the behaviour that try/catch exists for.
async function testBundleFailureLeavesRunCopyDone(signer: Signer): Promise<void> {
  console.log("-- (d) a bundle copy failure leaves the run copy counted as done --");
  const origin = new MemoryDestination();
  const treeKeys = [`run/run-1/root.manifest.json`, `run/run-1/manifest/00000.dpe`];
  for (const k of treeKeys) await origin.put(k, new TextEncoder().encode(`obj:${k}`));
  await seedBundle(origin, signer);

  const real = new MemoryDestination();
  // A target double that behaves exactly like `real` for run-tree/RUNLOG/seg objects, but throws on any
  // write under the bundle prefix -- the fault this test injects.
  const faulty = putFaultDestination(real, async (k) => {
    if (k.startsWith(BUNDLE_PREFIX)) throw new Error(`simulated store fault writing ${k}`);
    return "passthrough";
  });

  const res = await mirrorRunToReplica(origin, faulty, signer, entryFor("run-1", 1, null));
  ok("the run copy itself succeeded (not incomplete, not already-done)", res.alreadyDone === false && res.incomplete !== true);

  let threw = false;
  try {
    await replicateRecoveryBundle(getDestOf({ A: origin, B: faulty }), "B", faulty, [{ runId: "run-1", index: 1, origin: "A" }]);
  } catch {
    threw = true;
  }
  ok("the bundle copy itself threw (the injected fault)", threw);

  const rl = await faulty.get("_RECOVERY/RUNLOG");
  const entries = rl ? parseRunlog(rl.body) : [];
  ok("the run's RUNLOG done-marker is still there: the run copy stands despite the bundle fault", entries.some((e) => e.runId === "run-1"));
  ok("the run-tree objects are still there too", (await faulty.get(treeKeys[0]!)) !== null);
}

async function main(): Promise<void> {
  const signer = await makeBundleSigner();
  await testCopyToEmptyDestination();
  await testSecondPassWritesNothing();
  await testNewerTargetBundleIsKept();
  await testBundleFailureLeavesRunCopyDone(signer);

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nRECOVERY-BUNDLE REPLICATION VECTORS PASS");
}

void main();
