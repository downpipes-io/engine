// Writes a downpipe/0.1.0 archive with the engine's TypeScript writer, replicates it to a SECOND, empty
// destination with the real replication cores (mirrorRunToReplica for the run, replicateRecoveryBundle for
// the recovery bundle), then flushes the REPLICA's objects plus the break-glass identity and a signer.pub
// kit file to disk, in the Go CLI's labelled formats. scripts/e2e-replica-bundle.sh runs this twice (with
// and without the bundle step) and drives the Go reader against both, proving that a destination reached
// only through replication is a self-sufficient, verifiable archive once the bundle is copied, and is not
// otherwise.
//
// Usage: node test/write-replica-bundle.ts <outdir> [with-bundle|no-bundle]  (default: with-bundle)

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import type { Destination } from "../src/dest/types.ts";
import { buildArchive, type RecipientEntry, type RunlogEntry, type Signer } from "../src/format/writer.ts";
import { mirrorRunToReplica, replicateRecoveryBundle, type RunOrigin } from "../src/seal/replicate.ts";
import { MemoryDestination } from "./memdest.ts";

const outDirArg = process.argv[2];
if (!outDirArg) throw new Error("usage: node test/write-replica-bundle.ts <outdir> [with-bundle|no-bundle]");
const outDir: string = outDirArg;
const mode = process.argv[3] === "no-bundle" ? "no-bundle" : "with-bundle";
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const PRIMARY_ID = "primary";
const REPLICA_ID = "replica";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  const ek = mlkemKeygen(seed).encapKey;
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: ek } }, identity: concat(xk.secretKey, seed) };
}

async function flush(dest: MemoryDestination, dir: string): Promise<void> {
  for (const [key, bytes] of dest.entries()) {
    const path = join(dir, key);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, bytes);
  }
}

async function main(): Promise<void> {
  const breakGlass = makeRecipient("break-glass");
  const operational = makeRecipient("operational");
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };

  const primary = new MemoryDestination();
  const archive = await buildArchive(
    {
      downpipeId: "dp_replica_bundle_check",
      downpipeName: "replica-bundle-check",
      cadence: "0 * * * *",
      runId: RUN_ID,
      master: rand(32),
      recipients: [breakGlass.entry, operational.entry],
      signer,
      records: [{ sourceType: "kv", name: "greeting", value: utf8("the engine wrote this; a replica-only destination recovers it") }],
      windowStart: "2026-10-05T00:00:00.000Z",
      windowEnd: "2026-10-05T00:00:01.000Z",
      createdAt: "2026-10-05T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId: null,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    },
    { dest: primary },
  );
  for (const [key, bytes] of archive) await primary.put(key, bytes);

  // The replica holds nothing until replication runs: this is the destination a run was never sealed to
  // directly, reached only through replication.
  const replica = new MemoryDestination();
  const entry: RunlogEntry = { index: 1, runId: RUN_ID, downpipeId: "dp_replica_bundle_check", time: "2026-10-05T00:00:01.000Z", recordCount: 1, prevRunId: null, status: "active" };
  const runRes = await mirrorRunToReplica(primary, replica, signer, entry);
  if (runRes.incomplete || runRes.alreadyDone) throw new Error(`mirrorRunToReplica did not complete cleanly: ${JSON.stringify(runRes)}`);

  if (mode === "with-bundle") {
    const runs: RunOrigin[] = [{ runId: RUN_ID, index: 1, origin: PRIMARY_ID }];
    const getDest = async (id: string | undefined): Promise<Destination | null> => (id === PRIMARY_ID ? primary : id === REPLICA_ID ? replica : null);
    const outcome = await replicateRecoveryBundle(getDest, REPLICA_ID, replica, runs);
    if (outcome !== "copied") throw new Error(`replicateRecoveryBundle did not copy (mode=with-bundle): ${outcome}`);
  }
  // mode === "no-bundle": the negative control. replicateRecoveryBundle is never called, so the run copies
  // and the bundle does not: the shape this script's reader check must independently fail against.

  await flush(replica, join(outDir, "archive"));
  await writeFile(join(outDir, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(breakGlass.identity)}\n`);
  await writeFile(join(outDir, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(concat(edPublic, mldsa.publicKey))}\n`);
  console.log(`wrote a replica-only archive (${mode}) + keys to ${outDir} (run ${RUN_ID})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
