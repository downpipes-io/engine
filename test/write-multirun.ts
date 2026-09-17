// Write a two-run history for one downpipe with an accumulated, signed RUNLOG, so the Go
// offline tool can prove anti-rollback: the latest run verifies, and the older run is
// reported stale (exit 5). Run: node test/write-multirun.ts <outdir>

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

import { x25519 } from "@noble/curves/ed25519.js";
import { mlkemKeygen, mldsaKeygen } from "../src/crypto/pq.ts";
import { buildArchive, type RecipientEntry, type Signer, type RunlogEntry } from "../src/format/writer.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";

const outDirArg = process.argv[2];
if (!outDirArg) throw new Error("usage: node test/write-multirun.ts <outdir>");
// Bind as a definite string: the throw-guard narrowing does not flow into the nested function bodies below.
const outDir: string = outDirArg;
const R1 = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const R2 = "01ARZ3NDEKTSV4RRFFQ69G5FB0";
const DP = "dp_history";

function rand(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}
function makeRecipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

async function main(): Promise<void> {
  const bg = makeRecipient("break-glass");
  const op = makeRecipient("operational");
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const edPublic = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
  const mldsa = mldsaKeygen();
  const signer: Signer = { edPrivate: ed.privateKey, edPublic, mldsaSecret: mldsa.secretKey, mldsaPublic: mldsa.publicKey };
  const recipients = [bg.entry, op.entry];

  const e1: RunlogEntry = { index: 1, runId: R1, downpipeId: DP, time: "2026-06-07T00:00:01.000Z", recordCount: 1, prevRunId: null, status: "active" };
  const e2: RunlogEntry = { index: 2, runId: R2, downpipeId: DP, time: "2026-06-07T01:00:01.000Z", recordCount: 1, prevRunId: R1, status: "active" };

  const common = {
    downpipeId: DP, downpipeName: "history", cadence: "0 * * * *",
    recipients, signer,
    windowStart: "2026-06-07T00:00:00.000Z", windowEnd: "2026-06-07T00:00:01.000Z",
    randomNonce: () => rand(16), randomSalt: () => rand(16),
  };

  // Run 1 (older): its RUNLOG has only e1.
  const run1 = await buildArchive({ ...common, runId: R1, master: rand(32), createdAt: e1.time, runlogIndex: 1, prevRunId: null, runlog: [e1], records: [{ sourceType: "kv", name: "k", value: utf8("run one value") }] });
  // Run 2 (latest): the accumulated RUNLOG [e1, e2] overwrites the shared anchor.
  const run2 = await buildArchive({ ...common, runId: R2, master: rand(32), createdAt: e2.time, runlogIndex: 2, prevRunId: R1, runlog: [e1, e2], records: [{ sourceType: "kv", name: "k", value: utf8("run two value") }] });

  for (const archive of [run1, run2]) {
    for (const [key, bytes] of archive) {
      const path = join(outDir, "archive", key);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, bytes);
    }
  }
  await writeFile(join(outDir, "identity.key"), `downpipe-identity-v1 ${b64urlEncode(bg.identity)}\n`);
  await writeFile(join(outDir, "signer.pub"), `downpipe-signer-public-v1 ${b64urlEncode(concat(edPublic, mldsa.publicKey))}\n`);
  console.log(`wrote a 2-run history to ${outDir} (older ${R1}, latest ${R2})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
