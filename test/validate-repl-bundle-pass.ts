// validate-repl-bundle-pass: replication copies the recovery bundle to every destination that holds runs,
// driven through the REAL cron entry point (runReplications), not the injectable per-call cores. One
// downpipe, two real S3-shaped destinations (A, the origin a run is sealed to directly; B, empty), a real
// SchedulerDO over in-memory storage, and a stateful S3 wire standing in for both buckets (no network, no
// disk): exactly the harness test/validate-repl-backfill-dest-removal.ts and test/validate-repl-fairness.ts
// already drive runReplications with, trimmed to the smallest estate that can prove this.
//
// Unlike test/validate-repl-bundle.ts (which drives the injectable syncRecoveryBundle /
// replicateRecoveryBundle cores directly and needs their exports to even import), this file imports ONLY
// names that exist at an engine that does not copy the bundle (buildArchive, appendRunlog, runReplications,
// SchedulerDO, S3Destination, ...), so it also serves as a behavioural check against that engine: it
// compiles and runs cleanly there and FAILS ON THE ASSERTION. B's RUNLOG gains the run (the run-tree copy
// does not depend on the bundle step), but B holds none of the five recovery-bundle files. With the bundle
// step in place, the same pass leaves B with every bundle file byte-identical to A's.
//
// Run: node test/validate-repl-bundle-pass.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import { S3Destination } from "../src/dest/s3.ts";
import type { Env } from "../src/env.d.ts";
import { BUNDLE_PREFIX, BUNDLE_SIGNER_NAME } from "../src/format/bundle.ts";
import { buildArchive, type RecipientEntry, type RunlogEntry } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { SliceBudget } from "../src/seal/budget.ts";
import { appendRunlog } from "../src/seal/pipeline.ts";
import { runReplications } from "../src/seal/replicate.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { S3Wire } from "./lib/s3-wire.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const ENDPOINT = "https://s3.example.test";
const A = "dest-a";
const B = "dest-b";
const BUCKET: Record<string, string> = { [A]: "bucket-a", [B]: "bucket-b" };
const DP = "dp-replica-bundle";
const RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

// The bundle's five files (format/bundle.ts addBundle), named here as the production reader and the
// SHA384SUMS line do, not imported from replicate.ts so this file compiles unmodified at an engine that
// does not copy the bundle.
const BUNDLE_FILES = ["FORMAT.md", "RECOVER.md", BUNDLE_SIGNER_NAME, "SHA384SUMS.sig", "SHA384SUMS"];

function storedDest(id: string): Record<string, unknown> {
  return { id, label: id, endpoint: ENDPOINT, bucket: BUCKET[id], region: "auto", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "not-a-real-secret", addressing: "path", setAt: 1, setBy: "owner@acme.example", verifiedAt: 1, deleteProbe: "ok" };
}

async function main(): Promise<void> {
  console.log("-- behavioural: runReplications leaves B holding the recovery bundle byte-equal to A's --");

  const wire = new S3Wire(ENDPOINT);
  wire.install();
  try {
    const signerPrivateB64 = b64urlEncode(crypto.getRandomValues(new Uint8Array(64)));
    const signer = await loadSigner(signerPrivateB64);
    const recipients: RecipientEntry[] = ["break-glass", "operational"].map((role) => ({
      role,
      pub: { x25519: x25519.keygen().publicKey, mlkemEk: mlkemKeygen(crypto.getRandomValues(new Uint8Array(64))).encapKey },
    }));

    // Seal ONE run directly to A: a real archive (records + signed root + RUNLOG + recovery bundle, via
    // the same finaliseArchive/addBundle path every production seal runs).
    const a = new S3Destination(ENDPOINT, BUCKET[A]!, "auto", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
    const archive = await buildArchive({
      downpipeId: DP,
      downpipeName: "replica-bundle-behavioural",
      cadence: "86400s",
      runId: RUN_ID,
      master: crypto.getRandomValues(new Uint8Array(32)),
      recipients,
      signer,
      records: [{ sourceType: "kv", name: "greeting", namespace: "ns", value: utf8("replication behavioural pass check") }],
      windowStart: "2026-10-05T00:00:00.000Z",
      windowEnd: "2026-10-05T00:00:01.000Z",
      createdAt: "2026-10-05T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId: null,
      skipRunlog: true, // appended below via appendRunlog, matching the real seal pipeline's own call
      randomNonce: () => crypto.getRandomValues(new Uint8Array(16)),
      randomSalt: () => crypto.getRandomValues(new Uint8Array(16)),
    });
    for (const [key, bytes] of archive) await a.put(key, bytes);
    const entry: RunlogEntry = { index: 1, runId: RUN_ID, downpipeId: DP, time: "2026-10-05T00:00:01.000Z", recordCount: 1, prevRunId: null, status: "active" };
    await appendRunlog(a, signer, entry, undefined, { relinkLocalPrev: true });

    // The scheduler DO's state: one downpipe fanned out to A and B, A's history carries the one ok run with
    // its origin, B is a destination record with nothing copied to it yet.
    const storage = new MockStorage();
    storage.seed("destinations", { list: [storedDest(A), storedDest(B)], defaultId: A });
    storage.seed(`dp:${DP}`, {
      config: { id: DP, name: "replica-bundle-behavioural", cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: [A, B] },
      nextRunAt: Date.now() + 86_400_000,
      lastRunId: RUN_ID,
      inFlight: false,
      sealedRuns: 1,
    });
    storage.seed(`hist:${DP}`, [{ runId: RUN_ID, index: 1, startedAt: entry.time, status: "ok", destinationId: A, prevRunId: null }]);

    const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
    const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
    const env = { SIGNER_PRIVATE: signerPrivateB64 } as unknown as Env;

    // ONE cron pass, the real entry point, a fresh default-sized budget (one tiny run is nowhere near it).
    await runReplications(env, scheduler, new SliceBudget());

    const b = new S3Destination(ENDPOINT, BUCKET[B]!, "auto", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
    const runlogOnB = await b.get("_RECOVERY/RUNLOG");
    ok("B's RUNLOG holds the run", runlogOnB !== null && new TextDecoder().decode(runlogOnB.body).includes(RUN_ID));

    for (const name of BUNDLE_FILES) {
      const key = `${BUNDLE_PREFIX}${name}`;
      const onA = await a.get(key);
      const onB = await b.get(key);
      const equal = onA !== null && onB !== null && onA.body.length === onB.body.length && onA.body.every((v, i) => v === onB.body[i]);
      ok(`B holds ${name} byte-identical to A's`, equal);
    }
  } finally {
    wire.uninstall();
  }

  verdictReached(failures);
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nBEHAVIOURAL REPLICATION-PASS CHECK PASSES");
}

void main();
