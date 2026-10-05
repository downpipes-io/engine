// Generates test/fixtures/repl-v035/state.json: the replication state that engine 0.3.5 (release commit
// 6a093886) writes, for test/validate-repl-backcompat-v035.ts. It is NOT a hand-made fixture: every object
// and every scheduler row in it was written by the 0.3.5 source.
//
// WHAT IT DOES. It extracts src/ and test/mock-storage.ts at 6a093886 into a temporary directory inside
// this checkout (so the 0.3.5 source resolves this checkout's node_modules), and with that source only:
//   1. seals runs 1 to 4 to destination A (downpipe dp-0 takes the odd indexes, dp-1 the even ones) and
//      completes each through the 0.3.5 SchedulerDO, so A's rows are the ones a 0.3.5 seal records;
//   2. runs the 0.3.5 replication pass (runReplications) until B's RUNLOG holds runs 1 to 4, so B's RUNLOG
//      entries and the repl:<dp> rows for B, with [holdsFrom, holdsIndex], are the ones 0.3.5 writes;
//   3. seals runs 5 and 6 to A only, so the upgraded engine has a backlog to add on top of 0.3.5's copies.
// It writes the two buckets (every object, base64) and every scheduler storage row.
//
// The run signer is derived from a fixed label (fixtureSigner below), so the validator can append to the
// same RUNLOGs without the fixture carrying a key. The archives' recipient keys are random and discarded:
// replication is keyless and never opens a record.
//
// Run by hand when the fixture must change: node test/fixtures/repl-v035/generate.ts
// It needs the git history of 6a093886 (a full clone, not a shallow one).

import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { fixtureSigner, V035_COMMIT, V035_FIXTURE_ENDPOINT } from "./shared.ts";
import { S3Wire } from "../../lib/s3-wire.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const OUT = join(HERE, "state.json");
const A = "dest-a";
const B = "dest-b";
const BUCKET: Record<string, string> = { [A]: "archive", [B]: "archive2" };
const DPS = ["dp-0", "dp-1"];

function runId(i: number): string {
  return `01K5ZZKBKACTAV9WEVGEMMVR${String(i).padStart(2, "0")}`;
}

async function main(): Promise<void> {
  const tmp = join(ROOT, `.tmp-repl-v035-${process.pid}`);
  mkdirSync(tmp);
  try {
    const tar = execFileSync("git", ["-C", ROOT, "archive", "--format=tar", V035_COMMIT, "src", "test/mock-storage.ts", "package.json"], { maxBuffer: 256 * 1024 * 1024 });
    execFileSync("tar", ["-x", "-C", tmp], { input: tar });
    const version = (JSON.parse(execFileSync("git", ["-C", ROOT, "show", `${V035_COMMIT}:package.json`]).toString()) as { version: string }).version;
    if (version !== "0.3.5") throw new Error(`${V035_COMMIT} is version ${version}, not 0.3.5`);
    const src = (p: string): string => pathToFileURL(join(tmp, "src", p)).href;
    const { SchedulerDO } = (await import(src("sched/scheduler-do.ts"))) as typeof import("../../../src/sched/scheduler-do.ts");
    const { runReplications } = (await import(src("seal/replicate.ts"))) as typeof import("../../../src/seal/replicate.ts");
    const { SliceBudget } = (await import(src("seal/budget.ts"))) as typeof import("../../../src/seal/budget.ts");
    const { appendRunlog } = (await import(src("seal/pipeline.ts"))) as typeof import("../../../src/seal/pipeline.ts");
    const { buildArchive, parseRunlog } = (await import(src("format/writer.ts"))) as typeof import("../../../src/format/writer.ts");
    const { S3Destination } = (await import(src("dest/s3.ts"))) as typeof import("../../../src/dest/s3.ts");
    const { loadSigner } = (await import(src("keys-env.ts"))) as typeof import("../../../src/keys-env.ts");
    const { utf8 } = (await import(src("crypto/bytes.ts"))) as typeof import("../../../src/crypto/bytes.ts");
    const { mlkemKeygen } = (await import(src("crypto/pq.ts"))) as typeof import("../../../src/crypto/pq.ts");
    const { MockStorage } = (await import(pathToFileURL(join(tmp, "test", "mock-storage.ts")).href)) as typeof import("../../mock-storage.ts");
    const { x25519 } = await import("@noble/curves/ed25519.js");

    const wire = new S3Wire(V035_FIXTURE_ENDPOINT);
    wire.install();
    try {
      const signerPrivate = await fixtureSigner();
      const signer = await loadSigner(signerPrivate);
      const recipients = ["break-glass", "operational"].map((role) => ({ role, pub: { x25519: x25519.keygen().publicKey, mlkemEk: mlkemKeygen(crypto.getRandomValues(new Uint8Array(64))).encapKey } }));
      const a = new S3Destination(V035_FIXTURE_ENDPOINT, BUCKET[A]!, "auto", "AKIDEXAMPLE", "not-a-real-secret", { addressing: "path" });
      const storage = new MockStorage();
      const stored = (id: string): Record<string, unknown> => ({ id, label: id, endpoint: V035_FIXTURE_ENDPOINT, bucket: BUCKET[id], region: "auto", accessKeyId: "AKIDEXAMPLE", secretAccessKey: "not-a-real-secret", addressing: "path", setAt: 1, setBy: "owner@acme.example", verifiedAt: 1, deleteProbe: "ok" });
      storage.seed("destinations", { list: [stored(A), stored(B)], defaultId: A });
      for (const dp of DPS) {
        storage.seed(`dp:${dp}`, { config: { id: dp, name: dp, cadenceSeconds: 86400, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds: [A, B] }, nextRunAt: Date.now() + 86_400_000, lastRunId: null, inFlight: false, sealedRuns: 0 });
        storage.seed(`hist:${dp}`, []);
      }
      const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
      const scheduler = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(input, init)) } as unknown as DurableObjectStub;
      const env = { SIGNER_PRIVATE: signerPrivate } as unknown as import("../../../src/env.d.ts").Env;
      const prev: Record<string, string | null> = { "dp-0": null, "dp-1": null };

      // seal writes run i to A with the 0.3.5 writer and completes it through the 0.3.5 SchedulerDO.
      const seal = async (i: number): Promise<void> => {
        const dp = DPS[(i - 1) % 2]!;
        const id = runId(i);
        const archive = await buildArchive({
          downpipeId: dp, downpipeName: dp, cadence: "86400s", runId: id, master: crypto.getRandomValues(new Uint8Array(32)), recipients, signer,
          records: Array.from({ length: 2 }, (_, r) => ({ sourceType: "kv" as const, name: `rec-${r}`, namespace: "ns", value: utf8(`value-${i}-${r}`) })),
          windowStart: "2026-09-20T08:00:00.000Z", windowEnd: "2026-09-20T08:00:01.000Z", createdAt: "2026-09-20T08:00:01.000Z",
          runlogIndex: i, prevRunId: prev[dp]!, skipRunlog: true, randomNonce: () => crypto.getRandomValues(new Uint8Array(16)), randomSalt: () => crypto.getRandomValues(new Uint8Array(16)),
        });
        for (const [k, v] of archive) await a.put(k, v);
        const time = `2026-09-20T08:0${i}:00.000Z`;
        await appendRunlog(a, signer, { index: i, runId: id, downpipeId: dp, time, recordCount: 2, prevRunId: prev[dp]!, status: "active" }, undefined, { relinkLocalPrev: true });
        const ring = (await storage.get<Array<Record<string, unknown>>>(`hist:${dp}`))!;
        ring.push({ runId: id, index: i, startedAt: time, status: "in-flight", prevRunId: prev[dp] });
        await storage.put(`hist:${dp}`, ring);
        const st = (await storage.get<Record<string, unknown>>(`dp:${dp}`))!;
        st.inFlight = true;
        await storage.put(`dp:${dp}`, st);
        await dobj.completeRun({ id: dp, runId: id, index: i, status: "ok", destinationId: A, recordCount: 2 });
        prev[dp] = id;
      };

      for (let i = 1; i <= 4; i++) await seal(i);
      const onB = (): number[] => {
        const rl = wire.bucket(BUCKET[B]!).get("_RECOVERY/RUNLOG");
        return rl ? parseRunlog(rl.bytes).map((x) => x.index).sort((p, q) => p - q) : [];
      };
      for (let t = 0; t < 10 && onB().length < 4; t++) await runReplications(env, scheduler, new SliceBudget());
      if (JSON.stringify(onB()) !== "[1,2,3,4]") throw new Error(`0.3.5 replication left B holding [${onB()}], not runs 1 to 4`);
      for (let i = 5; i <= 6; i++) await seal(i);

      const buckets: Record<string, Record<string, string>> = {};
      for (const [name, objs] of wire.buckets) {
        buckets[name] = {};
        for (const [k, o] of [...objs.entries()].sort(([p], [q]) => (p < q ? -1 : 1))) buckets[name]![k] = Buffer.from(o.bytes).toString("base64");
      }
      const rows: Record<string, unknown> = {};
      for (const k of [...storage.raw().keys()].sort()) rows[k] = storage.raw().get(k);
      const state = { generatedBy: "test/fixtures/repl-v035/generate.ts", engine: { version, commit: V035_COMMIT }, endpoint: V035_FIXTURE_ENDPOINT, destinations: { A, B }, buckets: BUCKET, objects: buckets, storage: rows };
      writeFileSync(OUT, `${JSON.stringify(state, null, 1)}\n`);
      console.log(`wrote ${OUT}: ${Object.values(buckets).reduce((n, b) => n + Object.keys(b).length, 0)} objects, ${Object.keys(rows).length} storage rows; B holds [${onB()}]`);
    } finally {
      wire.uninstall();
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

await main();
