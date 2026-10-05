// RESTORE OVERWRITE CHECK AND NO-CLOBBER: drive the real restore path over a signed archive of two KV keys and
// two R2 objects, into a live namespace and bucket that already hold one key and one object of the same names.
//
// WHY: the in-account restore replaces a live KV key or R2 object of the same name, and the dry run never read
// the live target, so an operator could not see which live keys an apply would replace. The dry run now asks
// the target about each KV and R2 record and reports the answer, and an apply can be asked to keep the live
// keys (onExisting "skip"). This file pins both halves:
//
//   DRY RUN   counts existing / absent / unknown over the window, names a bounded sample, marks each preview
//             row, writes nothing, and never reads or returns a live value (the KV value stream is never
//             pulled, the R2 object is only HEADed, and the plan JSON carries no live bytes).
//   DEFAULT   an apply without onExisting (or with "overwrite") still replaces the live key and object, which
//             is the documented in-account restore. Unchanged.
//   SKIP      an apply with onExisting "skip" keeps the live key and object, writes the absent ones, reports
//             the kept ones in skipped with the reason, and a failed check writes nothing and is a failure.
//   HASH      "skip" is bound into the plan hash; "overwrite" and an absent field hash identically.
//   REFUSAL   an onExisting value outside the closed set is refused and writes nothing.
//   ECHO      every dry-run plan says which choice it planned with (plan.onExisting). A client needs that
//             proof before it sends a "skip" apply, because an older engine ignores the field and overwrites.
//   FAULTS    a failed check under "skip" lands in the support pack's restore fault ring as its own class,
//             exists-check-failed, and a kept live key is not a fault at all.
//
// Run: node test/validate-restore-overwrite-check.ts
// In-memory doubles only. No network, no account, no deploy, no cost.

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { restorePlanHash } from "../src/admin/approvals.ts";
import { classifyRestoreFaultClass } from "../src/admin/diag-records.ts";
import { runRestore } from "../src/admin/restore.ts";
import { restoreFaultRows } from "../src/admin/restore-faults.ts";
import { EXISTS_CHECK_FAILED_REASON, KEPT_EXISTING_REASON, OVERWRITE_SAMPLE_CAP } from "../src/admin/restore-sinks.ts";
import type { RestorePlan, RestoreRequest, RestoreResult } from "../src/admin/restore-types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen, mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, parseRunlog, type RecipientEntry, type Signer } from "../src/format/writer.ts";
import { loadSigner, verifierFrom } from "../src/keys-env.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const RUN = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const NS = "ns_overwrite";
const BUCKET = "bkt_overwrite";

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

function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}

const text = (b: Uint8Array | undefined): string | undefined => (b === undefined ? undefined : new TextDecoder().decode(b));

// LiveKV is the live namespace. A get for type "stream" returns a stream that has NOT pulled the value (high
// water mark 0), so valuePulls counts every time anyone actually read a live value. failGet makes every get
// throw, to model a binding that refuses the check.
class LiveKV {
  store = new Map<string, Uint8Array>();
  putCount = 0;
  valuePulls = 0;
  getCalls = 0;
  failGet = false;
  async put(k: string, v: ArrayBuffer | Uint8Array): Promise<void> {
    this.putCount++;
    this.store.set(k, v instanceof Uint8Array ? v : new Uint8Array(v));
  }
  async get(k: string, opts?: { type?: string } | string): Promise<ReadableStream<Uint8Array> | ArrayBuffer | null> {
    this.getCalls++;
    if (this.failGet) throw new Error("kv get refused");
    const v = this.store.get(k);
    if (v === undefined) return null;
    const type = typeof opts === "string" ? opts : opts?.type;
    if (type !== "stream") {
      this.valuePulls++;
      return toAB(v);
    }
    const self = this;
    return new ReadableStream<Uint8Array>(
      {
        pull(c) {
          self.valuePulls++;
          c.enqueue(v);
          c.close();
        },
      },
      { highWaterMark: 0 },
    );
  }
}

// LiveR2 is the live bucket. It counts head and get calls separately: the dry run may only HEAD it. The apply's
// post-write readback is a get, which is why getCalls is compared only on the dry run.
class LiveR2 {
  store = new Map<string, Uint8Array>();
  headCalls = 0;
  getCalls = 0;
  putCount = 0;
  failHead = false;
  async head(key: string): Promise<{ size: number } | null> {
    this.headCalls++;
    if (this.failHead) throw new Error("r2 head refused");
    const v = this.store.get(key);
    return v ? { size: v.byteLength } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.putCount++;
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
  async get(key: string): Promise<{ body: ReadableStream<Uint8Array> } | null> {
    this.getCalls++;
    const v = this.store.get(key);
    if (!v) return null;
    return {
      body: new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(v);
          c.close();
        },
      }),
    };
  }
}

// ArchiveR2 serves the sealed archive to the R2 destination the restore reads through.
class ArchiveR2 {
  store = new Map<string, Uint8Array>();
  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer>; etag: string } | null> {
    const v = this.store.get(key);
    return v ? { arrayBuffer: async () => toAB(v), etag: `"${key.length}"` } : null;
  }
  async head(key: string): Promise<{ etag: string } | null> {
    const v = this.store.get(key);
    return v ? { etag: `"${key.length}"` } : null;
  }
  async put(key: string, body: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.store.set(key, body instanceof Uint8Array ? body : new Uint8Array(body));
    return { etag: `"${key.length}"` };
  }
}

async function main(): Promise<void> {
  const edSeed = rand(32);
  const mldsaSeed = rand(32);
  const mldsa = mldsaKeygen(mldsaSeed);
  const signerPrivateB64 = b64urlEncode(concat(edSeed, mldsaSeed));
  const signer: Signer = await loadSigner(signerPrivateB64);
  const verifier = verifierFrom(signer);
  ok("signer public halves derive consistently", b64urlEncode(verifier.ed) === b64urlEncode(ed25519.getPublicKey(edSeed)) && b64urlEncode(verifier.mldsa) === b64urlEncode(mldsa.publicKey));
  const breakGlass = makeRecipient("break-glass");
  const op = makeRecipient("operational");

  // The archive: KV keys "a" (exists live) and "b" (absent live), R2 objects "x" (exists live) and "y" (absent).
  const archive = await buildArchive({
    downpipeId: "dp_overwrite",
    downpipeName: "overwrite",
    cadence: "3600s",
    runId: RUN,
    master: rand(32),
    recipients: [breakGlass.entry, op.entry],
    signer,
    records: [
      { sourceType: "kv", name: "a", value: utf8("archived-a"), namespace: NS },
      { sourceType: "kv", name: "b", value: utf8("archived-b"), namespace: NS },
      { sourceType: "r2", name: "x", value: utf8("archived-x"), bucket: BUCKET },
      { sourceType: "r2", name: "y", value: utf8("archived-y"), bucket: BUCKET },
    ],
    windowStart: "2026-06-07T00:00:00.000Z",
    windowEnd: "2026-06-07T00:00:01.000Z",
    createdAt: "2026-06-07T00:00:01.000Z",
    runlogIndex: 1,
    prevRunId: null,
    randomNonce: () => rand(16),
    randomSalt: () => rand(16),
  });
  const dest = new ArchiveR2();
  for (const [k, b] of archive) dest.store.set(k, b);
  ok("the archive's runlog carries this run", parseRunlog(archive.get("_RECOVERY/RUNLOG")!).some((e) => e.runId === RUN));

  // fresh builds a live namespace + bucket that hold "a" and "x" with LIVE values, and the env wired to them.
  const fresh = (): { kv: LiveKV; r2: LiveR2; env: Env } => {
    const kv = new LiveKV();
    const r2 = new LiveR2();
    kv.store.set("a", utf8("LIVE-VALUE-A"));
    r2.store.set("x", utf8("LIVE-VALUE-X"));
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: dest as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivateB64,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      [`KV_${NS}`]: kv as unknown as KVNamespace,
      [`R2_${BUCKET}`]: r2 as unknown as R2Bucket,
    } as unknown as Env;
    return { kv, r2, env };
  };

  // ---- DRY RUN: the overwrite check ----
  console.log("\nDRY RUN: which live keys and objects would an apply replace?");
  {
    const { kv, r2, env } = fresh();
    const plan = (await runRestore(env, { runId: RUN })) as RestorePlan;
    ok("the dry run planned all four records", plan.ok === true && plan.plannedWrites === 4);
    const oc = plan.overwriteCheck;
    ok("the plan carries an overwriteCheck", oc !== undefined);
    ok("it checked every KV and R2 record in the window", oc?.checked === 4);
    ok("it found the live key and the live object (2 existing)", oc?.existing === 2);
    ok("it found the two names an apply would create (2 absent)", oc?.absent === 2);
    ok("no check failed (0 unknown)", oc?.unknown === 0);
    ok("its sample names exactly the existing names, in window order", JSON.stringify(oc?.existingSample) === JSON.stringify(["a", "x"]));
    const row = (n: string) => plan.sample.find((s) => s.name === n);
    ok("the preview row for a live KV key says it exists", row("a")?.targetExists === true);
    ok("the preview row for an absent KV key says it does not", row("b")?.targetExists === false);
    ok("the preview row for a live R2 object says it exists", row("x")?.targetExists === true);
    ok("the preview row for an absent R2 object says it does not", row("y")?.targetExists === false);
    ok("the dry run wrote nothing to the namespace or the bucket", kv.putCount === 0 && r2.putCount === 0);
    ok("the live values are unchanged", text(kv.store.get("a")) === "LIVE-VALUE-A" && text(r2.store.get("x")) === "LIVE-VALUE-X");
    ok("the KV check never read a live value (the stream was cancelled unread)", kv.valuePulls === 0 && kv.getCalls === 2);
    ok("the R2 check was a head only, never a get of the object", r2.headCalls === 2 && r2.getCalls === 0);
    const wire = JSON.stringify(plan);
    ok("the plan returns no live value", !wire.includes("LIVE-VALUE-A") && !wire.includes("LIVE-VALUE-X"));
    ok('a plan without onExisting echoes "overwrite"', plan.onExisting === "overwrite");
  }

  // ---- DRY RUN: the plan echoes the choice it planned with ----
  console.log("\nDRY RUN: the plan echoes onExisting");
  {
    const { env } = fresh();
    const skipPlan = (await runRestore(env, { runId: RUN, onExisting: "skip" })) as RestorePlan;
    ok('a "skip" dry run echoes "skip"', skipPlan.ok === true && skipPlan.onExisting === "skip");
    const overwritePlan = (await runRestore(env, { runId: RUN, onExisting: "overwrite" })) as RestorePlan;
    ok('an "overwrite" dry run echoes "overwrite"', overwritePlan.ok === true && overwritePlan.onExisting === "overwrite");
  }

  // ---- DRY RUN: a check that fails is unknown, never a plan failure and never a guess ----
  console.log("\nDRY RUN: a check that fails");
  {
    const { kv, r2, env } = fresh();
    kv.failGet = true;
    r2.failHead = true;
    const plan = (await runRestore(env, { runId: RUN })) as RestorePlan;
    ok("a failed check does not fail the plan", plan.ok === true && plan.plannedWrites === 4);
    ok("every failed check counts as unknown", plan.overwriteCheck?.unknown === 4 && plan.overwriteCheck.existing === 0 && plan.overwriteCheck.absent === 0);
    ok("a row whose check failed carries no targetExists", plan.sample.every((s) => s.targetExists === undefined));
  }

  // ---- DRY RUN: the sample is bounded ----
  console.log("\nDRY RUN: the existing-name sample is bounded");
  ok("OVERWRITE_SAMPLE_CAP is a small positive bound", OVERWRITE_SAMPLE_CAP > 0 && OVERWRITE_SAMPLE_CAP <= 50);

  // ---- APPLY, default: the documented overwrite is unchanged ----
  console.log("\nAPPLY without onExisting: the documented overwrite");
  for (const req of [{ runId: RUN, confirm: true }, { runId: RUN, confirm: true, onExisting: "overwrite" as const }]) {
    const { kv, r2, env } = fresh();
    const res = (await runRestore(env, req)) as RestoreResult;
    const tag = req.onExisting === undefined ? "absent" : `"${req.onExisting}"`;
    ok(`onExisting ${tag}: all four records restored`, res.ok === true && res.recordsRestored === 4);
    ok(`onExisting ${tag}: the live KV key is replaced with the archived value`, text(kv.store.get("a")) === "archived-a");
    ok(`onExisting ${tag}: the live R2 object is replaced with the archived value`, text(r2.store.get("x")) === "archived-x");
  }

  // ---- APPLY, skip: keep the live key and object ----
  console.log('\nAPPLY with onExisting "skip": keep the live key and object');
  {
    const { kv, r2, env } = fresh();
    const res = (await runRestore(env, { runId: RUN, confirm: true, onExisting: "skip" })) as RestoreResult;
    ok("the apply is ok with no failures", res.ok === true && res.failures.length === 0);
    ok("it restored only the two absent names", res.recordsRestored === 2);
    ok("the live KV key keeps its live value", text(kv.store.get("a")) === "LIVE-VALUE-A");
    ok("the live R2 object keeps its live value", text(r2.store.get("x")) === "LIVE-VALUE-X");
    ok("the absent KV key is created", text(kv.store.get("b")) === "archived-b");
    ok("the absent R2 object is created", text(r2.store.get("y")) === "archived-y");
    const kept = (res.skipped ?? []).filter((s) => s.reason === KEPT_EXISTING_REASON).map((s) => s.name).sort();
    ok("the kept names are reported in skipped with the reason", JSON.stringify(kept) === JSON.stringify(["a", "x"]));
    ok("the receipt counts the kept names as skipped", res.receipt?.summary.recordsSkipped === 2);
    ok("the receipt has no entry for a kept name", !(res.receipt?.records ?? []).some((r) => r.name === "a" || r.name === "x"));
  }

  // ---- APPLY, skip, check fails: fail closed ----
  console.log('\nAPPLY with onExisting "skip" when the check fails');
  {
    const { kv, r2, env } = fresh();
    kv.failGet = true;
    r2.failHead = true;
    const res = (await runRestore(env, { runId: RUN, confirm: true, onExisting: "skip" })) as RestoreResult;
    ok("the apply is not ok", res.ok === false);
    ok("every record whose check failed is a failure", res.failures.length === 4);
    ok("nothing was written", kv.putCount === 0 && r2.putCount === 0);
    ok("the live values are unchanged", text(kv.store.get("a")) === "LIVE-VALUE-A" && text(r2.store.get("x")) === "LIVE-VALUE-X");
    ok("every failure carries the exists-check reason", res.failures.every((f) => f.reason === EXISTS_CHECK_FAILED_REASON));
    const rows = restoreFaultRows("apply", res);
    ok("the fault ring records the failed checks as exists-check-failed, in the write phase", rows.some((r) => r.cls === "exists-check-failed" && r.phase === "write" && r.count === 4));
    ok("no failed check falls to the residual other class", !rows.some((r) => r.cls === "other"));
  }

  // ---- FAULTS: the classifier and a kept live key ----
  console.log("\nFAULTS: the restore fault ring");
  {
    ok("the exists-check reason classifies as exists-check-failed", classifyRestoreFaultClass(EXISTS_CHECK_FAILED_REASON) === "exists-check-failed");
    const { env } = fresh();
    const res = (await runRestore(env, { runId: RUN, confirm: true, onExisting: "skip" })) as RestoreResult;
    ok("a keep-live-keys apply that kept two names is ok", res.ok === true && (res.skipped ?? []).some((s) => s.reason === KEPT_EXISTING_REASON));
    ok("a kept live key is not recorded as a fault", restoreFaultRows("apply", res).length === 0);
  }

  // ---- REFUSAL: an unknown onExisting value ----
  console.log("\nREFUSAL: an onExisting value outside the closed set");
  {
    const { kv, r2, env } = fresh();
    const bad = { runId: RUN, confirm: true, onExisting: "merge" } as unknown as RestoreRequest;
    const res = (await runRestore(env, bad)) as RestoreResult;
    ok("an unknown onExisting is refused", res.ok === false && typeof res.reason === "string" && res.reason.includes("onExisting"));
    ok("the refused apply wrote nothing", kv.putCount === 0 && r2.putCount === 0);
  }

  // ---- HASH: skip carries its own approval ----
  console.log("\nPLAN HASH");
  {
    const base = await restorePlanHash({ runId: RUN });
    ok('onExisting "skip" changes the plan hash', (await restorePlanHash({ runId: RUN, onExisting: "skip" })) !== base);
    ok('onExisting "overwrite" hashes as a request without the field', (await restorePlanHash({ runId: RUN, onExisting: "overwrite" })) === base);
  }

  verdictReached(failures);
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures}`);
  if (failures > 0) process.exit(1);
}

await main();
