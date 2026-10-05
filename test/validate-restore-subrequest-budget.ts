// IN-ACCOUNT RESTORE SUBREQUEST BUDGET: count every destination and binding call a restore makes, at the
// in-account ceilings, and pin the figures the ceiling rationale in src/admin/restore-sinks.ts states.
//
// WHY: the in-account restore runs its whole window in one Worker invocation, and the platform caps the
// subrequests one invocation can make at about 1000. MAX_IN_ACCOUNT_RESTORE_RECORDS (200) was budgeted on
// that cap. An apply under onExisting "skip" adds one existence check per KV or R2 record, and a 200-record
// R2 window then costs 1005 calls, over the budget. So a "skip" request has its own, lower ceiling
// (MAX_IN_ACCOUNT_SKIP_RESTORE_RECORDS), and this file measures the cost rather than asserting it:
//
//   MEASURED  the calls a default apply, a "skip" apply and a dry run make, each at its own ceiling, for R2
//             and for KV. The figures are the ones the ceiling comment states, so a change that adds a call
//             per record turns this red and the comment gets re-measured.
//   BUDGET    every accepted in-account mode at its ceiling stays at or under the 200-record default apply.
//   REFUSAL   a "skip" apply or dry run over the "skip" ceiling is refused before any write, naming the
//             "skip" ceiling; a default apply of the same window is still accepted.
//
// Run: node test/validate-restore-subrequest-budget.ts
// In-memory doubles only. No network, no account, no deploy, no cost.

import { x25519 } from "@noble/curves/ed25519.js";
import { runRestore } from "../src/admin/restore.ts";
import { MAX_IN_ACCOUNT_RESTORE_RECORDS, MAX_IN_ACCOUNT_SKIP_RESTORE_RECORDS } from "../src/admin/restore-sinks.ts";
import type { RestorePlan, RestoreRequest, RestoreResult } from "../src/admin/restore-types.ts";
import { b64urlEncode, concat, utf8 } from "../src/crypto/bytes.ts";
import { mlkemKeygen } from "../src/crypto/pq.ts";
import type { Env } from "../src/env.d.ts";
import { buildArchive, type RecipientEntry } from "../src/format/writer.ts";
import { loadSigner } from "../src/keys-env.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

const RUN = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
// The per-invocation subrequest budget the ceiling rationale is written against.
const PLATFORM_BUDGET = 1000;

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const rand = (n: number): Uint8Array => crypto.getRandomValues(new Uint8Array(n));
function toAB(b: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(b.byteLength);
  new Uint8Array(out).set(b);
  return out;
}
function recipient(role: string): { entry: RecipientEntry; identity: Uint8Array } {
  const xk = x25519.keygen();
  const seed = rand(64);
  return { entry: { role, pub: { x25519: xk.publicKey, mlkemEk: mlkemKeygen(seed).encapKey } }, identity: concat(xk.secretKey, seed) };
}

// Counting is a store that counts every call made to it. It serves as the archive destination (R2), the live
// R2 bucket and the live KV namespace, so the total is every subrequest the restore spends on bindings.
class Counting {
  calls = 0;
  store = new Map<string, Uint8Array>();
  async get(k: string, opts?: { type?: string } | string): Promise<unknown> {
    this.calls++;
    const v = this.store.get(k);
    if (v === undefined) return null;
    const type = typeof opts === "string" ? opts : opts?.type;
    const stream = (): ReadableStream<Uint8Array> =>
      new ReadableStream<Uint8Array>({
        start(c) {
          c.enqueue(v);
          c.close();
        },
      });
    if (type === "stream") return stream();
    return { arrayBuffer: async () => toAB(v), etag: '"e"', body: stream() };
  }
  async head(k: string): Promise<{ etag: string; size: number } | null> {
    this.calls++;
    const v = this.store.get(k);
    return v ? { etag: '"e"', size: v.byteLength } : null;
  }
  async put(k: string, b: ArrayBuffer | Uint8Array): Promise<{ etag: string }> {
    this.calls++;
    this.store.set(k, b instanceof Uint8Array ? b : new Uint8Array(b));
    return { etag: '"e"' };
  }
}

type Kind = "r2" | "kv";
// Outcome is the part of a plan or an apply result this file reads. A dry run returns a RestorePlan and an
// apply a RestoreResult; both carry these fields.
type Outcome = { ok: boolean; reason?: string; recordsRestored?: number; plannedWrites?: number; complete?: boolean };

async function main(): Promise<void> {
  const signerPrivate = b64urlEncode(concat(rand(32), rand(32)));
  const signer = await loadSigner(signerPrivate);
  const breakGlass = recipient("break-glass");
  const op = recipient("operational");

  // archive seals n small records of one kind, all absent from the live target, which is the worst case for
  // a "skip" apply: every record pays the check AND the write.
  const archives = new Map<string, Map<string, Uint8Array>>();
  async function archive(kind: Kind, n: number): Promise<Map<string, Uint8Array>> {
    const key = `${kind}:${n}`;
    const hit = archives.get(key);
    if (hit) return hit;
    const records = Array.from({ length: n }, (_, i) =>
      kind === "r2" ? { sourceType: "r2" as const, name: `o${i}`, value: utf8(`v${i}`), bucket: "b" } : { sourceType: "kv" as const, name: `k${i}`, value: utf8(`v${i}`), namespace: "n" },
    );
    const built = await buildArchive({
      downpipeId: "dp_budget",
      downpipeName: "budget",
      cadence: "3600s",
      runId: RUN,
      master: rand(32),
      recipients: [breakGlass.entry, op.entry],
      signer,
      records,
      windowStart: "2026-06-07T00:00:00.000Z",
      windowEnd: "2026-06-07T00:00:01.000Z",
      createdAt: "2026-06-07T00:00:01.000Z",
      runlogIndex: 1,
      prevRunId: null,
      randomNonce: () => rand(16),
      randomSalt: () => rand(16),
    });
    archives.set(key, built);
    return built;
  }

  // measure runs one restore request against a fresh counting destination and a fresh, empty live target,
  // and returns the result, the total calls, and the live writes.
  async function measure(kind: Kind, n: number, req: Omit<RestoreRequest, "runId">): Promise<{ res: Outcome; calls: number; writes: number }> {
    const dest = new Counting();
    for (const [k, b] of await archive(kind, n)) dest.store.set(k, b);
    const live = new Counting();
    const env = {
      SCHEDULER: {} as unknown as DurableObjectNamespace,
      DEST_KIND: "r2",
      DEST_R2: dest as unknown as R2Bucket,
      SIGNER_PRIVATE: signerPrivate,
      OPERATIONAL_PRIVATE: b64urlEncode(op.identity),
      ...(kind === "r2" ? { R2_b: live as unknown as R2Bucket } : { KV_n: live as unknown as KVNamespace }),
    } as unknown as Env;
    const res = (await runRestore(env, { runId: RUN, ...req })) as RestorePlan | RestoreResult as Outcome;
    return { res, calls: dest.calls + live.calls, writes: live.store.size };
  }

  const MAX = MAX_IN_ACCOUNT_RESTORE_RECORDS;
  const SKIP = MAX_IN_ACCOUNT_SKIP_RESTORE_RECORDS;
  console.log(`\nCEILINGS: default ${MAX}, keep live keys ${SKIP}`);
  ok("the keep-live-keys ceiling is below the default ceiling", SKIP > 0 && SKIP < MAX);

  console.log("\nMEASURED: calls at each ceiling (the figures restore-sinks.ts states)");
  const r2Default = await measure("r2", MAX, { confirm: true });
  const r2Skip = await measure("r2", SKIP, { confirm: true, onExisting: "skip" });
  const r2Dry = await measure("r2", MAX, {});
  const kvDefault = await measure("kv", MAX, { confirm: true });
  const kvSkip = await measure("kv", SKIP, { confirm: true, onExisting: "skip" });
  const r2SkipAtMax = await measure("r2", MAX, { confirm: false, onExisting: "skip" });
  for (const [label, m] of [
    [`R2 default apply, ${MAX} records`, r2Default],
    [`R2 keep-live-keys apply, ${SKIP} records`, r2Skip],
    [`R2 dry run, ${MAX} records`, r2Dry],
    [`KV default apply, ${MAX} records`, kvDefault],
    [`KV keep-live-keys apply, ${SKIP} records`, kvSkip],
  ] as const) {
    console.log(`       ${label}: ${m.calls} calls`);
  }
  ok(`the ${MAX}-record R2 default apply restored every record`, r2Default.res.ok === true && r2Default.res.recordsRestored === MAX);
  ok(`the ${SKIP}-record R2 keep-live-keys apply restored every (absent) record`, r2Skip.res.ok === true && r2Skip.res.recordsRestored === SKIP);
  ok(`the ${MAX}-record KV default apply restored every record`, kvDefault.res.ok === true && kvDefault.res.recordsRestored === MAX);
  ok(`the ${SKIP}-record KV keep-live-keys apply restored every (absent) record`, kvSkip.res.ok === true && kvSkip.res.recordsRestored === SKIP);
  ok(`the ${MAX}-record R2 dry run planned every record`, r2Dry.res.ok === true && r2Dry.res.plannedWrites === MAX);
  // The exact figures the ceiling comment states. 5 is the run open, then per small R2 record: 4 on a default
  // apply (verify read, re-verify read, put, readback), 5 under "skip" (plus the head), 2 on a dry run
  // (verify read, overwrite check). A KV record has no readback: 3, or 4 under "skip".
  ok("an R2 default apply costs 805 at 200 records (5 + 4 per record)", r2Default.calls === 805);
  ok("an R2 keep-live-keys apply costs 805 at 160 records (5 + 5 per record)", r2Skip.calls === 805);
  ok("an R2 dry run costs 405 at 200 records (5 + 2 per record)", r2Dry.calls === 405);
  ok("a KV default apply costs 605 at 200 records (5 + 3 per record)", kvDefault.calls === 605);
  ok("a KV keep-live-keys apply costs 645 at 160 records (5 + 4 per record)", kvSkip.calls === 645);

  console.log("\nBUDGET: every accepted mode at its ceiling stays inside the default apply's cost");
  for (const [label, m] of [
    ["R2 keep-live-keys apply", r2Skip],
    ["KV keep-live-keys apply", kvSkip],
    ["KV default apply", kvDefault],
    ["R2 dry run", r2Dry],
  ] as const) {
    ok(`${label} (${m.calls}) is at or under the R2 default apply (${r2Default.calls})`, m.calls <= r2Default.calls);
  }
  ok(`the R2 default apply (${r2Default.calls}) is inside the ~${PLATFORM_BUDGET} platform budget`, r2Default.calls <= PLATFORM_BUDGET);

  console.log("\nREFUSAL: a keep-live-keys window over its own ceiling");
  {
    const apply = await measure("r2", MAX, { confirm: true, onExisting: "skip" });
    ok(`a keep-live-keys apply of ${MAX} records is refused`, apply.res.ok === false && typeof apply.res.reason === "string" && apply.res.reason.includes(`in-account limit of ${SKIP}`));
    ok("the refused apply wrote nothing", apply.writes === 0);
    ok(`the refusal names maxRecords <= ${SKIP} as the bounded route`, typeof apply.res.reason === "string" && apply.res.reason.includes(`maxRecords <= ${SKIP}`));
    ok(`a keep-live-keys dry run of ${MAX} records is refused the same way`, r2SkipAtMax.res.ok === false && typeof r2SkipAtMax.res.reason === "string" && r2SkipAtMax.res.reason.includes(`in-account limit of ${SKIP}`));
    const windowed = await measure("r2", MAX, { confirm: true, onExisting: "skip", maxRecords: SKIP });
    ok(`a keep-live-keys apply of ${MAX} records with maxRecords ${SKIP} runs as a window`, windowed.res.ok === true && windowed.res.recordsRestored === SKIP && windowed.res.complete === false);
    ok(`a default apply of the same ${MAX} records is still accepted`, r2Default.res.ok === true);
  }

  verdictReached(failures);
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures}`);
  if (failures > 0) process.exit(1);
}

await main();
