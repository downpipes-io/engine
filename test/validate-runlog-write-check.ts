// The RUNLOG writers prove their own write before they publish its signature, and they bound and pace their
// retries. This validator pins the three behaviours the mutation run left unproved (seal/pipeline.ts
// appendRunlogBody, supersedeRunlogBody, verifyRunlogForWrite):
//   - the read-after-write check: after a conditional write lands, the writer publishes RUNLOG.sig only when the
//     body it reads back is its own (the same etag, or with no etag the same bytes). A read-back that is
//     missing, carries another etag, or (with no etag) holds other bytes leaves RUNLOG.sig as it was and counts
//     a sigPublishSkipped; the matching read-back publishes. The append and the prune are both held to it;
//   - the conditional write carries its precondition: If-None-Match "*" to create, If-Match <etag> to extend;
//   - the retry bound and pace: a write that always loses ends as RunlogContendedError after exactly six
//     conditional writes with five backoffs of 25, 50, 100, 200 and 400 ms (the jitter pinned to its ceiling),
//     none after the last attempt; a write that wins on the sixth attempt succeeds; the append and the prune
//     behave alike;
//   - the prune's own rules: an empty target set touches nothing, only targeted active entries change, a
//     target already superseded writes nothing, an absent RUNLOG with no floor is a no-op, and a held-for-ever
//     lock is never released;
//   - the chain refusal: the anomaly row carries the kind, the index pair only when the detector gave one, the
//     entry count and the digest, and the refusal text differs for a duplicate index; a below-floor RUNLOG
//     records its own row.
//
// Run: node test/validate-runlog-write-check.ts

import { b64urlEncode, utf8 } from "../src/crypto/bytes.ts";
import { mldsaKeygen } from "../src/crypto/pq.ts";
import { drainIntegrityFaultLedger, resetIntegrityFaultLedger } from "../src/format/integrity-fault-ledger.ts";
import { parseRunlog, type RunlogEntry, type Signer, signRunlog } from "../src/format/writer.ts";
import { appendRunlog, RunlogContendedError, RunlogIntegrityError, type RunlogLock, supersedeRunlog } from "../src/seal/pipeline.ts";
import { beginRunObservations, runObservations } from "../src/seal/run-observations.ts";
import { verdictReached } from "./lib/verdict-guard.ts";
import { MemoryDestination } from "./memdest.ts";

const RUNLOG = "_RECOVERY/RUNLOG";
const RUNLOG_SIG = "_RECOVERY/RUNLOG.sig";
const DP = "dp_write_check";
const R = (n: number): string => `01ARZ3NDEKTSV4RRFFQ69G5FH${n}`;

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 300)}`);
  }
}

async function makeSigner(): Promise<Signer> {
  const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const m = mldsaKeygen();
  return { edPrivate: ed.privateKey, edPublic: new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey)), mldsaSecret: m.secretKey, mldsaPublic: m.publicKey };
}
const entryAt = (index: number, runId: string, prev: string | null, dp = DP, status: "active" | "superseded" = "active"): RunlogEntry => ({ index, runId, downpipeId: dp, time: "2026-10-02T04:00:00.000Z", recordCount: 1, prevRunId: prev, status });

type ReadBack = "own" | "missing" | "other-etag" | "other-bytes-no-etag" | "same-bytes-no-etag";

// A destination that can lose the next N conditional writes, report no etag, replace the read that follows a
// landed write, and record what it was asked.
class SpyDestination extends MemoryDestination {
  failFirst = 0;
  conditionalCalls = 0;
  getCalls = 0;
  opts: Array<{ ifMatch?: string; ifNoneMatch?: string }> = [];
  readBack: ReadBack = "own";
  private landed = false;
  override async get(key: string) {
    this.getCalls++;
    const real = await super.get(key);
    if (key === RUNLOG && this.landed) {
      this.landed = false;
      if (this.readBack === "missing") return null;
      if (this.readBack === "other-etag" && real) return { body: real.body, etag: `"somebody-else"` };
      if (this.readBack === "other-bytes-no-etag" && real) return { body: utf8("not our body"), etag: undefined as unknown as string };
      if (this.readBack === "same-bytes-no-etag" && real) return { body: real.body, etag: undefined as unknown as string };
    }
    return real;
  }
  override async putConditional(key: string, body: Uint8Array, opts: { ifMatch?: string; ifNoneMatch?: string }) {
    if (key !== RUNLOG) return super.putConditional(key, body, opts);
    this.conditionalCalls++;
    this.opts.push({ ...opts });
    if (this.failFirst > 0) {
      this.failFirst--;
      return { ok: false as const };
    }
    const r = await super.putConditional(key, body, opts);
    this.landed = true;
    if (r.ok && (this.readBack === "other-bytes-no-etag" || this.readBack === "same-bytes-no-etag")) return { ok: true as const };
    return r;
  }
}

async function seed(d: MemoryDestination, signer: Signer, entries: RunlogEntry[]): Promise<void> {
  const signed = await signRunlog(entries, signer.edPrivate, signer.mldsaSecret);
  await d.put(RUNLOG, signed.runlog);
  await d.put(RUNLOG_SIG, utf8(b64urlEncode(signed.sig)));
}
const sigText = async (d: MemoryDestination): Promise<string | null> => {
  const o = await d.get(RUNLOG_SIG);
  return o ? new TextDecoder().decode(o.body) : null;
};
const bodyOf = async (d: MemoryDestination): Promise<Uint8Array> => (await d.get(RUNLOG))!.body;
const same = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && a.every((x, i) => x === b[i]);

async function attempt(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e;
  }
}

// Time and jitter under test control: every setTimeout runs at once and its delay is recorded; the 4-byte jitter
// draw is pinned to its ceiling (or floor), so the delay is exactly the cap (or 0).
const realSetTimeout = globalThis.setTimeout;
const realRandom = crypto.getRandomValues.bind(crypto);
let delays: number[] = [];
function fakeTime(jitter: 0 | 255): void {
  delays = [];
  (globalThis as { setTimeout: unknown }).setTimeout = (fn: () => void, ms?: number) => {
    delays.push(ms ?? 0);
    fn();
    return 0;
  };
  (crypto as { getRandomValues: unknown }).getRandomValues = (a: Uint8Array) => {
    if (a instanceof Uint8Array && a.length === 4) {
      a.fill(jitter);
      return a;
    }
    return realRandom(a as Uint8Array<ArrayBuffer>);
  };
}
function realTime(): void {
  (globalThis as { setTimeout: unknown }).setTimeout = realSetTimeout;
  (crypto as { getRandomValues: unknown }).getRandomValues = realRandom;
}

async function main(): Promise<void> {
  const signer = await makeSigner();
  const base = [entryAt(1, R(1), null), entryAt(2, R(2), R(1))];

  console.log("\n-- the append's read-after-write check --");
  for (const mode of ["own", "missing", "other-etag", "other-bytes-no-etag", "same-bytes-no-etag"] as const) {
    const d = new SpyDestination();
    await seed(d, signer, base);
    const oldSig = await sigText(d);
    d.readBack = mode;
    beginRunObservations();
    const err = await attempt(() => appendRunlog(d, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
    const published = (await sigText(d)) !== oldSig;
    const skipped = runObservations().lock.sigPublishSkipped;
    const wrote = parseRunlog(await bodyOf(d)).length === 3;
    const expectPublish = mode === "own" || mode === "same-bytes-no-etag";
    ok(`${mode}: the append lands and never throws`, err === null && wrote, err instanceof Error ? err.message : err);
    ok(`${mode}: RUNLOG.sig is ${expectPublish ? "published" : "left as it was"}`, published === expectPublish);
    ok(`${mode}: sigPublishSkipped is ${expectPublish ? 0 : 1}`, skipped === (expectPublish ? 0 : 1), skipped);
  }

  console.log("\n-- the prune's read-after-write check --");
  for (const mode of ["own", "missing", "other-etag", "other-bytes-no-etag", "same-bytes-no-etag"] as const) {
    const d = new SpyDestination();
    await seed(d, signer, base);
    const oldSig = await sigText(d);
    d.readBack = mode;
    let n: unknown;
    const err = await attempt(async () => {
      n = await supersedeRunlog(d, signer, [R(1)]);
    });
    const published = (await sigText(d)) !== oldSig;
    const expectPublish = mode === "own" || mode === "same-bytes-no-etag";
    ok(`${mode}: the prune lands, returns 1 and never throws`, err === null && n === 1, err instanceof Error ? err.message : err);
    ok(`${mode}: RUNLOG.sig is ${expectPublish ? "published" : "left as it was"}`, published === expectPublish);
  }

  console.log("\n-- the conditional write carries its precondition --");
  {
    const d = new SpyDestination();
    await appendRunlog(d, signer, entryAt(1, R(1), null), undefined, { relinkLocalPrev: true });
    ok("a first write creates with If-None-Match *", d.opts.length === 1 && d.opts[0]!.ifNoneMatch === "*" && d.opts[0]!.ifMatch === undefined, d.opts);
    const etag = (await d.get(RUNLOG))!.etag;
    await appendRunlog(d, signer, entryAt(2, R(2), R(1)), undefined, { relinkLocalPrev: true });
    ok("the next write extends with If-Match <the etag it read>", d.opts[1]!.ifMatch === etag && d.opts[1]!.ifNoneMatch === undefined, d.opts);
    const etag2 = (await d.get(RUNLOG))!.etag;
    await supersedeRunlog(d, signer, [R(1)]);
    ok("the prune extends with If-Match <the etag it read>", d.opts[2]!.ifMatch === etag2 && d.opts[2]!.ifNoneMatch === undefined, d.opts);
  }

  console.log("\n-- the append's retry bound and backoff --");
  try {
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      d.failFirst = 99;
      fakeTime(255);
      beginRunObservations();
      const err = await attempt(() => appendRunlog(d, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
      ok("a write that always loses ends as RunlogContendedError", err instanceof RunlogContendedError && /contended 6 times/.test((err as Error).message), err instanceof Error ? err.message : err);
      ok("...after exactly six conditional writes", d.conditionalCalls === 6, d.conditionalCalls);
      ok("...with five backoffs of 25, 50, 100, 200 and 400 ms (none after the last)", JSON.stringify(delays) === "[25,50,100,200,400]", delays);
      ok("...and one casExhausted counted", runObservations().lock.casExhausted === 1);
      ok("...and nothing was written", parseRunlog(await bodyOf(d)).length === 2);
    }
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      d.failFirst = 5;
      fakeTime(255);
      const err = await attempt(() => appendRunlog(d, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
      ok("a write that wins on the sixth and last attempt succeeds", err === null && d.conditionalCalls === 6 && parseRunlog(await bodyOf(d)).length === 3, err instanceof Error ? err.message : err);
      ok("...after five backoffs", JSON.stringify(delays) === "[25,50,100,200,400]", delays);
    }
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      fakeTime(255);
      const err = await attempt(() => appendRunlog(d, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
      ok("a write that wins first time waits for nothing", err === null && d.conditionalCalls === 1 && delays.length === 0, delays);
    }
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      d.failFirst = 99;
      fakeTime(0);
      await attempt(() => appendRunlog(d, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
      ok("the jitter draws from zero up to the cap: the floor draw waits 0 ms", delays.length === 5 && delays.every((x) => x === 0), delays);
    }

    console.log("\n-- the prune's retry bound and backoff --");
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      d.failFirst = 99;
      fakeTime(255);
      beginRunObservations();
      const err = await attempt(() => supersedeRunlog(d, signer, [R(1)]));
      ok("a prune that always loses ends as RunlogContendedError", err instanceof RunlogContendedError && /supersede contended 6 times/.test((err as Error).message), err instanceof Error ? err.message : err);
      ok("...after exactly six conditional writes", d.conditionalCalls === 6, d.conditionalCalls);
      ok("...with five backoffs of 25, 50, 100, 200 and 400 ms (none after the last)", JSON.stringify(delays) === "[25,50,100,200,400]", delays);
      ok("...and one casExhausted counted", runObservations().lock.casExhausted === 1);
    }
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      d.failFirst = 5;
      fakeTime(255);
      let n: unknown;
      const err = await attempt(async () => {
        n = await supersedeRunlog(d, signer, [R(1)]);
      });
      ok("a prune that wins on the sixth and last attempt succeeds", err === null && n === 1 && d.conditionalCalls === 6, err instanceof Error ? err.message : err);
      ok("...after five backoffs", JSON.stringify(delays) === "[25,50,100,200,400]", delays);
    }

    console.log("\n-- the prune's own rules --");
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      const gets = d.getCalls;
      const n = await supersedeRunlog(d, signer, []);
      ok("an empty target set returns 0 and reads nothing", n === 0 && d.getCalls === gets && d.conditionalCalls === 0);
    }
    {
      const d = new SpyDestination();
      await seed(d, signer, [entryAt(1, R(1), null), entryAt(2, R(2), R(1)), entryAt(3, R(3), R(2))]);
      const n = await supersedeRunlog(d, signer, [R(2)]);
      const after = parseRunlog(await bodyOf(d));
      ok("only the targeted entry changes", n === 1 && after.map((e) => e.status).join() === "active,superseded,active", after.map((e) => e.status));
      const body = await bodyOf(d);
      const again = await supersedeRunlog(d, signer, [R(2)]);
      ok("a target that is already superseded returns 0 and writes nothing", again === 0 && d.conditionalCalls === 1 && same(await bodyOf(d), body), d.conditionalCalls);
      const none = await supersedeRunlog(d, signer, ["01ARZ3NDEKTSV4RRFFQ69G5FZZ"]);
      ok("a target no entry carries returns 0 and writes nothing", none === 0 && d.conditionalCalls === 1);
    }
    {
      const d = new SpyDestination();
      const n = await supersedeRunlog(d, signer, [R(1)]);
      ok("an absent RUNLOG with no floor is a no-op", n === 0 && d.conditionalCalls === 0 && (await d.get(RUNLOG)) === null);
    }
    {
      const d = new SpyDestination();
      await seed(d, signer, base);
      let released: string[] = [];
      const lock: RunlogLock = { acquire: async () => "tok-1", release: async (t) => void released.push(t) };
      await supersedeRunlog(d, signer, [R(1)], lock);
      ok("a held lock is released with its own token", released.length === 1 && released[0] === "tok-1", released);
      released = [];
      let acquires = 0;
      const never: RunlogLock = {
        acquire: async () => {
          acquires++;
          return null;
        },
        release: async (t) => void released.push(t),
      };
      await supersedeRunlog(d, signer, [R(2)], never);
      ok("a lock that was never taken is never released", acquires > 1 && released.length === 0, { acquires, released });
    }
  } finally {
    realTime();
  }

  console.log("\n-- the chain refusal --");
  {
    const dup = new SpyDestination();
    await seed(dup, signer, [entryAt(1, R(1), null), entryAt(2, R(2), R(1)), entryAt(2, R(4), R(2))]);
    resetIntegrityFaultLedger();
    const err = await attempt(() => appendRunlog(dup, signer, entryAt(5, R(5), R(4)), undefined, { relinkLocalPrev: true }));
    const row = drainIntegrityFaultLedger().runlogAnomalies.find((a) => a.kind === "duplicate-index");
    ok("a duplicate index in the chain is refused as chain-anomaly", err instanceof RunlogIntegrityError && err.reason === "chain-anomaly", err instanceof Error ? err.message : err);
    ok("...with the duplicate-index kind, both indices (2 and 2), the entry count and the digest", row !== undefined && row.indexA === 2 && row.indexB === 2 && row.entryCount === 3 && typeof row.digest === "string" && row.digest.length === 12, row);
    const msg = err instanceof Error ? err.message : "";
    ok("...and the text names the kind and says to attach a fresh destination", msg.includes("(duplicate-index)") && msg.includes("fresh destination") && !msg.includes("GET /admin/runlog/chain"), msg);
    ok("...and the RUNLOG is untouched", dup.conditionalCalls === 0);
  }
  {
    const brk = new SpyDestination();
    await seed(brk, signer, [entryAt(1, R(1), null), entryAt(2, R(2), null)]);
    resetIntegrityFaultLedger();
    const err = await attempt(() => appendRunlog(brk, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
    const row = drainIntegrityFaultLedger().runlogAnomalies.find((a) => a.kind === "chain-break");
    ok("a break in the chain records chain-break with both indices (1 and 2)", row !== undefined && row.indexA === 1 && row.indexB === 2 && row.entryCount === 2 && row.digest !== undefined, row);
    const msg = err instanceof Error ? err.message : "";
    ok("...and the text points an Owner at the chain review, not at a fresh destination", err instanceof RunlogIntegrityError && msg.includes("(chain-break)") && msg.includes("GET /admin/runlog/chain") && !msg.includes("fresh destination"), msg);
  }
  {
    const dang = new SpyDestination();
    await seed(dang, signer, [entryAt(1, R(1), "01ARZ3NDEKTSV4RRFFQ69G5FZZ"), entryAt(2, R(2), R(1))]);
    resetIntegrityFaultLedger();
    await attempt(() => appendRunlog(dang, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
    const row = drainIntegrityFaultLedger().runlogAnomalies.find((a) => a.kind === "dangling-prev");
    ok("a dangling prev records one index (1) and no second index", row !== undefined && row.indexA === 1 && !("indexB" in row), row);
  }
  {
    const clean = new SpyDestination();
    await seed(clean, signer, base);
    resetIntegrityFaultLedger();
    const err = await attempt(() => appendRunlog(clean, signer, entryAt(3, R(3), R(2)), undefined, { relinkLocalPrev: true }));
    ok("control: a clean chain appends and records no anomaly", err === null && drainIntegrityFaultLedger().runlogAnomalies.length === 0, err instanceof Error ? err.message : err);
  }

  console.log("\n-- the floor refusal --");
  {
    const d = new SpyDestination();
    await seed(d, signer, [entryAt(1, R(1), null), entryAt(2, R(2), R(1)), entryAt(3, R(3), R(2))]);
    const lock: RunlogLock = { acquire: async () => "tok", release: async () => {}, floor: async () => 5 };
    resetIntegrityFaultLedger();
    const err = await attempt(() => appendRunlog(d, signer, entryAt(4, R(4), R(3)), lock, { relinkLocalPrev: true }));
    const row = drainIntegrityFaultLedger().runlogAnomalies.find((a) => a.kind === "index-regression");
    ok("a RUNLOG below the floor is refused as below-floor", err instanceof RunlogIntegrityError && err.reason === "below-floor", err instanceof Error ? err.message : err);
    ok("...with an index-regression row: highest 3, floor 5, three entries, a digest", row !== undefined && row.indexA === 3 && row.indexB === 5 && row.entryCount === 3 && row.digest !== undefined, row);
    const msg = err instanceof Error ? err.message : "";
    ok("...and the text names both numbers", msg.includes("highest index 3") && msg.includes("5 confirmed"), msg);
    const ctl = new SpyDestination();
    await seed(ctl, signer, [entryAt(1, R(1), null), entryAt(2, R(2), R(1)), entryAt(3, R(3), R(2))]);
    const lock3: RunlogLock = { acquire: async () => "tok", release: async () => {}, floor: async () => 3 };
    const okErr = await attempt(() => appendRunlog(ctl, signer, entryAt(4, R(4), R(3)), lock3, { relinkLocalPrev: true }));
    ok("control: a RUNLOG at the floor appends", okErr === null, okErr instanceof Error ? okErr.message : okErr);
  }

  console.log(failures === 0 ? "\nRUNLOG WRITE CHECK PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures, checks);
  if (failures > 0) process.exitCode = 1;
}

main().catch((e) => {
  realTime();
  console.error(e);
  process.exitCode = 1;
  verdictReached(failures + 1, checks);
});
