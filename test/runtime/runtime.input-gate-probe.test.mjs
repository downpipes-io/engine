// POSITIVE CONTROL + MECHANISM PROBE for the dual-control double-approve concurrency test.
//
// Run:
//   node test/runtime/runtime.input-gate-probe.test.mjs
//
// WHY THIS EXISTS
// ---------------
// runtime.dual-control-approve.test.mjs found NO double-apply on the PRE-FIX approveChange under real
// workerd. A null result is only trustworthy if we (a) prove the harness genuinely creates concurrent,
// overlapping in-flight execution at a single DO, and (b) pin the underlying mechanism: the whole
// double-approve concern hinges on whether the Durable Object INPUT GATE is RELEASED across the awaits
// approveChange performs between reading the change status and writing status=applied (the config-history
// head only moves at autoSnapshotConfig, AFTER the apply, across the changeContentHash crypto await).
//
// This probe uses MINIMAL Durable Objects (no production code) and an in-memory overlap detector:
// `active` = handlers executing in this DO right now, `maxActive` = the high-water mark. The input gate's
// contract is at most one event executes at a time, so if the gate is HELD across an await, maxActive stays
// 1; if the gate OPENS across it, a sibling handler runs concurrently and maxActive reaches >= 2. maxActive
// is independent of any storage lost-update, so it detects overlap directly.
//
// WHAT IT ESTABLISHES (all under REAL workerd):
//   PART A  Positive control + await-kind classification, N concurrent requests each:
//             * setTimeout await  -> gate OPENS  (maxActive == N, wall ~= one delay)  [proves overlap is
//               real AND the detector observes it: the harness is sound]
//             * crypto.subtle.digest await -> gate HELD (maxActive == 1, wall scales linearly = serial)
//             * storage get->put  -> gate HELD  (maxActive == 1)
//   PART B  The approveChange PATTERN (read status -> yielding await -> if pending: INSERT a fresh-id row +
//           mark applied), driven with two concurrent same-approver requests, across a gate-RELEASING await
//           (setTimeout, to force the window open), done two ways:
//             * WITHOUT blockConcurrencyWhile -> BOTH apply -> TWO rows  (the race, made to manifest)
//             * WITH    blockConcurrencyWhile -> ONE applies, one refused -> ONE row  (the guard closes it)
//
// CONCLUSION the probe supports: approveChange's real awaits (changeContentHash = crypto.subtle.digest, and
// storage) are exactly the gate-HOLDING kinds, with no timer/fetch in its critical path, so the gate
// serialises approveChange end-to-end and the double-apply window never opens with the code as it stands
// (hence the null result in the approve test). blockConcurrencyWhile is DEFENCE-IN-DEPTH that becomes
// LOAD-BEARING the moment any gate-releasing await (a timer, a fetch) is introduced into that window -- which
// PART B demonstrates directly.

import { Miniflare, Log, LogLevel } from "miniflare";

const SCRIPT = `
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- PART A: await-kind classifier (overlap detector over different await kinds) -----------------------
export class GateDO {
  constructor(state) { this.state = state; this.active = {}; this.max = {}; }
  _enter(k) { this.active[k] = (this.active[k] || 0) + 1; if (this.active[k] > (this.max[k] || 0)) this.max[k] = this.active[k]; }
  _sample(k) { if (this.active[k] > (this.max[k] || 0)) this.max[k] = this.active[k]; }
  _exit(k) { this.active[k] -= 1; }
  async fetch(req) {
    const p = new URL(req.url).pathname;
    if (p === "/timer") { this._enter("timer"); await sleep(20); this._sample("timer"); this._exit("timer"); return new Response("ok"); }
    if (p === "/crypto") { this._enter("crypto"); await crypto.subtle.digest("SHA-384", new Uint8Array(16 * 1024 * 1024)); this._sample("crypto"); this._exit("crypto"); return new Response("ok"); }
    if (p === "/storage") { this._enter("storage"); const v = (await this.state.storage.get("k")) || 0; this._sample("storage"); await this.state.storage.put("k", v + 1); this._exit("storage"); return new Response("ok"); }
    if (p === "/max") return new Response(JSON.stringify(this.max));
    return new Response("nf", { status: 404 });
  }
}

// ---- PART B: the approveChange PATTERN, with and without the blockConcurrencyWhile guard ---------------
// Mirrors approveChange's shape: read the single change record (status), and if it is still "pending",
// INSERT a fresh-id row (the non-idempotent notify-channel-set apply) and flip status to "applied". The
// yielding await in the middle is a setTimeout -- a gate-RELEASING await -- to force the very window the
// real crypto/storage awaits do not open, so the pattern's raciness is exposed deterministically.
export class PatternDO {
  constructor(state) { this.state = state; this.blockConcurrencyWhile = state.blockConcurrencyWhile.bind(state); }
  async _applyOnce() {
    const rec = (await this.state.storage.get("change")) || { status: "pending" };
    if (rec.status !== "pending") return { applied: false, reason: "already applied" }; // single-use check
    await sleep(15);                                          // gate-RELEASING await inside the window
    // non-idempotent INSERT: a fresh id per apply (like addNotifyChannel minting a ULID)
    const id = "row-" + crypto.randomUUID();
    await this.state.storage.put("inserted:" + id, true);
    rec.status = "applied";
    await this.state.storage.put("change", rec);
    return { applied: true, id };
  }
  async fetch(req) {
    const p = new URL(req.url).pathname;
    if (p === "/reset") {
      const all = await this.state.storage.list();
      for (const k of all.keys()) await this.state.storage.delete(k);
      await this.state.storage.put("change", { status: "pending" });
      return new Response("ok");
    }
    if (p === "/approve-noguard") return new Response(JSON.stringify(await this._applyOnce()));
    if (p === "/approve-guarded") return new Response(JSON.stringify(await this.blockConcurrencyWhile(() => this._applyOnce())));
    if (p === "/count") {
      const all = await this.state.storage.list({ prefix: "inserted:" });
      return new Response(JSON.stringify({ rows: all.size }));
    }
    return new Response("nf", { status: 404 });
  }
}

export default {
  async fetch(req, env) {
    const p = new URL(req.url).pathname;
    if (p.startsWith("/pat/")) return env.PAT.get(env.PAT.idFromName("pat")).fetch(new Request("https://i.internal" + p.slice(4)));
    return env.GATE.get(env.GATE.idFromName("gate")).fetch(new Request("https://i.internal" + p));
  },
};
`;

let failures = 0;
const ok = (label, cond) => {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
};

async function main() {
  const mf = new Miniflare({
    modules: true,
    script: SCRIPT,
    compatibilityDate: "2026-06-01",
    durableObjects: {
      GATE: { className: "GateDO", useSQLite: true },
      PAT: { className: "PatternDO", useSQLite: true },
    },
    log: new Log(LogLevel.WARN),
  });
  await mf.ready;

  const N = 16;
  const fire = async (path) => {
    const t = Date.now();
    await Promise.all(Array.from({ length: N }, () => mf.dispatchFetch("https://probe.test" + path)));
    return Date.now() - t;
  };

  try {
    console.log("INPUT-GATE PROBE (REAL WORKERD)\n");

    // ---- PART A: which awaits release the input gate? ---------------------------------------------
    const wTimer = await fire("/timer");
    const wCrypto = await fire("/crypto");
    const wStorage = await fire("/storage");
    const max = await (await mf.dispatchFetch("https://probe.test/max")).json();

    console.log("  PART A  await-kind classification (N concurrent; maxActive 1 = gate HELD, >=2 = gate OPENS)");
    console.log(`    setTimeout(20ms)        maxActive=${max.timer}   wall=${wTimer}ms`);
    console.log(`    crypto.subtle.digest    maxActive=${max.crypto}   wall=${wCrypto}ms`);
    console.log(`    storage get->put        maxActive=${max.storage}   wall=${wStorage}ms\n`);

    // Positive control: a gate-RELEASING await MUST show overlap, proving the harness + detector are sound.
    ok(`positive control: gate OPENS across setTimeout (maxActive == N == ${N})`, max.timer === N);
    // The award-winning fact: the awaits approveChange actually performs HOLD the gate.
    ok("crypto.subtle.digest (= changeContentHash) HOLDS the gate (maxActive == 1, serial)", max.crypto === 1);
    ok("storage op HOLDS the gate (maxActive == 1)", max.storage === 1);

    // ---- PART B: the approveChange PATTERN, both ways, across a gate-RELEASING await ---------------
    // NO GUARD: two concurrent same-approver applies across a releasing await -> BOTH apply -> TWO rows.
    await mf.dispatchFetch("https://probe.test/pat/reset");
    const ng = await Promise.all([
      mf.dispatchFetch("https://probe.test/pat/approve-noguard").then((r) => r.json()),
      mf.dispatchFetch("https://probe.test/pat/approve-noguard").then((r) => r.json()),
    ]);
    const ngRows = (await (await mf.dispatchFetch("https://probe.test/pat/count")).json()).rows;
    const ngApplied = ng.filter((r) => r.applied).length;

    // GUARDED: the same race, but the apply runs inside blockConcurrencyWhile -> ONE applies -> ONE row.
    await mf.dispatchFetch("https://probe.test/pat/reset");
    const g = await Promise.all([
      mf.dispatchFetch("https://probe.test/pat/approve-guarded").then((r) => r.json()),
      mf.dispatchFetch("https://probe.test/pat/approve-guarded").then((r) => r.json()),
    ]);
    const gRows = (await (await mf.dispatchFetch("https://probe.test/pat/count")).json()).rows;
    const gApplied = g.filter((r) => r.applied).length;

    console.log("  PART B  the approveChange read->yield->insert PATTERN across a gate-RELEASING await");
    console.log(`    WITHOUT blockConcurrencyWhile : ${ngApplied} applied, ${ngRows} row(s) inserted  (race => 2)`);
    console.log(`    WITH    blockConcurrencyWhile : ${gApplied} applied, ${gRows} row(s) inserted  (guard => 1)\n`);

    // The pattern IS racy across a gate-releasing await: without the guard, both apply and two rows land.
    ok("PATTERN without guard DOUBLE-APPLIES across a gate-releasing await (2 rows)", ngRows === 2 && ngApplied === 2);
    // The guard makes the apply exactly-once even across a gate-releasing await: LOAD-BEARING when one exists.
    ok("blockConcurrencyWhile guard makes it EXACTLY-ONCE (1 row, 1 applied)", gRows === 1 && gApplied === 1);
  } finally {
    await mf.dispose();
  }

  console.log(failures === 0 ? "\nINPUT-GATE PROBE COMPLETE (all checks passed)" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
