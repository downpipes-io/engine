// REAL-WORKERD concurrency test for the config-change dual-control double-approve race.
//
// Run:
//   node test/runtime/runtime.dual-control-approve.test.mjs
//
// THE QUESTION
// ------------
// approveChange (src/sched/scheduler-do-change-control.ts) applies a second-approver config change.
// Concern: two concurrent DISTINCT-approver approvals of the SAME pending change could both APPLY,
// because the config-history HEAD only moves at autoSnapshotConfig (AFTER applyConfigMutation, across
// the changeContentHash / buildConfigVersion crypto awaits), so the optimistic baseMoved guard alone
// leaves a double-apply window -- but ONLY if workerd RELEASES the DO input gate across that crypto
// await. The offline validators run the DO serially, so they cannot test this. The FIX wraps the apply
// in blockConcurrencyWhile + a re-read + a re-assert that the status is still pending.
//
// A `notify-channel-set` is NON-IDEMPOTENT: addNotifyChannel mints a FRESH ULID per apply, so a genuine
// double-apply creates TWO notify channels. The channel count is therefore a faithful, unambiguous race
// signal: exactly one channel per approved change means the apply ran exactly once.
//
// METHOD (mirrors the RL-1 / IDX-1 overlap in runtime.scheduler-do.test.mjs)
// -------------------------------------------------------------------------
// Boot the PRODUCTION SchedulerDO in a REAL workerd isolate (the shared harness), then, for each of N
// iterations: PROPOSE a fresh notify-channel-set as the proposer (Alice, under dual-control-on, which
// queues a genuine pending change with a valid contentHash + base by construction), then fire TWO
// genuinely-concurrent approves as the SAME distinct approver (Bob) via Promise.all -- two overlapping
// in-flight HTTP requests against the single DO, exactly how RL-1 creates its contended RMW. If the input
// gate opens across the crypto await, both approves read the same pending record and both apply -> the
// iteration creates 2 channels. Counting channels across N iterations measures whether the race manifests.
//
// We drive the DO's own HTTP surface directly (like the existing runtime suite), setting the router-
// internal x-downpipe-caller header so each request carries a concrete verified caller; the DO RE-RESOLVES
// every authority from its OWN tables (roleForCaller), so the header only names who is calling, it never
// grants authority. encodeCaller is imported from the PRODUCTION identity module so the header is encoded
// exactly as the live router encodes it (the DO's own decodeCaller round-trips it).

import { startScheduler, makeReporter } from "./harness.mjs";
import { encodeCaller } from "../../src/admin/identity.ts";

// Two distinct verified identities. Alice is the PROPOSER (maker); Bob is the APPROVER (checker). Both are
// Owners (Owner holds notify.config, the capability a notify-channel-set requires), distinct on the subject
// axis so canApproveChange permits Bob to approve Alice's change. role here is only the router-asserted
// hint; the DO re-resolves it from role:sub:<subject> built during setup.
const ALICE = { method: "access", email: "alice@example.com", subject: "access|alice", role: "owner", groups: [] };
const BOB = { method: "access", email: "bob@example.com", subject: "access|bob", role: "owner", groups: [] };

// How many independent propose+double-approve rounds to run. Each round is a fresh single-use change, so
// running many rounds gives the race many chances to manifest (a timing-dependent window may not fire every
// time). With the fix, EVERY round must add exactly one channel.
const ROUNDS = Number(process.env.ROUNDS) || 24;

async function main() {
  const { mf, dispose } = await startScheduler();
  const { ok, done } = makeReporter("SchedulerDO dual-control approveChange CONCURRENCY (REAL WORKERD)");

  // Drive the DO's HTTP surface with an optional caller header. Mirrors harness.mjs `req`, plus the caller.
  const call = async (method, path, { body, caller } = {}) => {
    const headers = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (caller !== undefined) headers["x-downpipe-caller"] = encodeCaller(caller);
    const r = await mf.dispatchFetch(`https://scheduler.test/do${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await r.text();
    let parsed;
    try {
      parsed = text.length ? JSON.parse(text) : null;
    } catch {
      parsed = text;
    }
    return { status: r.status, body: parsed };
  };

  const whoami = (id) =>
    call("GET", `/whoami?email=${encodeURIComponent(id.email)}&subject=${encodeURIComponent(id.subject)}&method=access`);
  const listChannels = async () => {
    const r = await call("GET", "/notify/channels");
    return Array.isArray(r.body) ? r.body : [];
  };

  try {
    // ---- SETUP: two distinct Owners + dual control armed -------------------------------------------
    // 1) First authenticated caller bootstraps to Owner (subject-keyed role:sub: entry).
    const aliceWho = await whoami(ALICE);
    ok("setup: Alice (proposer) bootstraps to Owner", aliceWho.status === 200 && aliceWho.body?.role === "owner");

    // 2) Alice grants Bob Owner. Dual control is still OFF, so this applies inline (a pending email invite
    //    keyed by bob@…, which binds to Bob's subject on his first whoami).
    const grant = await call("POST", "/roles", { caller: ALICE, body: { email: BOB.email, role: "owner" } });
    ok("setup: Alice grants Bob Owner inline (gate off)", grant.status === 200);

    // 3) Bob authenticates -> the pending invite binds to his stable subject -> he resolves to Owner.
    const bobWho = await whoami(BOB);
    ok("setup: Bob (approver) resolves to Owner, distinct subject", bobWho.status === 200 && bobWho.body?.role === "owner");

    // 4) Alice arms dual control (owner-only, immediate; arming is never itself gated).
    const arm = await call("POST", "/config/approval-policy", { caller: ALICE, body: { requireConfigApproval: true } });
    ok("setup: dual control armed", arm.status === 200 && arm.body?.requireConfigApproval === true);

    const startChannels = (await listChannels()).length;
    ok("setup: zero notify channels before any approval", startChannels === 0);

    // ---- THE RACE: N rounds of propose + two concurrent same-approver approves ---------------------
    let roundsWithTwoApplied = 0; // rounds where BOTH concurrent approves reported applied (double-apply)
    let roundsRefusedCleanly = 0; // rounds where exactly one applied and the other was refused
    let proposeFailures = 0;
    const refusalReasons = new Set();

    for (let i = 0; i < ROUNDS; i++) {
      // PROPOSE a genuine pending change via the REAL propose path (valid contentHash + base by construction).
      // A unique url per round keeps each change distinct and easy to eyeball.
      const propose = await call("POST", "/notify/channels", {
        caller: ALICE,
        body: { kind: "webhook", name: `Ops on-call ${i}`, url: `https://hooks.example.com/round-${i}` },
      });
      if (propose.status !== 202 || propose.body?.queued !== true || typeof propose.body?.id !== "string") {
        proposeFailures++;
        continue;
      }
      const changeId = propose.body.id;

      // FIRE TWO TRULY-CONCURRENT APPROVES as the SAME distinct approver (Bob). Both are in flight together
      // (Promise.all issues them without awaiting between), so the DO input gate is what must serialise them.
      const [a, b] = await Promise.all([
        call("POST", "/config/changes/approve", { caller: BOB, body: { id: changeId } }),
        call("POST", "/config/changes/approve", { caller: BOB, body: { id: changeId } }),
      ]);
      const applied = [a, b].filter((r) => r.status === 200 && r.body?.status === "applied");
      const refused = [a, b].filter((r) => !(r.status === 200 && r.body?.status === "applied"));
      for (const r of refused) if (typeof r.body?.error === "string") refusalReasons.add(r.body.error);

      if (applied.length === 2) roundsWithTwoApplied++;
      else if (applied.length === 1 && refused.length === 1) roundsRefusedCleanly++;
    }

    const finalChannels = (await listChannels()).length;
    const expected = ROUNDS; // exactly one channel per round if the apply ran exactly once each time

    console.log(`\n  diagnostics ----------------------------------------------------------`);
    console.log(`  rounds                         : ${ROUNDS}`);
    console.log(`  propose failures               : ${proposeFailures}`);
    console.log(`  rounds with BOTH approves applied (double-apply): ${roundsWithTwoApplied}`);
    console.log(`  rounds with exactly one applied + one refused   : ${roundsRefusedCleanly}`);
    console.log(`  refusal reasons observed       : ${[...refusalReasons].map((s) => JSON.stringify(s)).join(", ") || "(none)"}`);
    console.log(`  notify channels created        : ${finalChannels}  (expected exactly ${expected})`);
    console.log(`  extra channels from double-apply: ${finalChannels - expected}`);
    console.log(`  ----------------------------------------------------------------------\n`);

    // ASSERTIONS (the FIXED-code contract): the apply runs EXACTLY ONCE per change.
    ok("no propose failed", proposeFailures === 0);
    ok(`exactly ${expected} notify channels exist (one per change; no double-apply)`, finalChannels === expected);
    ok("every round resolved as one-applied + one-refused (single use)", roundsRefusedCleanly === ROUNDS);
    ok("NO round had both concurrent approves apply", roundsWithTwoApplied === 0);
  } finally {
    await dispose();
  }

  const failures = done("DUAL-CONTROL APPROVE CONCURRENCY VECTORS PASS");
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
