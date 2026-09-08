// validate-dest-remove-default-history: another pass, BOUNDARIES AND ACCUMULATION.
//
// THE DEFECT THIS PINS. `removeDest`'s only-proven-copy orphan guard attributed a DEFAULT-ROUTED run
// (a history row with no `destinationId`, which is what an UNPINNED downpipe -- the console wizard's
// own output -- records) to the destination that is the default AT SCAN TIME. Repointing the console
// default from A to B and then removing A therefore reported ZERO at-risk runs and removed the
// destination holding the only copy of every backup, with `force:false` and
// `uncoveredOriginRunCount: 0` written into the audit as though nothing had been at stake.
//
// It is the ordinary order of a destination migration, and it is the order the guard's OWN refusal
// pushes an operator toward: for an unpinned downpipe there is no per-downpipe assignment to change,
// so "reassign those downpipes" reads as "repoint the default", which is exactly the step that makes
// the guard stop seeing the runs.
//
// AND THE SECOND HALF: the refusal's first remedy was
// "wait for replication to copy them to another destination". `replicateBacklog` returns at
// `allDestinationIds(config).length < 2` before it reads anything, so for a downpipe writing to one
// destination -- which every at-risk downpipe in the default-routed case is, by construction -- no
// tick will ever copy those runs. The wait cannot end. The step that MAKES replication run (give
// those downpipes a second destination) was named nowhere.
//
// Nothing here touches an estate: an in-memory DO storage double, the real SchedulerDO mixin, and
// pure functions. Run: node test/validate-dest-remove-default-history.ts

import type { AuthMethod } from "../src/admin/identity.ts";
import { validateSamlCerts } from "../src/admin/idpconn-validators.ts";
import { SchedulerDO } from "../src/sched/scheduler-do.ts";
import { couldHaveTakenDefaultRoutedRuns, rememberPriorDefault } from "../src/sched/scheduler-do-dest-config.ts";
import { PRIOR_DEFAULT_IDS_MAX } from "../src/sched/scheduler-do-limits.ts";
import { replicateBacklog } from "../src/seal/replicate.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

import { MockStorage } from "./mock-storage.ts";

type Caller = { method: AuthMethod; email: string | null; subject: string | null; groups: string[] };
const OWNER: Caller = { method: "token", email: null, subject: null, groups: [] };

function makeDO(seed: Record<string, unknown>): { dobj: SchedulerDO; storage: MockStorage } {
  const storage = new MockStorage();
  for (const [k, v] of Object.entries(seed)) storage.seed(k, v);
  return { dobj: new SchedulerDO({ storage } as unknown as DurableObjectState), storage };
}

function storedDest(id: string, label: string): Record<string, unknown> {
  return {
    id,
    label,
    endpoint: "https://acct.r2.cloudflarestorage.com",
    bucket: `bk-${id}`,
    region: "auto",
    accessKeyId: "AK",
    secretAccessKey: "SK",
    setAt: 1,
    setBy: "owner@acme.example",
    verifiedAt: 1,
    deleteProbe: "ok",
  };
}

// An UNPINNED downpipe: no destinationId, no destinationIds. This is what the console's create
// wizard produces, and what the guard's own comment calls "the common case".
function unpinnedDownpipe(id: string, name: string): Record<string, unknown> {
  return {
    config: { id, name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] } },
    nextRunAt: 0,
    lastRunId: "run-0",
    inFlight: false,
  };
}
function pinnedDownpipe(id: string, name: string, destinationIds: string[]): Record<string, unknown> {
  return {
    config: { id, name, cadenceSeconds: 3600, enabled: true, source: { type: "kv", binding: "KV", include: [], exclude: [] }, destinationIds },
    nextRunAt: 0,
    lastRunId: "run-0",
    inFlight: false,
  };
}

// DEFAULT-ROUTED history rows: status ok, and NO destinationId key at all. selectSealDestination
// returns `destinationId: primaryDestinationId(config)` for a downpipe with one destination or
// fewer, which is undefined when nothing is pinned, and completeRun omits the key entirely.
function defaultRoutedRing(n: number, from = 0): Array<Record<string, unknown>> {
  return Array.from({ length: n }, (_, i) => ({ runId: `run-${from + i}`, index: from + i, startedAt: "2026-06-15T00:00:00.000Z", status: "ok" }));
}
// RECORDED-ORIGIN rows: the differential control's population. A downpipe that fanned out recorded
// the failover-chosen origin, so its rows name the destination explicitly.
function recordedOriginRing(n: number, destinationId: string, from = 0): Array<Record<string, unknown>> {
  return Array.from({ length: n }, (_, i) => ({ runId: `run-${from + i}`, index: from + i, startedAt: "2026-06-15T00:00:00.000Z", status: "ok", destinationId }));
}

async function caught(fn: () => Promise<unknown>): Promise<Error | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    return e as Error;
  }
}

const TWO_DESTS = { list: [storedDest("A", "Primary R2"), storedDest("B", "New R2")], defaultId: "A" };

async function main(): Promise<void> {
  // ==============================================================================================
  // 1. DOSE-RESPONSE, both orders, over run counts far past anything an edge test would use.
  // ==============================================================================================
  console.log("-- dose-response: the SAME estate, removed in two orders, over 8 run counts --");
  {
    const doses = [0, 1, 2, 5, 10, 50, 200, 1000];
    let sameDefaultRefusals = 0;
    let repointedRefusals = 0;
    let countsExact = 0;
    for (const n of doses) {
      const seed = { destinations: TWO_DESTS, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), "hist:dp1": defaultRoutedRing(n) };
      // (a) remove A while A is STILL the default: the arm the guard was built for.
      {
        const { dobj } = makeDO(seed);
        const e = await caught(() => dobj.removeDest("A", false, OWNER));
        if (n === 0) {
          if (e === null) sameDefaultRefusals++; // a zero dose must be ALLOWED, or the guard proves nothing
        } else if (e !== null && /only proven copy/.test(e.message)) {
          sameDefaultRefusals++;
          if (new RegExp(`only proven copy of ${n} backed-up run`).test(e.message)) countsExact++;
        }
      }
      // (b) repoint the default to B FIRST, then remove A: the migration order.
      {
        const { dobj } = makeDO(seed);
        await dobj.setDefaultDest("B", OWNER);
        const e = await caught(() => dobj.removeDest("A", false, OWNER));
        if (n === 0) {
          if (e === null) repointedRefusals++;
        } else if (e !== null && /only proven copy/.test(e.message)) {
          repointedRefusals++;
          if (new RegExp(`only proven copy of ${n} backed-up run`).test(e.message)) countsExact++;
        }
      }
    }
    ok(`every dose is classified the same way with A still the default (${doses.length}/${doses.length})`, sameDefaultRefusals === doses.length);
    ok(`every dose is classified the SAME WAY after the default is repointed to B (${doses.length}/${doses.length})`, repointedRefusals === doses.length);
    ok("the refusal names the exact at-risk run count in BOTH orders, at every non-zero dose (14/14)", countsExact === 14);
  }

  // ==============================================================================================
  // 2. THE EFFECT ON STORAGE, read from the store rather than from the return value. A refusal that
  //    still removed the destination would be worse than no refusal at all.
  // ==============================================================================================
  console.log("-- the removal is actually PREVENTED, read back from DO storage and from the audit --");
  {
    const { dobj, storage } = makeDO({ destinations: TWO_DESTS, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), "hist:dp1": defaultRoutedRing(10) });
    await dobj.setDefaultDest("B", OWNER);
    await caught(() => dobj.removeDest("A", false, OWNER));
    const coll = storage.rawGet<{ list: Array<{ id: string }>; defaultId: string; priorDefaultIds?: string[] }>("destinations");
    ok("destination A is still stored after the refused removal", coll?.list.some((d) => d.id === "A") === true);
    ok("the repoint took effect (defaultId is B), so the refusal is not just a failed repoint", coll?.defaultId === "B");
    ok("the outgoing default A is remembered in priorDefaultIds", JSON.stringify(coll?.priorDefaultIds ?? []) === JSON.stringify(["A"]));
  }

  // ==============================================================================================
  // 3. DIFFERENTIAL CONTROL: the same removal, the same repoint, the same run count, down the path
  //    that is NOT the suspect. A run with a RECORDED origin was never in doubt, and repointing the
  //    default must not change its verdict in either direction.
  // ==============================================================================================
  console.log("-- differential control: a RECORDED-ORIGIN population is unaffected by the repoint --");
  {
    const seed = { destinations: TWO_DESTS, "dp:dpP": pinnedDownpipe("dpP", "Pinned", ["B"]), "hist:dpP": recordedOriginRing(10, "A") };
    const { dobj: d1 } = makeDO(seed);
    const e1 = await caught(() => d1.removeDest("A", false, OWNER));
    const { dobj: d2 } = makeDO(seed);
    await d2.setDefaultDest("B", OWNER);
    const e2 = await caught(() => d2.removeDest("A", false, OWNER));
    ok("a recorded-origin at-risk run refuses with A as default", e1 !== null && /only proven copy of 10 /.test(e1.message));
    ok("it refuses IDENTICALLY after the repoint (this path never depended on the default)", e2 !== null && e2.message === e1?.message);
  }
  {
    // The other half of the differential: a destination that has NEVER been the default must not be
    // dragged into the default-routed arm. A mode-blind fix would refuse to remove a freshly added
    // replica because some OTHER destination's default-routed runs exist, which is a fresh false
    // refusal of exactly the kind this campaign is against.
    const three = { list: [storedDest("A", "Primary"), storedDest("B", "New"), storedDest("C", "Never default")], defaultId: "A" };
    const { dobj } = makeDO({ destinations: three, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), "hist:dp1": defaultRoutedRing(10) });
    await dobj.setDefaultDest("B", OWNER);
    const e = await caught(() => dobj.removeDest("C", false, OWNER));
    ok("a NEVER-DEFAULT destination is still freely removable while default-routed runs exist", e === null);
    const remaining = (await dobj.listDestStatus()).destinations.map((d) => d.id).sort();
    ok("...and the removal really happened (A and B remain, C is gone)", JSON.stringify(remaining) === JSON.stringify(["A", "B"]));
  }

  // ==============================================================================================
  // 4. POSITION CONTROL: vary what must not matter and show the verdict does not move.
  // ==============================================================================================
  console.log("-- position control: ring order, index base, downpipe count, repoint depth --");
  {
    const base = defaultRoutedRing(10);
    const variants: Array<[string, Record<string, unknown>]> = [
      ["oldest-first ring", { "hist:dp1": base }],
      ["newest-first ring", { "hist:dp1": [...base].reverse() }],
      ["indices far from zero", { "hist:dp1": defaultRoutedRing(10, 900_000) }],
      ["a failed run interleaved", { "hist:dp1": [...base, { runId: "run-x", index: 99, startedAt: "t", status: "failed" }] }],
    ];
    let stable = 0;
    for (const [, extra] of variants) {
      const { dobj } = makeDO({ destinations: TWO_DESTS, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), ...extra });
      await dobj.setDefaultDest("B", OWNER);
      const e = await caught(() => dobj.removeDest("A", false, OWNER));
      if (e !== null && /only proven copy of 10 backed-up run/.test(e.message)) stable++;
    }
    ok(`the verdict and the count are identical across ${variants.length} orderings of the same 10 runs`, stable === variants.length);
  }
  {
    // Repoint DEPTH: A -> B -> C -> B. A has been the default and is still remembered three moves
    // later, which is the accumulation half -- the record must survive the repoints that follow it.
    const three = { list: [storedDest("A", "Primary"), storedDest("B", "Second"), storedDest("C", "Third")], defaultId: "A" };
    const { dobj, storage } = makeDO({ destinations: three, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), "hist:dp1": defaultRoutedRing(10) });
    await dobj.setDefaultDest("B", OWNER);
    await dobj.setDefaultDest("C", OWNER);
    await dobj.setDefaultDest("B", OWNER);
    const e = await caught(() => dobj.removeDest("A", false, OWNER));
    ok("A is still guarded three default moves later", e !== null && /only proven copy of 10 backed-up run/.test(e.message));
    const coll = storage.rawGet<{ priorDefaultIds?: string[] }>("destinations");
    // A -> B -> C -> B remembers all three outgoing defaults, most recent first. B appears because it
    // WAS the default over the middle leg and could have taken default-routed runs then, which is the
    // whole point: every destination the default has ever rested on is a candidate origin.
    ok("the remembered history is most-recent-first across all three moves (C, B, A)", JSON.stringify(coll?.priorDefaultIds ?? []) === JSON.stringify(["C", "B", "A"]));
  }
  {
    // An unrelated edit (adding a destination) round-trips the collection through
    // loadDestinations -> saveDestinations. The memory must survive it, or the guard loses its
    // record at the first rename.
    const { dobj, storage } = makeDO({ destinations: TWO_DESTS, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), "hist:dp1": defaultRoutedRing(10) });
    await dobj.setDefaultDest("B", OWNER);
    await dobj.putDest({ label: "A third bucket", config: { endpoint: "https://acct.r2.cloudflarestorage.com", bucket: "third", region: "auto", accessKeyId: "AK", secretAccessKey: "SK" } }, OWNER);
    const coll = storage.rawGet<{ priorDefaultIds?: string[] }>("destinations");
    ok("priorDefaultIds survives an unrelated collection edit", JSON.stringify(coll?.priorDefaultIds ?? []) === JSON.stringify(["A"]));
    const e = await caught(() => dobj.removeDest("A", false, OWNER));
    ok("...and the guard still fires after it", e !== null && /only proven copy/.test(e.message));
  }

  // ==============================================================================================
  // 5. NEGATIVE CONTROLS THAT MUST CLASSIFY DIFFERENTLY. If every refusal on this route borrowed one
  //    sentence, a fix to one of them could not be told from a fix to all of them.
  // ==============================================================================================
  console.log("-- negative controls: the sibling refusals keep their own sentences --");
  {
    const { dobj } = makeDO({ destinations: TWO_DESTS, "dp:dp1": pinnedDownpipe("dp1", "Pinner", ["A"]), "hist:dp1": defaultRoutedRing(10) });
    await dobj.setDefaultDest("B", OWNER);
    const e = await caught(() => dobj.removeDest("A", false, OWNER));
    ok("a PINNED downpipe still gets the in-use sentence, not the orphan one", e !== null && /in use by 1 downpipe/.test(e.message) && !/only proven copy/.test(e.message));
  }
  {
    const { dobj } = makeDO({ destinations: TWO_DESTS });
    const e = await caught(() => dobj.removeDest("ghost", false, OWNER));
    ok("an unknown id keeps `no such destination`", e !== null && e.message === "no such destination");
  }
  {
    const nonOwner: Caller = { method: "access", email: "ned@acme.example", subject: "sub-ned", groups: [] };
    const { dobj } = makeDO({ destinations: TWO_DESTS });
    const e = await caught(() => dobj.removeDest("A", false, nonOwner));
    ok("a non-owner keeps the AuthError, which is a different class entirely", e !== null && e.name === "AuthError");
  }
  {
    // A TRUE ZERO must still read as zero after the fix, or the guard is just always-on. Another
    // destination PROVES it holds the window [1, 9], so the runs are genuinely copied elsewhere.
    const { dobj } = makeDO({
      destinations: TWO_DESTS,
      "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"),
      "hist:dp1": defaultRoutedRing(10),
      "repl:dp1": { B: { holdsRunId: "run-9", holdsIndex: 9, holdsFrom: 0, lastOk: true, lastAttemptAt: 1 } },
    });
    await dobj.setDefaultDest("B", OWNER);
    const e = await caught(() => dobj.removeDest("A", false, OWNER));
    ok("a genuinely covered population is STILL removable after the repoint (no blanket refusal)", e === null);
  }
  {
    // force still clears the guard, and the audit still carries the data-loss magnitude. A fix that
    // made the estate unclearable would be a permanent foreclosure of its own.
    const { dobj } = makeDO({ destinations: TWO_DESTS, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), "hist:dp1": defaultRoutedRing(10) });
    await dobj.setDefaultDest("B", OWNER);
    const r = await dobj.removeDest("A", true, OWNER);
    ok("force still drops it, so the guard is clearable rather than a new lockout", !r.destinations.some((d) => d.id === "A"));
  }

  // ==============================================================================================
  // 6. QUESTION TWO: does the remedy the refusal names exist, and does taking it help?
  // ==============================================================================================
  console.log('-- question two: "wait for replication" against what replicateBacklog actually does --');
  {
    // Driven, not read: replicateBacklog with a ONE-destination config must make no call at all.
    // The scheduler double counts fetches; a pass that got past the fan-out guard would read
    // /downpipes or post a fault and be visible here.
    let calls = 0;
    const scheduler = { fetch: async () => { calls++; return new Response("{}"); } } as unknown as DurableObjectStub;
    const cfg = { id: "dp1", name: "Nightly KV", cadenceSeconds: 3600, enabled: true, source: { type: "kv" as const, binding: "KV", include: [], exclude: [] } };
    await replicateBacklog({} as never, scheduler, cfg as never, recordedOriginRing(10, "A") as never);
    ok("replicateBacklog on an UNPINNED downpipe does nothing at all (0 calls): the wait cannot end", calls === 0);
    calls = 0;
    await replicateBacklog({} as never, scheduler, { ...cfg, destinationIds: ["B"] } as never, recordedOriginRing(10, "A") as never);
    ok("...and a ONE-destination pinned downpipe is skipped identically (0 calls)", calls === 0);
    calls = 0;
    // The positive control on the instrument: at TWO destinations it gets past the fan-out guard and
    // reaches the no-signer arm, which posts a fault. A zero here would mean the double was never
    // able to observe a pass at all and the two zeros above would prove nothing.
    await replicateBacklog({} as never, scheduler, { ...cfg, destinationIds: ["B", "A"] } as never, recordedOriginRing(10, "A") as never);
    ok("at TWO destinations the pass DOES run (the instrument can see a pass, so the zeros mean something)", calls > 0);
  }
  {
    // So the message must not tell an operator to wait when no tick will ever copy these runs.
    const { dobj } = makeDO({ destinations: TWO_DESTS, "dp:dp1": unpinnedDownpipe("dp1", "Nightly KV"), "hist:dp1": defaultRoutedRing(10) });
    const e = await caught(() => dobj.removeDest("A", false, OWNER));
    const m = e?.message ?? "";
    ok("the refusal does NOT tell the operator to wait for a replication that cannot run", !/^.*\. Wait for replication/.test(m));
    ok("it says plainly that replication cannot copy them as things stand", /Replication cannot copy them as things stand/.test(m));
    ok("it names the precondition the replicate pass actually has (two or more destinations)", /two or more destinations/.test(m));
    ok("it names the step that makes the pass run, before it names force", m.indexOf("Add a second destination") < m.indexOf("remove with force") && m.includes("Add a second destination"));
    ok("force is still named as the last resort", /remove with force to drop those copies/.test(m));
    ok("the count and the at-risk downpipe name are unchanged (the halves that were never wrong)", /only proven copy of 10 backed-up run\(s\) \(Nightly KV\)/.test(m));
  }
  {
    // The MIXED population keeps the wait clause, because for the fanned-out half waiting is real.
    // A fix that deleted the wait sentence outright would be a fresh false claim.
    const { dobj } = makeDO({
      destinations: { list: [storedDest("A", "Primary"), storedDest("B", "New"), storedDest("C", "Third")], defaultId: "A" },
      "dp:dpFan": pinnedDownpipe("dpFan", "Fanned", ["B", "C"]),
      "hist:dpFan": recordedOriginRing(4, "A"),
      "dp:dpOne": pinnedDownpipe("dpOne", "Single", ["B"]),
      "hist:dpOne": recordedOriginRing(6, "A", 100),
    });
    const e = await caught(() => dobj.removeDest("A", false, OWNER));
    const m = e?.message ?? "";
    ok("a MIXED population still offers the wait (some of it is real)", /Wait for replication to copy them/.test(m));
    ok("...and names how many of the runs the wait cannot help (6 of 10)", /6 of these runs belong to downpipes configured with only one destination/.test(m));
  }
  {
    // A wholly fanned-out at-risk population keeps the original sentence verbatim: the honesty fix
    // must not change the message where the message was already true.
    const { dobj } = makeDO({
      destinations: { list: [storedDest("A", "Primary"), storedDest("B", "New"), storedDest("C", "Third")], defaultId: "A" },
      "dp:dpFan": pinnedDownpipe("dpFan", "Fanned", ["B", "C"]),
      "hist:dpFan": recordedOriginRing(4, "A"),
    });
    const e = await caught(() => dobj.removeDest("A", false, OWNER));
    ok(
      "a fully fanned-out population keeps the original wait-or-reassign sentence unchanged",
      e?.message === 'destination is the only proven copy of 4 backed-up run(s) (Fanned). Wait for replication to copy them to another destination (the map shows "N of M copies"), reassign those downpipes, or remove with force to drop those copies.',
    );
  }

  // ==============================================================================================
  // 7. THE PURE HELPERS, driven directly including their bound.
  // ==============================================================================================
  console.log("-- rememberPriorDefault / couldHaveTakenDefaultRoutedRuns: bounds and identities --");
  {
    ok("a no-op repoint (A -> A) remembers nothing", JSON.stringify(rememberPriorDefault(undefined, "A", "A")) === JSON.stringify([]));
    ok("an estate with no default yet (empty outgoing id) remembers nothing", JSON.stringify(rememberPriorDefault(["X"], "", "A")) === JSON.stringify(["X"]));
    ok("a repeat of an already-remembered id moves it to the front rather than duplicating", JSON.stringify(rememberPriorDefault(["C", "A"], "A", "B")) === JSON.stringify(["A", "C"]));
    let acc: string[] = [];
    for (let i = 0; i < PRIOR_DEFAULT_IDS_MAX + 20; i++) acc = rememberPriorDefault(acc, `d${i}`, `d${i + 1}`);
    ok(`the remembered history is bounded at PRIOR_DEFAULT_IDS_MAX (${PRIOR_DEFAULT_IDS_MAX}) past ${PRIOR_DEFAULT_IDS_MAX + 20} moves`, acc.length === PRIOR_DEFAULT_IDS_MAX);
    ok("overflow drops the OLDEST, keeping the most recent moves", acc[0] === `d${PRIOR_DEFAULT_IDS_MAX + 19}` && !acc.includes("d0"));
    ok("the current default is a candidate origin with no memory at all", couldHaveTakenDefaultRoutedRuns("A", "A", undefined));
    ok("a never-defaulted id is NOT a candidate origin", !couldHaveTakenDefaultRoutedRuns("C", "B", ["A"]));
    ok("a remembered prior default IS a candidate origin", couldHaveTakenDefaultRoutedRuns("A", "B", ["A"]));
  }

  // ==============================================================================================
  // 8. A cross-check: the SAML_CERTS_MAX edge, re-measured against this rig.
  // ==============================================================================================
  console.log("-- cross-check: the SAML cap edge --");
  {
    const pem = (n: number): string[] => Array.from({ length: n }, (_, i) => `-----BEGIN CERTIFICATE-----\nMIIB${String(i).padStart(4, "0")}\n-----END CERTIFICATE-----`);
    const eight = validateSamlCerts(pem(8));
    const nine = validateSamlCerts(pem(9));
    ok("8 certificates are accepted (the measured edge reproduces here)", eight.ok === true);
    ok("9 are refused (the bound holds on this rig)", nine.ok === false);
  }

  console.log(failures === 0 ? "\nVALIDATE-DEST-REMOVE-DEFAULT-HISTORY VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

void main();
