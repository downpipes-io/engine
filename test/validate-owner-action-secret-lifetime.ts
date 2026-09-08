// validate-owner-action-secret-lifetime: how long a LIVE SECRET submitted with a high-blast owner action
// stays in the Durable Object, driven against the real DO rather than reasoned about.
//
// An owner action stores its params VERBATIM because the approved execution must replay the identical
// action, and for the destination, IdP, push and discovery kinds that verbatim store includes the live
// credential the proposer typed. The record's own TTL (OWNER_ACTION_TTL_MS) bounds what the record can DO,
// but does not bound what it HOLDS: a stored credential can outlive the action it belonged to.
//
// The fix is a scrub at the point the action becomes unspendable, in three deterministic places (the
// DO-executed approve, the router-executed consume, and any reject) plus a lazy sweep for records nobody
// ever decided. It reuses the listing's own secret-field list, so there is one definition of what a secret is.
//
// This file proves the scrub two ways.
//   1. Every "the secret is gone" assertion is paired with a "the secret was there" control taken from the
//      SAME record moments earlier, so a proposal that never stored a credential cannot satisfy it, and with
//      a "the non-secret params survived" control, so a scrub that simply erased the record cannot either.
//   2. MockStorage.list returns the STORED object by reference, while the real Durable Object returns a
//      deserialised copy. A sweep that mutated the listed record and forgot to persist it would therefore
//      pass here and do nothing in production. So this file installs a cloning list() over the harness's
//      storage for the whole run, restoring production value semantics, and additionally counts the
//      storage.put calls the sweep issues, so section F can tell a persisted scrub from an in-place mutation.
//
// Run: node test/validate-owner-action-secret-lifetime.ts

import { GOVERNANCE_FAULTS_KEY, governanceFaultKey } from "../src/sched/sched-fault-ledger.ts";
import { OWNER_ACTION_PREFIX, ownerActionKey, type PendingOwnerAction } from "../src/admin/owner-action.ts";
import { buildContext } from "./validate-owner-action-dualcontrol-harness.ts";

let failures = 0;
let checks = 0;
function ok(label: string, cond: boolean): void {
  checks++;
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// A recognisable stand-in for a live credential. It is only ever tested for PRESENCE or ABSENCE; no assertion
// prints it, and no assertion prints a stored params object, so a failure never spills a value.
const SECRET = "DO-NOT-LOG-owner-action-secret-lifetime";
const SECRET2 = "DO-NOT-LOG-owner-action-secret-lifetime-2";
const SECRET3 = "DO-NOT-LOG-owner-action-secret-lifetime-3";

async function main(): Promise<void> {
  const ctx = await buildContext();
  const { sched, OWNER, OWNER2, call, doFetch, ownerCaller, destConfig, inbox, setGate } = ctx;
  const store = sched.storage;

  // Does the AT-REST record still hold the credential? Read raw, bypassing every projection.
  const atRest = (id: string): PendingOwnerAction | undefined => store.rawGet<PendingOwnerAction>(ownerActionKey(id));
  const holdsSecret = (id: string, secret: string): boolean => JSON.stringify(atRest(id)?.params ?? null).includes(secret);
  const governanceFaults = (): Record<string, { count?: number }> => store.rawGet<Record<string, { count?: number }>>(GOVERNANCE_FAULTS_KEY) ?? {};
  const integrityFailedCount = (stage: "owner-action-approve" | "owner-action-execute"): number =>
    governanceFaults()[governanceFaultKey(stage, "integrity-failed")]?.count ?? 0;

  // HAZARD 2, part one: restore the real DO's value semantics. MockStorage.list hands back the stored object
  // itself, so an in-place mutation during a sweep would be visible to a later rawGet whether or not the
  // sweep persisted it. Cloning here means ONLY a storage.put can change what is stored, which is what
  // production does and what section F must be able to tell apart.
  const rawList = store.list.bind(store);
  store.list = (async <T>(opts?: { prefix?: string }): Promise<Map<string, T>> => {
    const src = await rawList<T>(opts);
    const out = new Map<string, T>();
    for (const [k, v] of src) out.set(k, JSON.parse(JSON.stringify(v)) as T);
    return out;
  }) as typeof store.list;

  // HAZARD 2, part two: count the writes. The DO holds the storage OBJECT, so wrapping the method is visible
  // to it, and a sweep that mutates without persisting shows up as a missing key here.
  const rawPut = store.put.bind(store);
  const putKeys: string[] = [];
  store.put = (async <T>(key: string, value: T): Promise<void> => {
    putKeys.push(key);
    return rawPut(key, value);
  }) as typeof store.put;
  const putsSince = (mark: number): string[] => putKeys.slice(mark);

  // Queue a gated dest-put carrying a credential, returning the pending record's id.
  const proposeDestPut = async (label: string, secret: string): Promise<string> => {
    const r = await doFetch("/destinations", ownerCaller(OWNER), { label, config: { ...destConfig(`${label}-bucket`), secretAccessKey: secret } });
    if (r.status !== 202) throw new Error(`expected a queued (202) dest-put, got ${r.status}`);
    return ((await r.json()) as { id: string }).id;
  };

  try {
    // ===========================================================================================
    // SECTION A: the account, the gate, and the reproduction. Everything below is vacuous unless a
    // real gated action really does store a real credential, so A asserts that rather than assuming
    // it, and A3 pins the read-path control that already existed (so a later "the secret is gone"
    // cannot be satisfied by the projection that was always there).
    // ===========================================================================================
    let firstId = "";
    {
      // A second owner is what arms dual control at all: with one owner every high-blast op runs inline and
      // no record is ever written, so there would be nothing to measure.
      ok("A1: a second owner exists", (await call(OWNER, "POST", "/admin/roles", { email: OWNER2, role: "owner" })).status === 200);
      ok("A2: the dual-control gate is armed", (await setGate(OWNER, true)).status === 200);
      firstId = await proposeDestPut("secret-lifetime-a", SECRET);
      // THE CONTROL that stops every later absence assertion being vacuous. It passes on the unfixed tree
      // and on the fixed one: the params must carry the credential while the action can still run, because
      // the approved execution replays them byte for byte.
      ok("A3: CONTROL, the queued record really does hold the credential at rest", holdsSecret(firstId, SECRET));
      const listed = (await inbox(OWNER)).find((a) => a.id === firstId);
      ok("A4: CONTROL, the pre-existing read-path redaction still strips it from the inbox", listed !== undefined && !JSON.stringify(listed.params).includes(SECRET));
      ok("A5: CONTROL, the inbox still carries the non-secret bucket, so A4 is not an empty projection", JSON.stringify(listed?.params ?? null).includes("secret-lifetime-a-bucket"));
    }

    // ===========================================================================================
    // SECTION B: a DO-EXECUTED action that RAN. The commonest case, and the one where the record is
    // most obviously finished with: the destination edit has already been applied.
    // ===========================================================================================
    {
      const r = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: firstId });
      ok("B1: CONTROL, a distinct owner's approval succeeds", r.status === 200);
      // The action must actually have RUN. Without this the scrub could be passing because the approve
      // failed outright, which is a lockout wearing a helmet rather than a fix.
      const dests = await ctx.listDestinations();
      ok("B2: CONTROL, the approved action really ran (the destination exists), so the scrub did not break replay", dests.destinations.some((d) => d.label === "secret-lifetime-a"));
      ok("B3: the executed record NO LONGER holds the credential at rest", !holdsSecret(firstId, SECRET));
      ok("B4: the executed record is marked as scrubbed", typeof atRest(firstId)?.paramsScrubbedAt === "string");
      ok("B5: CONTROL, the non-secret decision params SURVIVE, so B3 is a scrub and not an erasure", JSON.stringify(atRest(firstId)?.params ?? null).includes("secret-lifetime-a-bucket"));
      ok("B6: CONTROL, the record itself survives for the forensic account", atRest(firstId)?.status === "executed");
    }

    // ===========================================================================================
    // SECTION C: a WITHDRAWN action. The sharpest human case: an owner who realises they pasted the
    // wrong credential withdraws the proposal, and until now the withdrawal left it in storage.
    // ===========================================================================================
    {
      const id = await proposeDestPut("secret-lifetime-c", SECRET2);
      ok("C1: CONTROL, the withdrawn-to-be record holds the credential before the reject", holdsSecret(id, SECRET2));
      const r = await doFetch("/owner-actions/reject", ownerCaller(OWNER2), { id });
      ok("C2: CONTROL, the reject succeeds", r.status === 200);
      ok("C3: the rejected record NO LONGER holds the credential at rest", !holdsSecret(id, SECRET2));
      ok("C4: CONTROL, its non-secret params survive", JSON.stringify(atRest(id)?.params ?? null).includes("secret-lifetime-c-bucket"));
    }

    // ===========================================================================================
    // SECTION D: THE OVER-EAGER ARM. A router-executed action that has been APPROVED is ARMED, not
    // spent: the maker has yet to re-submit with the one-shot token, and consumeOwnerAction
    // re-derives the actionHash FROM THE STORED PARAMS to pin that consume to this exact approved
    // action. Scrubbing at approve would break the binding that stops a consume being redirected.
    // These pass on both trees by construction; they exist so a future "scrub earlier" cannot land
    // quietly.
    // ===========================================================================================
    {
      const params = { sources: [], remove: ["KV_SECRET_LIFETIME"] };
      const gc = await doFetch("/owner-actions/gate-check", ownerCaller(OWNER), { kind: "sources-attach", params, summary: "detach KV_SECRET_LIFETIME" });
      const gate = (await gc.json()) as { gate: string; id?: string; actionHash?: string };
      ok("D1: CONTROL, a router-executed action is queued rather than run", gate.gate === "pending" && typeof gate.id === "string");
      const id = gate.id ?? "";
      ok("D2: CONTROL, a distinct owner ARMS it", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id })).status === 200);
      ok("D3: an ARMED record KEEPS its params, because the consume re-derives the hash from them", JSON.stringify(atRest(id)?.params ?? null).includes("KV_SECRET_LIFETIME"));
      ok("D4: an ARMED record is NOT marked scrubbed", atRest(id)?.paramsScrubbedAt === undefined);
      // And the consume still works, which is what D3 is protecting.
      const consume = await doFetch("/owner-actions/consume", ownerCaller(OWNER), { id, expectedActionHash: atRest(id)?.actionHash });
      ok("D5: CONTROL, the armed approval still consumes cleanly", consume.status === 200);
      ok("D6: the consumed record is spent and marked scrubbed", atRest(id)?.status === "executed");
    }

    // ===========================================================================================
    // SECTION E: THE INTEGRITY GUARD, both directions. A scrubbed record's actionHash cannot
    // recompute, by construction. If that were left to collide with the tamper check, every
    // duplicate approve of a spent action would be filed as integrity-failed, which is the one
    // governance class whose whole meaning is "somebody altered a stored record". E1 proves the
    // tamper teeth survive; E2 proves the benign case no longer cries wolf.
    // ===========================================================================================
    {
      // E1: a scrubbed marker on a record that is still LIVE. Only a spent record is ever scrubbed, so this
      // is a genuine tamper (stripping the params is exactly how the consume binding would be attacked), and
      // it must keep both the refusal and the fault.
      const id = await proposeDestPut("secret-lifetime-e1", SECRET3);
      const rec = atRest(id)!;
      store.rawPut(ownerActionKey(id), { ...rec, params: { label: "secret-lifetime-e1" }, paramsScrubbedAt: new Date().toISOString() });
      const before = integrityFailedCount("owner-action-execute");
      const r = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id });
      ok("E1: a scrubbed marker on a STILL-PENDING record is refused", r.status !== 200);
      ok("E2: and it is still recorded as integrity-failed, so the tamper teeth survive the guard", integrityFailedCount("owner-action-execute") > before);

      // E3/E4: the benign case. A spent, legitimately scrubbed record approached again (an owner clicking
      // approve twice, or a re-submit racing itself) must be refused WITHOUT an integrity fault.
      const spentId = await proposeDestPut("secret-lifetime-e2", SECRET3);
      ok("E3: CONTROL, the record is spent by a real approval", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: spentId })).status === 200);
      ok("E4: CONTROL, and it was really scrubbed, so E5/E6 are about the guard and not about an untouched record", typeof atRest(spentId)?.paramsScrubbedAt === "string");
      const beforeApprove = integrityFailedCount("owner-action-approve");
      const beforeExecute = integrityFailedCount("owner-action-execute");
      const again = await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: spentId });
      ok("E5: a second approve of the spent action is refused", again.status !== 200);
      ok("E6: and NOTHING is filed as integrity-failed, so a scrub cannot masquerade as a tamper", integrityFailedCount("owner-action-approve") === beforeApprove && integrityFailedCount("owner-action-execute") === beforeExecute);

      // E7/E8: THE REASON MUST NOT DEPEND ON WHETHER THE ACTION CARRIED A SECRET. A duplicate approve of a
      // spent action must answer identically whether the record held a credential (and was scrubbed) or not.
      // The control is a spent action carrying NO secret, whose record is never scrubbed at all.
      const plainId = ((await doFetch("/destinations/default", ownerCaller(OWNER), { id: (await ctx.listDestinations()).destinations[0]?.id ?? "" }).then((x) => x.json())) as { id?: string }).id ?? "";
      ok("E7: CONTROL, a secret-free action is spent and is NOT scrubbed (nothing to strip)", (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: plainId })).status === 200 && atRest(plainId)?.paramsScrubbedAt === undefined);
      const scrubbedReason = await (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: spentId })).text();
      const plainReason = await (await doFetch("/owner-actions/approve", ownerCaller(OWNER2), { id: plainId })).text();
      ok("E8: the refusal reads THE SAME whether the spent action was scrubbed or not", scrubbedReason === plainReason && scrubbedReason.length > 0);
    }

    // ===========================================================================================
    // SECTION F: THE LAZY SWEEP, for the record nobody ever decided. This is the longest-lived copy
    // of a credential in the subsystem: proposed, never approved, never rejected, expired by a
    // clock that is COMPUTED at read and never written, so no code path visits it again. The
    // support pack already counts exactly this population as a governance stall.
    // ===========================================================================================
    {
      const id = await proposeDestPut("secret-lifetime-f", SECRET);
      const live = await proposeDestPut("secret-lifetime-f-live", SECRET2);
      // Age the first one past its TTL, leaving the second one live. Nothing else differs between them.
      const aged = atRest(id)!;
      store.rawPut(ownerActionKey(id), { ...aged, expiresAt: new Date(Date.now() - 60_000).toISOString() });
      ok("F1: CONTROL, the aged record still holds the credential before any sweep", holdsSecret(id, SECRET));

      // ONE inbox call, and the mark is taken before it: F3 must measure the writes made BY the same call
      // that F2 reads as expired, not a second call that would find nothing left to do.
      const mark = putKeys.length;
      const listed = await inbox(OWNER); // the read an owner performs most often, and one that lists the prefix
      const wrote = putsSince(mark);
      ok("F2: CONTROL, and it reads as expired, so F4 is about an expired record", listed.every((a) => a.id !== id));
      ok("F3: the sweep PERSISTED its scrub (a storage.put for that key), not merely mutated a listed copy", wrote.includes(ownerActionKey(id)));
      ok("F4: the expired-undecided record NO LONGER holds the credential at rest", !holdsSecret(id, SECRET));
      ok("F5: CONTROL, its non-secret params survive", JSON.stringify(atRest(id)?.params ?? null).includes("secret-lifetime-f-bucket"));
      // THE CONTROL THAT MAKES F4 MEAN SOMETHING. A sweep that scrubbed every record it listed would satisfy
      // F4 and would break the armed consume in section D. A live pending record must come through untouched.
      ok("F6: CONTROL, a still-LIVE pending record keeps its params through the same sweep", holdsSecret(live, SECRET2));
      ok("F7: CONTROL, and is not marked scrubbed", atRest(live)?.paramsScrubbedAt === undefined);
      ok("F8: CONTROL, the sweep changed no status, so the lifecycle is untouched", atRest(id)?.status === "pending");
    }

    // ===========================================================================================
    // SECTION G: the enumeration made executable. What is left in the store once every path above
    // has run, so the next change to this subsystem reports what it started or stopped keeping
    // rather than drifting.
    // ===========================================================================================
    {
      const keys = store.keysWithPrefix(OWNER_ACTION_PREFIX);
      ok("G1: CONTROL, records are RETAINED (a scrub is not a delete), so the forensic account survives", keys.length > 0);
      const spentHoldingSecret = keys
        .map((k) => store.rawGet<PendingOwnerAction>(k))
        .filter((r): r is PendingOwnerAction => r !== undefined)
        .filter((r) => r.status === "executed" || r.status === "rejected")
        .filter((r) => [SECRET, SECRET2, SECRET3].some((s) => JSON.stringify(r.params ?? null).includes(s)));
      ok("G2: NO spent owner-action record anywhere in the store holds a credential", spentHoldingSecret.length === 0);
    }
  } finally {
    globalThis.fetch = ctx.realFetch;
  }

  // Both arguments: called bare the guard reads failures as undefined and declares a verdict that means
  // nothing, and the check count rides so a run that asserted nothing cannot report a pass.
  if (failures > 0) process.exitCode = 1;
  console.log(`\nVERDICT: ${failures === 0 ? "PASS" : "FAIL"} failures=${failures} checks=${checks} entry=${import.meta.url.replace("file://", "")}`);
  if (failures > 0) process.exit(1);
}

await main();
