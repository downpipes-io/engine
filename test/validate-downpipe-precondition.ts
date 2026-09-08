// Prove that two operators editing one downpipe can no longer both be told they succeeded, and that a
// delete can no longer report success over a downpipe that is still running. No network, no deploy, no
// cost. Run:
//   node test/validate-downpipe-precondition.ts
//
// WHAT IS BEING GRADED, and it is the sentence rather than the status code. Two known interleaves are
// replayed here: two operators saving one downpipe with their writes overlapping (both answered 200 on
// the old behaviour, one edit silently discarded), and an overlap between a delete and a save where the
// delete answered {"deleted":true} while the downpipe survived enabled and on its cadence. This validator
// REPLAYS THOSE TWO INTERLEAVES DETERMINISTICALLY against the real router and a real SchedulerDO, by
// holding one operator's read while the other operator's write lands, which is exactly the state a real
// overlap produces. It then reads what each operator is TOLD.
//
// A live overlap cannot be manufactured in-process (MockStorage resolves synchronously, so two "concurrent"
// requests here would serialise and prove nothing, which would be a positive control of the wrong kind).
// What is established HERE is the product's answer once the interleave has happened.
//
// THE CONTROL IS EXPLICIT. Every arm carries a paired arm in which the interleave is REMOVED and nothing
// else changes: the same two operators, the same two writes, the second one's base re-read first. Those
// must all still succeed, or the check would merely be refusing everything.
//
// THE SEPARATION THIS ALSO PROVES. requireConfigApproval is FALSE throughout PROOFS 1 to 8. That is the
// point: the base check is honesty and runs at every account, and change control is governance and stays
// opt-in. PROOF 9 arms the gate and shows the queue still works, so nothing was made mandatory.

import { buildContext, OWNER, OPERATOR, OPERATOR2 } from "./validate-config-change-control-harness.ts";
import { readStripped, scanSpan, stripNonCode, YIELD_POINT_PATTERNS } from "./lib/precondition-critical-span.ts";
import { checkUpsertPrecondition, currentConfigRev, movedConfigFields, PRECONDITION_REFUSAL_REASONS, readPrecondition } from "../src/sched/downpipe-precondition.ts";
import type { DownpipeState } from "../src/sched/scheduler-do.ts";

interface Answer {
  status: number;
  body: Record<string, unknown>;
}

async function main(): Promise<void> {
  const { ctx, realFetch } = await buildContext();
  const { ok, call, listDownpipes, dp } = ctx;

  // read returns the stored record for an id, which is what an operator's SCREEN holds: the config they
  // are editing AND the configRev they will state back.
  async function read(id: string): Promise<DownpipeState | null> {
    return (await listDownpipes()).find((d) => d.config.id === id) ?? null;
  }
  async function post(email: string, path: string, body: unknown): Promise<Answer> {
    const r = await call(email, "POST", path, body);
    let parsed: Record<string, unknown>;
    try {
      parsed = (await r.json()) as Record<string, unknown>;
    } catch {
      parsed = {};
    }
    return { status: r.status, body: parsed };
  }
  const sentence = (a: Answer): string => (typeof a.body.error === "string" ? a.body.error : "");
  // pre reads the structured refusal WITHOUT assuming there is one. If the shipped overwrite-anyway
  // behaviour were restored, the answer would be a 200 with no `precondition` object at all, and a bare
  // property read would throw there and abort the run before the later arms were graded: a validator that
  // stops short under the violation it exists to detect reports FEWER reds than the violation causes.
  const pre = (a: Answer): { reason: string; yourRev: number | null; currentRev: number | null; changedFields: string[] } => {
    const p = a.body.precondition;
    if (p === null || typeof p !== "object") return { reason: "(none: the request was not refused)", yourRev: null, currentRev: null, changedFields: [] };
    return p as { reason: string; yourRev: number | null; currentRev: number | null; changedFields: string[] };
  };

  try {
    // ---- PROOF 0: the module's own invariants, before any drive ------------------------------------
    //
    // A closed reason list with a member nothing can reach is the shape this workspace records as a gate
    // that passes while it rots, so every member is asserted reachable by the arms below (PROOF 8 counts).
    ok("PROOF 0a: the refusal classes are six and closed", PRECONDITION_REFUSAL_REASONS.length === 6);
    ok("PROOF 0b: an OMITTED ifMatchRev is unstated", readPrecondition({ id: "x" }).kind === "unstated");
    ok("PROOF 0c: an EXPLICIT null ifMatchRev is a declared create, which is a different statement", readPrecondition({ id: "x", ifMatchRev: null }).kind === "expect-absent");
    ok("PROOF 0d: a number states a revision", readPrecondition({ id: "x", ifMatchRev: 4 }).kind === "expect-rev");
    {
      // A could-not-check outranks a pass: a precondition the engine cannot read must refuse, never be
      // quietly downgraded to "the caller said nothing".
      const junk = readPrecondition({ id: "x", ifMatchRev: "4" });
      const verdict = checkUpsertPrecondition({ stated: junk, prior: null, tombstone: null, guardResurrect: true, id: "x" });
      ok("PROOF 0e: an UNREADABLE ifMatchRev refuses rather than being read as unstated", junk.kind === "expect-rev" && !verdict.ok && verdict.reason === "precondition-unreadable");
    }
    ok("PROOF 0f: movedConfigFields names the field that moved and nothing else", JSON.stringify(movedConfigFields(dp("m", "m", 3600), dp("m", "m", 86400))) === '["cadenceSeconds"]');

    // ---- PROOF 1: the revision exists, starts at 1, and counts CONFIG writes only -------------------
    await post(OWNER, "/admin/downpipes", dp("pcrev", "pcrev", 3600));
    const created = await read("pcrev");
    ok("PROOF 1a: a created downpipe carries configRev 1", currentConfigRev(created) === 1);
    ok("PROOF 1b: a create records no lastConfigChange, because nothing moved", created?.lastConfigChange === undefined);
    await post(OWNER, "/admin/downpipes", { ...(created as DownpipeState).config, cadenceSeconds: 86400, ifMatchRev: 1 });
    const edited = await read("pcrev");
    ok("PROOF 1c: an edit bumps configRev to 2", currentConfigRev(edited) === 2);
    ok("PROOF 1d: the edit records WHICH field moved, by name", JSON.stringify(edited?.lastConfigChange?.fields) === '["cadenceSeconds"]');
    ok("PROOF 1e: the edit records WHO moved it", edited?.lastConfigChange?.by === OWNER);
    // This is why the key is stripped rather than merely ignored: the shipped upsert STORES an
    // unrecognised body field verbatim into the customer's configuration, so a client that adopted the
    // precondition against an engine that did not understand it would have written a statement about a
    // request into the record, and from there into every config-history diff and support-pack projection of
    // that downpipe.
    ok("PROOF 1f: the precondition is STRIPPED, never stored in the customer's config", !("ifMatchRev" in ((edited as DownpipeState).config as unknown as Record<string, unknown>)));

    // ---- PROOF 2: THE MEASURED INTERLEAVE. Two operators, one downpipe, both saving ------------------
    //
    // Operator A and operator B both load the same downpipe, so their bases are the same record at the
    // same revision. A saves a schedule change. B, whose screen still shows the pre-A config, saves a
    // rename. This is interleave's arm B replayed: on the shipped engine both were answered 200 and A's
    // schedule change was silently reverted by B's whole-object upsert.
    await post(OWNER, "/admin/downpipes", dp("pctwo", "pctwo", 3600));
    const baseA = await read("pctwo");
    const baseB = await read("pctwo"); // the SAME bytes: B's screen loaded before A wrote
    ok("PROOF 2a: both operators hold the same base revision", currentConfigRev(baseA) === currentConfigRev(baseB));

    const aSaves = await post(OPERATOR, "/admin/downpipes", { ...(baseA as DownpipeState).config, cadenceSeconds: 86400, ifMatchRev: currentConfigRev(baseA) });
    ok("PROOF 2b: operator A, who is first and whose base is current, is answered 200", aSaves.status === 200);

    const bSaves = await post(OPERATOR2, "/admin/downpipes", { ...(baseB as DownpipeState).config, name: "renamedbyb", ifMatchRev: currentConfigRev(baseB) });
    ok("PROOF 2c: operator B is NOT told they succeeded", bSaves.status !== 200);
    ok("PROOF 2d: operator B is answered 409, a conflict, not 400, a bad request", bSaves.status === 409);
    ok("PROOF 2e: operator B is told the downpipe changed under them", sentence(bSaves).includes("changed since you loaded it"));
    ok("PROOF 2f: operator B is told WHICH field moved, by name", sentence(bSaves).includes("cadenceSeconds"));
    ok("PROOF 2g: operator B is told their edit was NOT saved", sentence(bSaves).includes("was not saved"));
    const afterTwo = await read("pctwo");
    ok("PROOF 2h: A's schedule change SURVIVED, which is the edit that used to be discarded", afterTwo?.config.cadenceSeconds === 86400);
    ok("PROOF 2i: B's rename did NOT land, and B knows it", afterTwo?.config.name === "pctwo");
    ok("PROOF 2j: the refusal carries the two revisions a client needs to reconcile", pre(bSaves).yourRev === 1 && pre(bSaves).currentRev === 2);

    // ---- CONTROL 2: remove the interleave and change NOTHING else ------------------------------------
    //
    // Same two operators, same two edits, same order. B simply re-reads before saving, which is what a
    // real second operator who arrived a moment later would hold. Both must succeed, or the check above is
    // refusing everything rather than refusing a collision.
    await post(OWNER, "/admin/downpipes", dp("pcctl", "pcctl", 3600));
    const ctlA = await read("pcctl");
    const ctlASaves = await post(OPERATOR, "/admin/downpipes", { ...(ctlA as DownpipeState).config, cadenceSeconds: 86400, ifMatchRev: currentConfigRev(ctlA) });
    const ctlB = await read("pcctl"); // B's screen loaded AFTER A wrote: no interleave
    const ctlBSaves = await post(OPERATOR2, "/admin/downpipes", { ...(ctlB as DownpipeState).config, name: "renamedbyb", ifMatchRev: currentConfigRev(ctlB) });
    const ctlAfter = await read("pcctl");
    ok("CONTROL 2a: with the interleave removed, operator A is answered 200", ctlASaves.status === 200);
    ok("CONTROL 2b: with the interleave removed, operator B is ALSO answered 200", ctlBSaves.status === 200);
    ok("CONTROL 2c: both changes survive, so the check refuses collisions and not edits", ctlAfter?.config.cadenceSeconds === 86400 && ctlAfter?.config.name === "renamedbyb");

    // ---- PROOF 3: THE DELETE THAT SAID {"deleted":true} OVER A RUNNING DOWNPIPE ----------------------
    //
    // interleave's arm D, replayed. Operator A deletes. Operator B, whose screen still shows the row,
    // saves an edit to it. On the shipped engine the delete answered {"deleted":true} with no
    // qualification and B's whole-object upsert RECREATED the downpipe, enabled and on its cadence, so A
    // was told a backup was stopped while the product went on running it and charging for it.
    await post(OWNER, "/admin/downpipes", dp("pcdel", "pcdel", 3600));
    const delBase = await read("pcdel"); // B's screen
    const deleted = await post(OPERATOR, "/admin/downpipes/delete", { id: "pcdel", ifMatchRev: currentConfigRev(delBase) });
    ok("PROOF 3a: the delete succeeds and says which revision it removed", deleted.status === 200 && deleted.body.deleted === true && deleted.body.deletedRev === 1);
    const resurrect = await post(OPERATOR2, "/admin/downpipes", { ...(delBase as DownpipeState).config, cadenceSeconds: 86400, ifMatchRev: currentConfigRev(delBase) });
    ok("PROOF 3b: the saving operator is NOT told they succeeded", resurrect.status === 409);
    ok("PROOF 3c: the saving operator is told the downpipe was DELETED, not merely that it moved", sentence(resurrect).includes("was deleted since you loaded it"));
    ok("PROOF 3d: the saving operator is told it was not recreated", sentence(resurrect).includes("was not recreated"));
    ok("PROOF 3e: THE DELETING OPERATOR'S ANSWER IS STILL TRUE: the downpipe is gone", (await read("pcdel")) === null);

    // ---- PROOF 4: 44 WITHOUT A STATED PRECONDITION AT ALL --------------------------------------------
    //
    // PROOF 3 closes the resurrection for a client that states a base. That is not enough for the
    // highest-consequence shape here: a destructive operation that reports success without
    // having happened must not depend on a client behaving. This arm sends the save with NO ifMatchRev at
    // all, which is exactly what the shipped console and any raw API caller sends today.
    await post(OWNER, "/admin/downpipes", dp("pctomb", "pctomb", 3600));
    const tombBase = await read("pctomb");
    const tombDelete = await post(OPERATOR, "/admin/downpipes/delete", { id: "pctomb" });
    ok("PROOF 4a: an unconditioned delete still works and still says deleted", tombDelete.status === 200 && tombDelete.body.deleted === true);
    const tombResurrect = await post(OPERATOR2, "/admin/downpipes", { ...(tombBase as DownpipeState).config, cadenceSeconds: 86400 });
    ok("PROOF 4b: an UNCONDITIONED save cannot resurrect it either", tombResurrect.status === 409);
    ok("PROOF 4c: and the caller is told how to recreate it deliberately", sentence(tombResurrect).includes("ifMatchRev set to null"));
    ok("PROOF 4d: THE DELETE'S ANSWER IS STILL TRUE with no precondition stated anywhere", (await read("pctomb")) === null);
    // The guard stops a race and never stops an operator: a deliberate recreate is one request away.
    const deliberate = await post(OPERATOR2, "/admin/downpipes", { ...(tombBase as DownpipeState).config, ifMatchRev: null });
    ok("PROOF 4e: a DELIBERATE recreate, which declares the create, is allowed", deliberate.status === 200);
    ok("PROOF 4f: and the recreated downpipe starts a fresh revision at 1", currentConfigRev(await read("pctomb")) === 1);

    // ---- CONTROL 4: the same delete with nothing racing it -------------------------------------------
    await post(OWNER, "/admin/downpipes", dp("pcdelctl", "pcdelctl", 3600));
    const delCtl = await post(OPERATOR, "/admin/downpipes/delete", { id: "pcdelctl", ifMatchRev: 1 });
    ok("CONTROL 4a: a delete with nothing racing it answers deleted:true", delCtl.status === 200 && delCtl.body.deleted === true);
    ok("CONTROL 4b: and leaves nothing behind", (await read("pcdelctl")) === null);

    // ---- PROOF 5: THE DELETE'S OWN BASE CHECK, the other ordering ------------------------------------
    //
    // The save lands first and the delete arrives holding the pre-save base. An operator who deletes a
    // downpipe they have not seen the current state of is deleting something else.
    await post(OWNER, "/admin/downpipes", dp("pcorder", "pcorder", 3600));
    const orderBase = await read("pcorder");
    await post(OPERATOR, "/admin/downpipes", { ...(orderBase as DownpipeState).config, cadenceSeconds: 86400, ifMatchRev: 1 });
    const staleDelete = await post(OPERATOR2, "/admin/downpipes/delete", { id: "pcorder", ifMatchRev: currentConfigRev(orderBase) });
    ok("PROOF 5a: a delete whose base moved is refused", staleDelete.status === 409);
    ok("PROOF 5b: and it names the field that moved under it", sentence(staleDelete).includes("cadenceSeconds"));
    ok("PROOF 5c: and it says plainly that nothing was deleted", sentence(staleDelete).includes("was not deleted"));
    ok("PROOF 5d: the downpipe is STILL THERE, which is what the refusal claimed", (await read("pcorder")) !== null);

    // ---- PROOF 6: a declared create over an existing downpipe ----------------------------------------
    const clash = await post(OPERATOR, "/admin/downpipes", { ...dp("pcorder", "clashing", 3600), ifMatchRev: null });
    ok("PROOF 6a: a declared create over an existing id is refused, not silently an overwrite", clash.status === 409);
    ok("PROOF 6b: and the refusal says it was not overwritten", sentence(clash).includes("was not overwritten"));
    ok("PROOF 6c: the existing downpipe is untouched", (await read("pcorder"))?.config.name === "pcorder");

    // ---- PROOF 7: a running backup must not refuse an operator's save --------------------------------
    //
    // The revision counts CONFIG writes, not writes. If it moved on a heartbeat or a run completion, the
    // check would refuse an operator's save because a BACKUP RAN, which is not a collision, and a check
    // that fires on non-collisions is a check that gets switched off. Driven through the real trigger and
    // completion routes rather than by writing storage directly, so the run path's own writer is what runs.
    await post(OWNER, "/admin/downpipes", dp("pcrun", "pcrun", 3600));
    const runBase = await read("pcrun");
    await call(OWNER, "POST", "/admin/trigger", { id: "pcrun" });
    const afterRun = await read("pcrun");
    ok("PROOF 7a: a triggered run did NOT move the config revision", currentConfigRev(afterRun) === currentConfigRev(runBase));
    const saveAfterRun = await post(OPERATOR, "/admin/downpipes", { ...(runBase as DownpipeState).config, cadenceSeconds: 86400, ifMatchRev: currentConfigRev(runBase) });
    ok("PROOF 7b: and an operator holding the pre-run base is still allowed to save", saveAfterRun.status === 200);

    // ---- PROOF 8: every closed refusal class was actually reached ------------------------------------
    //
    // ASSERT THE POPULATION. "No write was lost" is also true of a run in which nothing collided, and a
    // closed class nothing reaches is a gate that passes while it rots.
    const reached = new Set<string>([
      pre(bSaves).reason,
      pre(resurrect).reason,
      pre(tombResurrect).reason,
      pre(staleDelete).reason,
      pre(clash).reason,
      "precondition-unreadable", // reached in PROOF 0e against the pure checker
    ]);
    const missed = PRECONDITION_REFUSAL_REASONS.filter((r) => !reached.has(r));
    // already-deleted is the sixth: a stated delete that finds nothing.
    const alreadyDeleted = await post(OPERATOR, "/admin/downpipes/delete", { id: "pcdelctl", ifMatchRev: 1 });
    ok("PROOF 8a: a stated delete of a downpipe that is already gone refuses rather than reporting success", alreadyDeleted.status === 409 && pre(alreadyDeleted).reason === "already-deleted");
    ok(`PROOF 8b: every one of the six closed refusal classes was reached (missing: ${missed.filter((m) => m !== "already-deleted").join(",") || "none"})`, missed.filter((m) => m !== "already-deleted").length === 0);

    // ---- PROOF 9: change control was NOT made mandatory ----------------------------------------------
    //
    // The whole point of the separation. Everything above ran with requireConfigApproval FALSE, so the base
    // check is reachable at every account. Here the gate is armed and the queue must still behave exactly
    // as it did: a proposal is queued as a 202 rather than applied, and it is NOT converted into a refusal
    // by the new check.
    const policyBefore = (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean };
    ok("PROOF 9a: the approval gate was OFF for every proof above, so the base check is not riding on it", policyBefore.requireConfigApproval === false);
    await ctx.setGate(OWNER, true);
    await post(OWNER, "/admin/downpipes", dp("pcgated", "pcgated", 3600));
    const queued = await post(OWNER, "/admin/downpipes", { ...dp("pcgated", "pcgated", 3600), ifMatchRev: null });
    ok("PROOF 9b: with the gate ON a downpipe create is still QUEUED (202), not refused by the base check", queued.status === 202 && queued.body.queued === true);
    await ctx.setGate(OWNER, false);
    const policyAfter = (await (await call(OWNER, "GET", "/admin/config/approval-policy")).json()) as { requireConfigApproval: boolean };
    ok("PROOF 9c: and the gate is back off, unchanged by anything here", policyAfter.requireConfigApproval === false);
    // ---- PROOF 11: THE CHECK CANNOT BE QUIETLY TURNED BACK INTO A RACE -------------------------------
    //
    // Everything above is a functional assertion, and every one of them would STILL PASS if a later edit
    // dropped a WebCrypto digest between the read of dp:<id> and the write of dp:<id>. That await is a yield
    // point: a Durable Object's input gate holds concurrent events out across a STORAGE operation and not
    // across a hash, which reopens the same overlap window this file cannot manufacture in-process at all.
    //
    // THE ATOMICITY ARGUMENT RESTS ON THE PLATFORM GATE AND IS NOT DRIVEN HERE, which is said plainly rather
    // than implied: proving it needs a workerd harness driving the object concurrently, which this pass did
    // not build. What IS checkable, cheaply and exactly, is the premise the argument depends on, so that is
    // what is checked: the span contains storage awaits and synchronous JS and nothing else.
    {
      const stripped = readStripped(new URL("../src/sched/scheduler-do.ts", import.meta.url).pathname);
      const upsert = scanSpan(stripped, "addDownpipe", "const prior = await this.state.storage.get<DownpipeState>(`dp:${resolved.id}`)", "await this.persistDownpipeState(ds)");
      // ANCHORED ON THE METHOD SIGNATURE. Without the anchor this line would scan addDownpipe's span while
      // believing it had scanned the delete's, because the two reads are byte-identical once their template
      // literals are stripped. See the comment on scanSpan for why the anchor is required.
      const del = scanSpan(stripped, "removeDownpipe", "const prior = await this.state.storage.get<DownpipeState>(`dp:${req.id}`)", "await this.state.storage.delete(`dp:${req.id}`)", "async removeDownpipe(");
      ok("PROOF 11b1: the delete's span is ANCHORED to removeDownpipe and not silently to the upsert's identical line", del.found && stripped.indexOf("async removeDownpipe(") >= 0 && stripped.indexOf("async removeDownpipe(") < stripped.length);
      ok("PROOF 11a: the upsert's critical span is LOCATABLE, so a silent zero is not mistaken for a clean one", upsert.found);
      ok("PROOF 11b: the delete's critical span is LOCATABLE", del.found);
      ok(`PROOF 11a2: no yield point between the upsert's read and its write (${upsert.findings.map((f) => `${f.yieldPoint}@${f.line}`).join(", ") || "none"})`, upsert.found && upsert.findings.length === 0);
      ok(`PROOF 11b2: no yield point between the delete's read and its delete (${del.findings.map((f) => `${f.yieldPoint}@${f.line}`).join(", ") || "none"})`, del.found && del.findings.length === 0);
      // THE KNOWN POSITIVE. A scanner that finds nothing proves nothing until it is shown finding something:
      // a scanner that reads a comment as code, and one that matches nothing at all, are both real failure
      // modes. Both directions are pinned here rather than trusted.
      const planted = stripNonCode("async f(){\n const prior = await this.state.storage.get(1);\n await crypto.subtle.digest('SHA-256', b);\n await this.persistDownpipeState(ds);\n}");
      const plantedScan = scanSpan(planted, "fixture", "const prior = await this.state.storage.get(1)", "await this.persistDownpipeState(ds)");
      // TWO findings, not one, and that is correct rather than a bug: `crypto.subtle.digest(` is both the
      // WebCrypto namespace and a digest call, and both patterns are meant to catch it. Asserting only one
      // would be an over-tight expectation, which the known positive surfaces.
      ok(`PROOF 11c: KNOWN POSITIVE, the scanner finds a planted crypto await in the span (${plantedScan.findings.map((f) => f.yieldPoint).join(", ")})`, plantedScan.found && plantedScan.findings.length === 2 && plantedScan.findings.some((f) => f.yieldPoint === "crypto.subtle") && plantedScan.findings.some((f) => f.yieldPoint === "a digest helper"));
      // The other direction: the SAME text inside a comment must NOT be found, or the guard would report
      // prose as a defect and be switched off.
      const commented = stripNonCode("async f(){\n const prior = await this.state.storage.get(1);\n // await crypto.subtle.digest('SHA-256', b);\n await this.persistDownpipeState(ds);\n}");
      const commentedScan = scanSpan(commented, "fixture", "const prior = await this.state.storage.get(1)", "await this.persistDownpipeState(ds)");
      ok("PROOF 11d: KNOWN NEGATIVE, the identical line inside a COMMENT is not found", commentedScan.found && commentedScan.findings.length === 0);
      ok("PROOF 11e: and the same line inside a STRING is not found either", scanSpan(stripNonCode("async f(){\n const prior = await this.state.storage.get(1);\n log(\"await crypto.subtle.digest\");\n await this.persistDownpipeState(ds);\n}"), "fixture", "const prior = await this.state.storage.get(1)", "await this.persistDownpipeState(ds)").findings.length === 0);
      ok("PROOF 11f: the yield-point list is closed and non-empty", YIELD_POINT_PATTERNS.length === 5);
    }

    // ---- PROOF 10: WHAT THIS REPAIR CLOSES FOR THE CONSOLE AS IT IS SHIPPED TODAY -------------------
    //
    // The console does not yet send ifMatchRev, and the console is claimed by another pass, so this arm
    // exists so that nobody (including me) can read "42 and 44 are repaired" off the engine change alone.
    // It drives EXACTLY what the shipped client sends: no precondition on either route.
    //
    // THE TWO ANSWERS ARE DIFFERENT AND THE DIFFERENCE IS THE POINT.
    await post(OWNER, "/admin/downpipes", dp("pcship", "pcship", 3600));
    const shipBase = await read("pcship");
    const shipA = await post(OPERATOR, "/admin/downpipes", { ...(shipBase as DownpipeState).config, cadenceSeconds: 86400 });
    const shipB = await post(OPERATOR2, "/admin/downpipes", { ...(shipBase as DownpipeState).config, name: "shipped-b" });
    ok("PROOF 10a: 42 IS STILL OPEN for a client that states no base: both unconditioned saves are answered 200", shipA.status === 200 && shipB.status === 200);
    ok("PROOF 10b: and one edit is still silently discarded, which is why the console half is named and not assumed", (await read("pcship"))?.config.cadenceSeconds === 3600);
    // The destructive shape is a different matter, and it does NOT wait on a client change.
    await post(OWNER, "/admin/downpipes", dp("pcshipd", "pcshipd", 3600));
    const shipDelBase = await read("pcshipd");
    const shipDel = await post(OPERATOR, "/admin/downpipes/delete", { id: "pcshipd" });
    const shipSave = await post(OPERATOR2, "/admin/downpipes", { ...(shipDelBase as DownpipeState).config, cadenceSeconds: 86400 });
    ok("PROOF 10c: 44 IS CLOSED for the shipped client too: the unconditioned save is refused", shipDel.body.deleted === true && shipSave.status === 409);
    ok("PROOF 10d: so the delete's {\"deleted\":true} is TRUE with no client change at all", (await read("pcshipd")) === null);
  } finally {
    globalThis.fetch = realFetch;
  }

  const failures = ctx.getFailures();
  console.log(failures === 0 ? "\nDOWNPIPE PRECONDITION VECTORS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
