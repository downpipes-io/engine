// The audit tamper-evidence + telemetry-correctness cells (net-zero, in-process, no estate,
// no deploy, no spend). This EXTENDS the shipped validate-audit-* suite rather than redoing it: the shipped
// PROOF 6-9b (validate-audit-chain.ts) already drive the alteration, the mid-chain deletion and the seq-gap
// through the product's own verify, and PROOF 1/1b/2/2b (validate-audit-events.ts) already prove the router
// emissions. What this file adds:
//   (a) the tamper cells re-run against a HARNESS-OWNED independent oracle (validate-audit-independent-oracle.ts),
//       not the product's verifyChain, so a hashing bug shared by the writer and the verifier is catchable;
//   (b) the TAIL-TRUNCATION execution cell, the one break class the shipped suite never drives, asserted through
//       the head-anchor witness (verifyAudit.headTruncated) while the recompute alone reads intact;
//   (c) explicit insertion and reorder cells scoped to the two real invariants (the prevHash link and the seq
//       contiguity); and
//   (d) the telemetry best-effort BOUND: a non-2xx audit append is a COUNTED loss, not a silent one.
//
// FIDELITY (this file honours the real mechanism, never a naive framing):
//   - The chain is an UNKEYED SHA-384 hash-chain, NOT a signature. The claim asserted here is exactly the
//     product's: "tamper-EVIDENT, never tamper-proof; a holder of the DO storage could rewrite the whole chain"
//     (audit.ts:7-10). Every tamper cell proves detection of a tamper that is NOT a fully-coordinated re-chain.
//   - Tail truncation is caught by a SEPARATE unkeyed head-anchor witness (AUDIT_HEAD_KEY), NOT by verifyChain,
//     which reads intact over a truncated tail (scheduler-do-audit.ts:292-305). The tail cell drives the anchor.
//   - A legitimate retention ROLLOVER must NOT read as tamper, and is distinguished from a truncation: a rollover
//     drops the OLDEST entries (head unchanged, headTruncated absent), a truncation drops the NEWEST.
//   - Ground truth is the HARNESS's own oracle and its own before/after knowledge, never the engine verifying
//     itself.
//
import { handleAdmin } from "../src/admin/router.ts";
import { auditHash, auditKey, AUDIT_PREFIX, verifyChain, type AuditDraft, type AuditEvent } from "../src/admin/audit.ts";
import { recordAudit } from "../src/admin/router-audit.ts";
import { pendingDroppedWrites, resetPendingDroppedWrites } from "../src/admin/diag-writer.ts";
import { AUDIT_HEAD_KEY, AUDIT_ROLLOVER_KEY, type AuditHead } from "../src/sched/scheduler-do-limits.ts";
import type { Env } from "../src/env.d.ts";
import { AUD, type Caller, makeScheduler, OWNER, type Scheduler, TEAM } from "./validate-audit-harness.ts";
import type { Ctx } from "./validate-audit-harness.ts";
import { independentAuditDigest, walkChainIndependently } from "./validate-audit-independent-oracle.ts";

// The GET /admin/audit/verify body shape (verifyAudit): the recompute verdict PLUS the head-anchor verdict.
type VerifyResult = {
  intact: boolean;
  checkedThrough: number;
  earliestSeq: number;
  rolledOver: boolean;
  rolledOverCount: number;
  brokenAt?: number;
  headTruncated?: boolean;
  headTruncatedAt?: number;
  auditCount: number;
  auditNearCap: boolean;
};

// clone deep-copies a stored entry so a cell can keep the ORIGINAL to restore and build a tamper as a fresh
// object, never mutating the stored reference by accident (MockStorage.rawGet returns the stored ref).
function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

export async function runTamper(ctx: Ctx): Promise<void> {
  const { ok, tokenFor } = ctx;

  // A FRESH, isolated DO for the positive control and the tamper cells (a to f), so the harness owns the whole
  // chain and every seq. The JWKS-stubbed globalThis.fetch installed by buildContext is still in force, so the
  // forged Owner token verifies for real against the same controlled JWKS; we only bind the env + call helper to
  // THIS scheduler, exactly as validate-audit-export-complete.ts does.
  const fresh = makeScheduler();
  const freshEnv = (): Env => ({ ...fresh.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;
  async function verifyRoute(sched: Scheduler): Promise<VerifyResult> {
    const env = (): Env => ({ ...sched.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env;
    const r = await handleAdmin(new Request("https://engine.example/admin/audit/verify", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor(OWNER) } }), env());
    return (await r.json()) as VerifyResult;
  }

  // appendDraft appends one entry through the REAL DO write path (POST /audit -> appendAuditFromRouter ->
  // appendAudit), so the entry is chained AND the head-anchor pointer (AUDIT_HEAD_KEY) is written on every
  // commit, which the tail-truncation cell depends on. Seeding via rawPut (as export-complete does for volume)
  // would never write the anchor, so the chain is built through the route here.
  async function appendDraft(sched: Scheduler, draft: AuditDraft): Promise<AuditEvent> {
    const r = await sched.stub.fetch("https://scheduler.internal/audit", { method: "POST", body: JSON.stringify(draft), headers: { "content-type": "application/json" } });
    return (await r.json()) as AuditEvent;
  }

  // snapshot reads the whole chain in ascending-seq order (rawKeys is sorted, so the keys and entries align by
  // index), for tampering by index and for feeding the oracle.
  function snapshot(sched: Scheduler): { keys: string[]; entries: AuditEvent[] } {
    const keys = sched.storage.rawKeys(AUDIT_PREFIX);
    return { keys, entries: keys.map((k) => sched.storage.rawGet<AuditEvent>(k)!) };
  }

  // A representative chain of REAL entries: a mix of engine-observed (null subject, omitted from the hash) and
  // access-attributed (string subject, folded into the hash) entries, so the independent oracle exercises BOTH
  // inclusion paths of the hashed-field set. Built after a bootstrap, whose own rows are valid chain entries.
  const SUBJECT = (n: number): string => `https://team.example|sub-tamper-${n}`;
  const IP = "203.0.113.10";
  const drafts: AuditDraft[] = [
    { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-version-change", outcome: "success", target: { kind: "engine-state", field: "engineVersion", detail: "0.0.1" } },
    { actorSubject: SUBJECT(1), actorEmail: "op@acme.example", actorMethod: "access", sourceIp: IP, action: "downpipe-create", outcome: "success", target: { kind: "downpipe", id: "dpA", name: "Alpha" } },
    { actorSubject: SUBJECT(2), actorEmail: "op@acme.example", actorMethod: "access", sourceIp: IP, action: "role-change", outcome: "success", target: { kind: "role", email: "newhire@acme.example", role: "viewer" } },
    { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-secret-present", outcome: "success", target: { kind: "engine-state", field: "secret-present", detail: "signerConfigured" } },
    { actorSubject: SUBJECT(3), actorEmail: "op@acme.example", actorMethod: "access", sourceIp: IP, action: "run-trigger", outcome: "success", target: { kind: "run", runId: "01ARZ3NDEKTSV4RRFFQ69G5FAV" } },
    { actorSubject: SUBJECT(4), actorEmail: "op@acme.example", actorMethod: "access", sourceIp: IP, action: "downpipe-delete", outcome: "success", target: { kind: "downpipe", id: "dpB" } },
    { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-version-change", outcome: "success", target: { kind: "engine-state", field: "engineVersion", detail: "0.0.2" } },
  ];

  // Bootstrap OWNER (first Access caller -> Owner) so GET /admin/audit/verify authorises, then build the chain.
  await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor(OWNER) } }), freshEnv());
  for (const d of drafts) await appendDraft(fresh, d);

  // ============================================================================================
  // Cell (a): POSITIVE CONTROL. A clean, untampered trail verifies intact, the head-anchor is quiet, and the
  // HARNESS-OWNED independent oracle AGREES with every entry (the two-sided guard: an oracle that disagreed with
  // a clean entry, or a suite that flagged a clean trail as tampered, fails here).
  // ============================================================================================
  {
    const { entries } = snapshot(fresh);
    ok("cell(a) positive control: the chain has enough entries to make the tamper cells meaningful", entries.length >= 7);
    const v = await verifyRoute(fresh);
    ok("cell(a) positive control: a clean trail verifies intact (verifyChain)", v.intact === true);
    ok("cell(a) positive control: checkedThrough is the head seq", v.checkedThrough === entries[entries.length - 1]!.seq);
    // A clean trail must NOT trip the head-anchor witness (the discriminator: this is what a rollover and a
    // truncation are told apart by; here neither has happened).
    ok("cell(a) positive control: a clean trail is NOT flagged truncated (headTruncated absent)", v.headTruncated === undefined);
    ok("cell(a) positive control: a clean trail is NOT flagged rolled over", v.rolledOver === false);
    // The independent oracle AGREES with every clean entry's stored hash, so the pass does not rest on the engine
    // verifying itself, and an oracle whose canonicalisation had drifted would be caught right here.
    const everyDigestAgrees = entries.every((e) => independentAuditDigest(e) === e.hash);
    ok("cell(a) independent-oracle sibling: the harness digest AGREES with every clean entry (not a broken oracle)", everyDigestAgrees);
    const indep = walkChainIndependently(entries);
    ok("cell(a) independent-oracle sibling: the harness walk agrees the clean chain is intact", indep.intact === true && indep.checkedThrough === entries[entries.length - 1]!.seq);
    // Non-vacuous oracle: flipping a field WITHOUT recompute makes the SAME oracle disagree (so it cannot rubber
    // stamp a tamper). A pure unit check, no storage touched.
    const probe = clone(entries[2]!);
    const flipped: AuditEvent = { ...probe, outcome: probe.outcome === "success" ? "denied" : "success" };
    ok("cell(a) independent-oracle sibling: the harness digest DISAGREES with a field-flipped entry (not a vacuous oracle)", independentAuditDigest(flipped) !== flipped.hash);
  }

  // ============================================================================================
  // Cell (b): ALTERATION. An in-place edit of a stored entry is detected at that seq. NET-NEW over the shipped
  // PROOF 8: the causeClass (recompute-mismatch, which GET /verify does not surface) is asserted, and the
  // HARNESS-OWNED independent digest of the edited entry DISAGREES with its stored hash.
  // Refuter (keystone, default-FAIL): a tampered trail that verifies clean fails the cell.
  // ============================================================================================
  {
    const { keys, entries } = snapshot(fresh);
    const i = 2; // a mid-chain entry
    const orig = clone(entries[i]!);
    const edited: AuditEvent = { ...orig, outcome: orig.outcome === "success" ? "denied" : "success" }; // no re-chain
    fresh.storage.rawPut(keys[i]!, edited);

    const v = await verifyRoute(fresh);
    ok("cell(b) alteration: the keystone refuter holds (a tampered trail does NOT verify clean)", v.intact === false);
    ok("cell(b) alteration: the break is reported at the edited seq", v.brokenAt === orig.seq);
    // causeClass via the product's pure verifyChain over the readback (the route hides the cause); it must be the
    // in-place-edit cause.
    const after = snapshot(fresh).entries;
    const product = await verifyChain(after);
    ok("cell(b) alteration: the product causeClass is recompute-mismatch at the edited seq", product.causeClass === "recompute-mismatch" && product.brokenAt === orig.seq);
    // The HARNESS-OWNED oracle detects the same, independently of the product's hashing.
    const indep = walkChainIndependently(after);
    ok("cell(b) alteration: the harness oracle disagrees with the edited entry (recompute-mismatch)", indep.intact === false && indep.causeClass === "recompute-mismatch" && indep.brokenAt === orig.seq);
    ok("cell(b) alteration: the harness digest of the edited entry disagrees with its stored hash", independentAuditDigest(edited) !== edited.hash);

    fresh.storage.rawPut(keys[i]!, orig); // restore
    ok("cell(b) alteration: restoring the entry re-verifies the chain", (await verifyRoute(fresh)).intact === true);
  }

  // ============================================================================================
  // Cell (c): DELETION, both naive and re-linked. NET-NEW over PROOF 9/9b: the causeClass is asserted and the
  // HARNESS-OWNED oracle drives the detection.
  //   (c1) naive: delete a mid entry, leave its successor -> prev-hash-mismatch at the entry after the hole.
  //   (c2) re-linked: delete a mid entry AND re-link + recompute the successor so the HASH chain is unbroken ->
  //        only the seq gap remains. The harness digest CONFIRMS the re-linked successor is internally consistent
  //        (it agrees), isolating the seq-contiguity check as the sole remaining evidence.
  // Refuter (keystone, default-FAIL): a deletion that verifies clean fails the cell.
  // ============================================================================================
  {
    // (c1) naive deletion.
    const { keys, entries } = snapshot(fresh);
    const h = 3; // hole
    const hole = clone(entries[h]!);
    fresh.storage.rawDelete(keys[h]!);

    const v = await verifyRoute(fresh);
    ok("cell(c1) naive deletion: the keystone refuter holds (the deletion does NOT verify clean)", v.intact === false);
    ok("cell(c1) naive deletion: the break is at the entry after the hole", typeof v.brokenAt === "number" && v.brokenAt > hole.seq);
    const after1 = snapshot(fresh).entries;
    const product1 = await verifyChain(after1);
    ok("cell(c1) naive deletion: the product causeClass is prev-hash-mismatch", product1.causeClass === "prev-hash-mismatch" && product1.brokenAt === hole.seq + 1);
    const indep1 = walkChainIndependently(after1);
    ok("cell(c1) naive deletion: the harness oracle reports prev-hash-mismatch at the entry after the hole", indep1.intact === false && indep1.causeClass === "prev-hash-mismatch" && indep1.brokenAt === hole.seq + 1);
    fresh.storage.rawPut(keys[h]!, hole); // restore
    ok("cell(c1) naive deletion: restoring the entry re-verifies the chain", (await verifyRoute(fresh)).intact === true);
  }
  {
    // (c2) re-linked deletion (the sophisticated tamper the seq check exists for).
    const { keys, entries } = snapshot(fresh);
    const h = 3;
    const predecessor = clone(entries[h - 1]!);
    const hole = clone(entries[h]!);
    const successor = clone(entries[h + 1]!);
    ok("cell(c2) re-linked deletion: pre-tamper the hole and its successor are seq-contiguous", successor.seq === hole.seq + 1 && hole.seq === predecessor.seq + 1);

    fresh.storage.rawDelete(keys[h]!);
    const relinked: AuditEvent = { ...successor, prevHash: predecessor.hash };
    relinked.hash = await auditHash(relinked); // the attacker re-chains the successor with the product's own hash
    fresh.storage.rawPut(keys[h + 1]!, relinked);

    const v = await verifyRoute(fresh);
    ok("cell(c2) re-linked deletion: the keystone refuter holds (the re-linked deletion does NOT verify clean)", v.intact === false);
    ok("cell(c2) re-linked deletion: the break is at the successor (its seq now jumps by two)", v.brokenAt === successor.seq);
    const after2 = snapshot(fresh).entries;
    const product2 = await verifyChain(after2);
    ok("cell(c2) re-linked deletion: the product causeClass is seq-gap (the hash chain is intact across the hole)", product2.causeClass === "seq-gap" && product2.brokenAt === successor.seq);
    const indep2 = walkChainIndependently(after2);
    ok("cell(c2) re-linked deletion: the harness oracle reports seq-gap at the successor", indep2.intact === false && indep2.causeClass === "seq-gap" && indep2.brokenAt === successor.seq);
    // The harness digest CONFIRMS the re-linked successor is internally consistent, isolating the seq check.
    ok("cell(c2) re-linked deletion: the harness digest AGREES with the re-linked successor (internally consistent, so only the seq gap is evidence)", independentAuditDigest(relinked) === relinked.hash);

    fresh.storage.rawPut(keys[h]!, hole); // restore hole
    fresh.storage.rawPut(keys[h + 1]!, successor); // restore original successor link
    ok("cell(c2) re-linked deletion: restoring the hole and the original link re-verifies the chain", (await verifyRoute(fresh)).intact === true);
  }

  // ============================================================================================
  // Cell (d): INSERTION. A forged entry spliced into the chain is detected. NET-NEW cell (the shipped suite has
  // no insertion drive). Two shapes, each scoped to one real invariant.
  //   (d1) forged entry takes an existing slot (a key overwrite): the overwritten real entry is gone, so the NEXT
  //        entry's prevHash no longer links -> prev-hash-mismatch. Honest scope: an attacker who re-chains EVERY
  //        entry from here to the head AND rewrites the anchor is outside the claim (audit.ts:7-10); this proves
  //        detection of an insertion that is not a full coordinated re-chain.
  //   (d2) a forged entry is appended with a fresh, NON-CONTIGUOUS seq (re-linked to the head, recomputed) ->
  //        seq-gap. The head anchor is deliberately left untouched, so this is a seq-contiguity catch, not a tail
  //        truncation (the retained head rises above the anchor, so headTruncated stays absent).
  // Refuter (keystone, default-FAIL): a forged insertion that verifies clean fails the cell.
  // ============================================================================================
  {
    // (d1) forged entry takes an existing slot.
    const { keys, entries } = snapshot(fresh);
    const i = 2;
    const orig = clone(entries[i]!);
    const next = clone(entries[i + 1]!);
    const forged: AuditEvent = { ...orig, outcome: orig.outcome === "success" ? "denied" : "success" };
    forged.hash = await auditHash(forged); // internally consistent, but its content (and hash) differs from orig
    fresh.storage.rawPut(keys[i]!, forged);

    const v = await verifyRoute(fresh);
    ok("cell(d1) insertion (slot overwrite): the keystone refuter holds (the forged entry does NOT verify clean)", v.intact === false);
    ok("cell(d1) insertion (slot overwrite): the break is at the entry after the forgery", v.brokenAt === next.seq);
    const after = snapshot(fresh).entries;
    const product = await verifyChain(after);
    ok("cell(d1) insertion (slot overwrite): the product causeClass is prev-hash-mismatch at the next entry", product.causeClass === "prev-hash-mismatch" && product.brokenAt === next.seq);
    const indep = walkChainIndependently(after);
    ok("cell(d1) insertion (slot overwrite): the harness oracle reports prev-hash-mismatch at the next entry", indep.intact === false && indep.causeClass === "prev-hash-mismatch" && indep.brokenAt === next.seq);
    ok("cell(d1) insertion (slot overwrite): the forged entry is itself internally consistent (the break is the broken forward link, not the forgery's own hash)", independentAuditDigest(forged) === forged.hash);

    fresh.storage.rawPut(keys[i]!, orig); // restore
    ok("cell(d1) insertion (slot overwrite): restoring the slot re-verifies the chain", (await verifyRoute(fresh)).intact === true);
  }
  {
    // (d2) forged entry appended with a fresh non-contiguous seq.
    const { entries } = snapshot(fresh);
    const head = clone(entries[entries.length - 1]!);
    const anchorBefore = fresh.storage.rawGet<AuditHead>(AUDIT_HEAD_KEY)!;
    const gapSeq = head.seq + 2; // skips head.seq + 1: a fresh seq that does not belong
    const forged: AuditEvent = { ...head, seq: gapSeq, prevHash: head.hash, target: { kind: "engine-state", field: "engineVersion", detail: "0.0.forged" } };
    forged.hash = await auditHash(forged); // links to the head and recomputes: only the seq is out of place
    fresh.storage.rawPut(auditKey(gapSeq), forged);

    const v = await verifyRoute(fresh);
    ok("cell(d2) insertion (fresh non-contiguous seq): the keystone refuter holds (the spliced entry does NOT verify clean)", v.intact === false);
    ok("cell(d2) insertion (fresh non-contiguous seq): the break is at the forged seq", v.brokenAt === gapSeq);
    // The anchor is NOT implicated (the retained head rose ABOVE it), so this is a seq-contiguity catch, not a
    // tail truncation: headTruncated must stay absent.
    ok("cell(d2) insertion (fresh non-contiguous seq): this is a seq-gap, NOT a truncation (headTruncated absent)", v.headTruncated === undefined && anchorBefore.headSeq === head.seq);
    const after = snapshot(fresh).entries;
    const product = await verifyChain(after);
    ok("cell(d2) insertion (fresh non-contiguous seq): the product causeClass is seq-gap", product.causeClass === "seq-gap" && product.brokenAt === gapSeq);
    const indep = walkChainIndependently(after);
    ok("cell(d2) insertion (fresh non-contiguous seq): the harness oracle reports seq-gap at the forged seq", indep.intact === false && indep.causeClass === "seq-gap" && indep.brokenAt === gapSeq);

    fresh.storage.rawDelete(auditKey(gapSeq)); // restore
    ok("cell(d2) insertion (fresh non-contiguous seq): removing the forgery re-verifies the chain", (await verifyRoute(fresh)).intact === true);
  }

  // ============================================================================================
  // Cell (e): REORDER. Two swapped entries are detected. NET-NEW cell. A real reorder must move the entries in
  // SEQ SPACE, because the read path (listAuditEntries) sorts by the seq FIELD as a defence, so a body-only swap
  // across two keys is silently undone by that re-sort and never reaches the chain the verify walks. This cell
  // therefore swaps the two adjacent entries' SEQ FIELDS without recomputing (their content and stale hashes/links
  // ride to the swapped positions), so a reordered entry's prevHash no longer links to whatever now precedes it
  // (prev-hash-mismatch at the first out-of-order position). Same two invariants as (c) and (d), the reorder shape.
  // The seq-field-sort defence is itself a finding worth recording: a naive body-only reorder is inert here.
  // Refuter (keystone, default-FAIL): a reorder that verifies clean fails the cell.
  // ============================================================================================
  {
    const { keys, entries } = snapshot(fresh);
    const i = 2; // reorder entries[i] (seq s) and entries[i+1] (seq s+1)
    const a = clone(entries[i]!);
    const b = clone(entries[i + 1]!);
    // Move B's content to position s and A's content to position s+1 by swapping the seq fields (no recompute), so
    // the reorder survives the seq-field re-sort the read path applies.
    const bAtS: AuditEvent = { ...b, seq: a.seq };
    const aAtS1: AuditEvent = { ...a, seq: b.seq };
    fresh.storage.rawPut(keys[i]!, bAtS);
    fresh.storage.rawPut(keys[i + 1]!, aAtS1);

    const v = await verifyRoute(fresh);
    ok("cell(e) reorder: the keystone refuter holds (the swap does NOT verify clean)", v.intact === false);
    ok("cell(e) reorder: the break is at the first out-of-order position", v.brokenAt === a.seq);
    const after = snapshot(fresh).entries;
    const product = await verifyChain(after);
    ok("cell(e) reorder: the product causeClass is prev-hash-mismatch at the first out-of-order seq", product.causeClass === "prev-hash-mismatch" && product.brokenAt === a.seq);
    const indep = walkChainIndependently(after);
    ok("cell(e) reorder: the harness oracle reports prev-hash-mismatch at the first out-of-order seq", indep.intact === false && indep.causeClass === "prev-hash-mismatch" && indep.brokenAt === a.seq);

    fresh.storage.rawPut(keys[i]!, a); // restore
    fresh.storage.rawPut(keys[i + 1]!, b);
    ok("cell(e) reorder: restoring the order re-verifies the chain", (await verifyRoute(fresh)).intact === true);
  }

  // ============================================================================================
  // Cell (f): TAIL-TRUNCATION (the fidelity keystone, the net-new cell the shipped suite never drives). Deleting
  // the NEWEST entries is detected by the head-anchor witness while the recompute alone reads intact. The
  // two-part assertion is the whole point: verifyChain's own intact is TRUE over the survivors (they stay
  // perfectly linked), AND the wrapped verifyAudit returns headTruncated:true at the anchored head seq. The
  // harness confirms independently that the retained head sits below the anchor it recorded BEFORE the deletion,
  // and that its own oracle is ALSO blind to the tail (proving the recompute genuinely cannot see it).
  // Refuter (truncation-missed, default-FAIL): a truncated tail the head-anchor misses fails the cell.
  // ============================================================================================
  {
    const anchorBefore = fresh.storage.rawGet<AuditHead>(AUDIT_HEAD_KEY)!;
    const before = snapshot(fresh);
    const retainedHeadBefore = before.entries[before.entries.length - 1]!;
    ok("cell(f) tail-truncation: pre-tamper the anchor matches the retained head (sanity)", anchorBefore.headSeq === retainedHeadBefore.seq && anchorBefore.headHash === retainedHeadBefore.hash);

    const K = 2; // delete the newest two entries WITHOUT touching AUDIT_HEAD_KEY
    const removed: Array<{ key: string; entry: AuditEvent }> = [];
    for (let n = 0; n < K; n++) {
      const key = before.keys[before.keys.length - 1 - n]!;
      removed.push({ key, entry: clone(before.entries[before.entries.length - 1 - n]!) });
      fresh.storage.rawDelete(key);
    }

    const v = await verifyRoute(fresh);
    // Part 1 (the fidelity correction): the recompute over the SURVIVORS reads intact. Asserting the recompute
    // was BROKEN here would be a falsehood about what verifyChain can see (the survivors are perfectly linked).
    ok("cell(f) tail-truncation: the recompute alone reads INTACT over the survivors (the honest bound of verifyChain)", v.intact === true);
    // Part 2 (the anchor witness): headTruncated fires at the anchored head seq, which is the WHOLE point of the
    // separate witness. The truncation-missed refuter is exactly this assertion coming out false.
    ok("cell(f) tail-truncation: the head-anchor witness catches the truncation (headTruncated true)", v.headTruncated === true);
    ok("cell(f) tail-truncation: headTruncatedAt is the anchored head seq (the deleted tail's head)", v.headTruncatedAt === anchorBefore.headSeq);
    // The harness owns the ground truth: the retained head now sits below the anchor it recorded before the delete.
    const survivors = snapshot(fresh).entries;
    const retainedHeadAfter = survivors[survivors.length - 1]!;
    ok("cell(f) tail-truncation: the retained head sits BELOW the anchor recorded before the deletion (harness before/after)", retainedHeadAfter.seq < anchorBefore.headSeq && retainedHeadAfter.seq === anchorBefore.headSeq - K);
    // The harness's OWN oracle is also blind to the tail, confirming this is genuinely the class the recompute
    // cannot see (not an artefact of the product's verify): the survivors walk intact.
    const indep = walkChainIndependently(survivors);
    ok("cell(f) tail-truncation: the harness oracle is ALSO blind to the removed tail (survivors walk intact), so the anchor is the only witness", indep.intact === true);

    for (const r of removed) fresh.storage.rawPut(r.key, r.entry); // restore the tail
    const vr = await verifyRoute(fresh);
    ok("cell(f) tail-truncation: restoring the tail clears the truncation (intact, headTruncated absent)", vr.intact === true && vr.headTruncated === undefined);
  }

  // ============================================================================================
  // Cell (a) sibling: RETENTION ROLLOVER is NOT a tamper, and is distinguished from a truncation. On a SEPARATE
  // fresh DO so the destructive prune is isolated. A rollover drops the OLDEST entries (the head is unchanged, so
  // the anchor stays quiet), which is the opposite of the tail truncation in cell (f) where the anchor fired.
  // Refuter (clean-flagged-tampered, default-FAIL): a legitimate rollover that returns a break or a spurious
  // truncation fails the cell.
  // ============================================================================================
  {
    const roll = makeScheduler();
    await handleAdmin(new Request("https://engine.example/admin/whoami", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor(OWNER) } }), ({ ...roll.env, CF_ACCESS_TEAM_DOMAIN: TEAM, CF_ACCESS_AUD: AUD }) as unknown as Env);
    for (const d of drafts) await appendDraft(roll, d);

    // Reproduce a rollover's STORAGE EFFECT (as validate-audit-rollover.ts PROOF 13 does): delete the oldest few
    // keys and write the auditRollover record, then drive the REAL GET /admin/audit/verify. The head-anchor is
    // left pointing at the true (unchanged) head, so a correct rollover must NOT read as a truncation.
    const before = roll.storage.rawKeys(AUDIT_PREFIX);
    const PRUNE = 3;
    const prunedSeqs = before.slice(0, PRUNE).map((k) => roll.storage.rawGet<AuditEvent>(k)!.seq);
    for (const k of before.slice(0, PRUNE)) roll.storage.rawDelete(k);
    const survivors = roll.storage.rawKeys(AUDIT_PREFIX);
    const newEarliest = roll.storage.rawGet<AuditEvent>(survivors[0]!)!.seq;
    roll.storage.rawPut(AUDIT_ROLLOVER_KEY, { earliestRetainedSeq: newEarliest, rolledOverCount: PRUNE });

    const v = await verifyRoute(roll);
    ok("cell(a) rollover sibling: a legitimate rollover verifies INTACT, not a break (clean-flagged-tampered refuter)", v.intact === true);
    ok("cell(a) rollover sibling: verify reports rolledOver true with the rolled-over count", v.rolledOver === true && v.rolledOverCount === PRUNE);
    ok("cell(a) rollover sibling: verify reports the new earliest RETAINED seq", v.earliestSeq === newEarliest && newEarliest > Math.min(...prunedSeqs));
    // The DISCRIMINATOR from cell (f): a rollover drops the OLDEST, so the head anchor stays quiet (headTruncated
    // absent), whereas the tail truncation fired it. This is how a rollover is told apart from a truncation.
    ok("cell(a) rollover sibling: a rollover is NOT a truncation (headTruncated absent, unlike cell (f))", v.headTruncated === undefined);
    // The independent oracle agrees: the retained set walks intact from a NON-GENESIS baseline, and the default
    // (genesis-expecting) walk correctly flags the missing genesis (the relaxation is gated, not a weakening).
    const retained = survivors.map((k) => roll.storage.rawGet<AuditEvent>(k)!);
    const indepRollover = walkChainIndependently(retained, { expectGenesis: false });
    ok("cell(a) rollover sibling: the harness oracle agrees the retained chain is intact from its baseline", indepRollover.intact === true && indepRollover.earliestSeq === newEarliest);
    const indepGenesis = walkChainIndependently(retained);
    ok("cell(a) rollover sibling: the harness oracle still flags a missing genesis when genesis IS expected (the relaxation is gated)", indepGenesis.intact === false && indepGenesis.causeClass === "genesis-link" && indepGenesis.brokenAt === newEarliest);

    // DERIVED rollover: even with the rollover RECORD removed, a chain that legitimately begins above seq 1 is a
    // rollover (derived from the earliest retained seq), NOT a tamper. This is the loseable-record fallback.
    roll.storage.rawDelete(AUDIT_ROLLOVER_KEY);
    const vd = await verifyRoute(roll);
    ok("cell(a) rollover sibling: with the rollover record removed, verify still reports intact + rolledOver (derived fallback, not a spurious tamper)", vd.intact === true && vd.rolledOver === true && vd.headTruncated === undefined);
  }

  // ============================================================================================
  // Cell (g): TELEMETRY (the right event for the right action and actor on the guaranteed path, with the honest
  // best-effort BOUND). The guaranteed committed-append path emits exactly one row; the best-effort window (a
  // non-2xx append response, router-audit.ts:59-62) DROPS the event but COUNTS the loss (noteDroppedWrite
  // "audit-write"), so telemetry is best-effort, never a guaranteed-every-action emit. Both refuters live here.
  // Refuter (missing-event, default-FAIL): a driven action with no recorded row on the guaranteed path fails.
  // Refuter (spurious-event, default-FAIL): a row for a non-action (here, a dropped append) fails.
  // ============================================================================================
  {
    resetPendingDroppedWrites();
    const caller: Caller = { method: "access", email: "owner@acme.example", subject: SUBJECT(99), role: "owner", groups: [], sourceIp: "203.0.113.50" };

    // GUARANTEED PATH: recordAudit (the real router appender) commits one row through the real DO.
    const beforeLen = snapshot(fresh).keys.length;
    const emitted = await recordAudit(fresh.stub as unknown as DurableObjectStub, caller, caller.sourceIp ?? null, "downpipe-create", "success", { kind: "downpipe", id: "dpG", name: "Guaranteed" });
    const afterGuaranteed = snapshot(fresh);
    const row = afterGuaranteed.entries[afterGuaranteed.entries.length - 1]!;
    ok("cell(g) telemetry: the guaranteed committed-append path records exactly one new row (missing-event refuter)", afterGuaranteed.keys.length === beforeLen + 1);
    ok("cell(g) telemetry: the row carries the right action, outcome, actor email + subject and target", row.action === "downpipe-create" && row.outcome === "success" && row.actorEmail === caller.email && row.actorSubject === caller.subject && row.target.kind === "downpipe" && (row.target as { id: string }).id === "dpG");
    ok("cell(g) telemetry: the emitted event echoed by the appender is the committed row", emitted.seq === row.seq && emitted.hash === row.hash);
    ok("cell(g) telemetry: a successful append counts NO dropped write", (pendingDroppedWrites()["audit-write"] ?? 0) === 0);

    // BEST-EFFORT BOUND: a DO configured to answer the /audit POST non-ok. The append is LOST but the loss is
    // COUNTED (noteDroppedWrite "audit-write"), and no row reaches the real chain. This is the honest bound, not
    // a false "every action always emits".
    const failStub = {
      fetch: async (): Promise<Response> => new Response(JSON.stringify({ error: "injected non-2xx" }), { status: 503, headers: { "content-type": "application/json" } }),
    } as unknown as DurableObjectStub;
    const lenBeforeDrop = snapshot(fresh).keys.length;
    await recordAudit(failStub, caller, caller.sourceIp ?? null, "keys-installed", "success", { kind: "key-ceremony" });
    ok("cell(g) telemetry: a non-2xx append COUNTS the loss (noteDroppedWrite audit-write), never silent", (pendingDroppedWrites()["audit-write"] ?? 0) >= 1);
    const afterDrop = snapshot(fresh);
    ok("cell(g) telemetry: the dropped append reached NO real chain (the event is absent)", afterDrop.keys.length === lenBeforeDrop);
    ok("cell(g) telemetry: no spurious keys-installed row appeared on the real chain (spurious-event refuter)", !afterDrop.entries.some((e) => e.action === "keys-installed"));
    resetPendingDroppedWrites();
  }
}
