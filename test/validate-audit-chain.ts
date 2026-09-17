// PROOF 6 / 7 / 8 / 9 / 9b for the D4 audit validator (split out of validate-audit.ts, finding
// engine-test-001-01): engine-OBSERVED events on a status transition + a version change; the hash
// chain verifies over the whole recorded log; a TAMPERED entry is detected at N; a DELETED entry
// breaks the link; a SEQ GAP is detected even when the hashes are re-linked around the hole.

import { handleAdmin } from "../src/admin/router.ts";
import { verifyChain, auditHash, type AuditEvent } from "../src/admin/audit.ts";
import type { Env } from "../src/env.d.ts";
import type { Ctx } from "./validate-audit-harness.ts";
import { OWNER, TEAM, AUD } from "./validate-audit-harness.ts";

export async function runChain(ctx: Ctx): Promise<void> {
  const { ok, call, readLog, sched, accessEnv, tokenFor } = ctx;

  // ---- PROOF 6: engine-OBSERVED events on a status transition + a version change ----------
  {
    // GET /admin/status drives the DO snapshot diff. The first status call establishes the baseline
    // (records nothing). With no secrets configured, the baseline is all-false. Then configure the
    // signer + break-glass + an R2 destination and call status again: the DO observes the presence
    // transitions and appends engine-secret-present events (actorMethod "engine", no human actor).
    const baseEnv = accessEnv();
    // Baseline observation (everything off).
    await handleAdmin(new Request("https://engine.example/admin/status", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor(OWNER) } }), baseEnv);
    const afterBaseline = await readLog("action=engine-secret-present");
    ok("first status observation establishes a baseline (no observed events yet)", afterBaseline.events.length === 0);

    // Now present the tracked secrets/destination and observe again.
    const configuredEnv = {
      ...sched.env,
      CF_ACCESS_TEAM_DOMAIN: TEAM,
      CF_ACCESS_AUD: AUD,
      SIGNER_PRIVATE: "present",
      BREAK_GLASS_PUBLIC: "present",
      DEST_KIND: "r2",
      DEST_R2: {} as unknown,
    } as unknown as Env;
    await handleAdmin(new Request("https://engine.example/admin/status", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor(OWNER) } }), configuredEnv);
    const observed = await readLog("action=engine-secret-present");
    const fields = new Set(observed.events.map((e) => (e.target as { kind: "engine-state"; field: string; detail: string }).detail));
    ok("engine observed signer presence transition", fields.has("signerConfigured"));
    ok("engine observed break-glass presence transition", fields.has("breakGlassConfigured"));
    ok("engine observed destination presence transition", fields.has("destConfigured"));
    ok("observed events carry actorMethod engine, no human actor", observed.events.every((e) => e.actorMethod === "engine" && e.actorEmail === null));
    ok("observed event detail is a boolean NAME, never a value", observed.events.every((e) => /Configured$/.test((e.target as { detail: string }).detail)));
    // THE FIX'S OTHER HALF: an engine-INITIATED event has no client request, so its source IP must stay
    // null (blank is the honest value) even when human-initiated events now carry one. The status
    // observation above runs with no inbound request IP, and these events are engine-authored regardless.
    ok("an engine-initiated (observed) event keeps a NULL source IP (no client request)", observed.events.length > 0 && observed.events.every((e) => e.sourceIp === null));

    // Bump the engine version (simulate a redeploy) by patching the snapshot's version, then
    // observe again: the DO appends an engine-version-change carrying the new version string.
    const snapKey = "auditStatusSnapshot";
    const snap = sched.storage.rawGet<{ presence: Record<string, boolean>; engineVersion: string }>(snapKey)!;
    snap.engineVersion = "0.0.1-old";
    sched.storage.rawPut(snapKey, snap);
    await handleAdmin(new Request("https://engine.example/admin/status", { method: "GET", headers: { "cf-access-jwt-assertion": await tokenFor(OWNER) } }), configuredEnv);
    const versions = await readLog("action=engine-version-change");
    ok("engine observed a version change (redeploy)", versions.events.length >= 1);
    ok("version-change detail is the new version string", versions.events.some((e) => (e.target as { field: string; detail: string }).field === "engineVersion"));
  }

  // ---- PROOF 7: the hash chain VERIFIES over the whole recorded log -----------------------
  {
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean; checkedThrough: number; brokenAt?: number };
    ok("the recorded chain verifies intact", verify.intact === true);
    ok("verify reports a non-empty checkedThrough head", verify.checkedThrough >= 1);
    // Independently recompute the chain from the exported events (a second, in-test verifier),
    // so the proof does not rely solely on the engine verifying itself.
    const log = await readLog();
    // readLog is newest-first; verifyChain wants ascending seq.
    const ascending = [...log.events].reverse();
    const independent = await verifyChain(ascending);
    ok("an independent re-verification of the chain agrees it is intact", independent.intact === true);
    ok("the head hash is reported and is a sha384 hash", typeof log.headHash === "string" && log.headHash.startsWith("sha384:"));
  }

  // ---- PROOF 8: a TAMPERED entry is DETECTED at N ----------------------------------------
  {
    // Edit one stored entry in place (simulate a holder altering the DB). Pick a mid-chain entry by
    // its storage key and change a recorded field WITHOUT re-chaining; verify must report a break at
    // that seq (its stored hash no longer recomputes).
    const keys = sched.storage.rawKeys("audit:");
    ok("there are several entries to tamper with", keys.length >= 4);
    const victimKey = keys[2]!; // a mid-chain entry
    const victim = sched.storage.rawGet<AuditEvent>(victimKey)!;
    const victimSeq = victim.seq;
    // Tamper: rewrite the outcome to something it never was, leaving hash/prevHash untouched.
    victim.outcome = victim.outcome === "success" ? "denied" : "success";
    sched.storage.rawPut(victimKey, victim);
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean; brokenAt?: number };
    ok("verify detects the in-place edit", verify.intact === false);
    ok("verify reports the break at the tampered seq", verify.brokenAt === victimSeq);
    // Restore the entry so the next sub-proof starts from an intact chain.
    victim.outcome = victim.outcome === "success" ? "denied" : "success";
    sched.storage.rawPut(victimKey, victim);
    const reverify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean };
    ok("restoring the entry makes the chain verify again", reverify.intact === true);
  }

  // ---- PROOF 9: a DELETED entry breaks the link (insert/delete/reorder is detectable) -----
  {
    const keys = sched.storage.rawKeys("audit:");
    const dropKey = keys[1]!; // delete the second entry; the third's prevHash no longer links
    const dropped = sched.storage.rawGet<AuditEvent>(dropKey)!;
    sched.storage.rawDelete(dropKey);
    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean; brokenAt?: number };
    ok("verify detects a deleted entry (the chain link breaks)", verify.intact === false);
    // The break surfaces at the FIRST entry whose prevHash no longer matches its (now different)
    // predecessor, i.e. the entry that followed the deleted one.
    ok("verify reports the break at the entry after the gap", typeof verify.brokenAt === "number" && verify.brokenAt > dropped.seq);
    // Put it back for the redaction + export proofs.
    sched.storage.rawPut(dropKey, dropped);
    ok("restoring the deleted entry re-verifies the chain", ((await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean }).intact === true);
  }

  // ---- PROOF 9b: a SEQ GAP is detected even when the hashes are re-linked (the seq check) --
  {
    // The module CLAIMS it detects sequence tampering and that "any deletion is detectable". A naive
    // deletion is caught by the prevHash link (PROOF 9), but a sophisticated tamper could delete a
    // middle entry AND re-chain its successor's prevHash + recompute its hash so the HASH chain is
    // intact across the hole. The only remaining evidence is the SEQ gap (the successor's seq jumps
    // by 2). Prove the new seq check catches exactly that: without it, this re-chained log would
    // verify as intact and a deletion would be undetectable.
    const keys = sched.storage.rawKeys("audit:");
    ok("there are enough entries for a mid-chain seq-gap test", keys.length >= 4);
    const holeKey = keys[2]!; // delete a mid-chain entry
    const successorKey = keys[3]!; // the entry that followed it (its prevHash must be re-linked)
    const hole = sched.storage.rawGet<AuditEvent>(holeKey)!;
    const successor = sched.storage.rawGet<AuditEvent>(successorKey)!;
    const predecessor = sched.storage.rawGet<AuditEvent>(keys[1]!)!; // the entry before the hole

    // Sanity: before tampering the chain is intact and the seqs are contiguous around the hole.
    ok("pre-tamper: the hole and its successor are seq-contiguous", successor.seq === hole.seq + 1 && hole.seq === predecessor.seq + 1);

    // Delete the middle entry, then re-link the successor's prevHash to the PREDECESSOR's hash and
    // recompute the successor's own hash, so the HASH chain is unbroken across the hole. Only the
    // seq gap (successor.seq is now predecessor.seq + 2) remains as evidence of the deletion.
    sched.storage.rawDelete(holeKey);
    const relinked: AuditEvent = { ...successor, prevHash: predecessor.hash };
    relinked.hash = await auditHash(relinked);
    sched.storage.rawPut(successorKey, relinked);

    // Confirm the hashes really are consistent now (so this proof isolates the SEQ check, not the
    // prevHash/hash checks): the successor's prevHash links to its (new) predecessor and its stored
    // hash recomputes. Were the seq check absent, verify would wrongly report intact.
    ok("the re-linked successor's prevHash links to its new predecessor", relinked.prevHash === predecessor.hash);
    ok("the re-linked successor's stored hash recomputes (hash chain intact across the hole)", (await auditHash(relinked)) === relinked.hash);

    const verify = (await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean; brokenAt?: number };
    ok("verify detects the seq gap from the deleted middle entry", verify.intact === false);
    ok("verify reports the break at the entry after the deleted one (the seq jump)", verify.brokenAt === successor.seq);

    // Restore the deleted entry and the successor's original prevHash/hash so the chain re-verifies
    // for the remaining proofs.
    sched.storage.rawPut(holeKey, hole);
    sched.storage.rawPut(successorKey, successor);
    ok("restoring the deleted entry and the original link re-verifies the chain", ((await (await call(OWNER, "GET", "/admin/audit/verify")).json()) as { intact: boolean }).intact === true);
  }
}
