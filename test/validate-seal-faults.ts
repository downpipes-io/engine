// Prove the PURE seal-fault OBSERVE core (src/seal/seal-faults.ts): the closed-kind vocabulary, the
// sanitiser that validates + clamps + redacts one posted observation, and the WORM-refusal classifier the
// orphan-root-reclaim outcome keys on. No network, no deploy, no DO. Run: node test/validate-seal-faults.ts
//
// These are DIAGNOSTIC observations (support-pack seal-integrity modes shard-list-truncated /
// shard-truncation-stalekeys / lease-lost-abandon / orphan-root-worm-leak / signer-rotation-strands-runs);
// the sanitiser is the redaction chokepoint, so this pins its NO-CUSTODY behaviour: only a closed kind, the
// customer's own ids, and non-negative ints / a strict boolean ever survive, and an out-of-vocabulary kind
// is dropped entirely.

import { SEAL_FAULT_KINDS, sanitiseSealFault, isWormRefusal, type SealFault } from "../src/seal/seal-faults.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const NOW = 1_700_000_000_000;

function main(): void {
  console.log("PART A: the closed kind vocabulary");
  {
    // The detection-point kinds are exactly the modes this deliverable covers; the set is closed. Three
    // retention kinds joined the original five seal-lifecycle kinds; two fan-out kinds (WHICH range wedged,
    // WHY a worker report was discarded) and the ring's own observe-dropped self-report joined them.
    // Two run-diagnosis kinds (config-fault: WHICH binding / secret / token / env var a run died
    // for; run-pressure: the retry / park / strike cost a run paid, on success as well as failure)
    // joined them; both are exercised in depth by test/validate-seal-config-pressure.ts.
    // Eight SEAL + DEST kinds joined them: replica-target-fault
    // (the REAL replica reason, not the two-word {not configured, unreachable} vocabulary),
    // replication-pass (the pass's own execution health), record-skipped-changed (an infra fault
    // masked as content churn), dest-stranding (the bytes the engine strands and never counts),
    // verify-suspect (the ordinal / digest / clean-count a suspect verdict could not carry), seal-mode
    // (the silent fan-out-to-serial downgrade), alert-routing-failed (a critical alert lost with no
    // evidence it was ever attempted) and lock-plane (a scheduler-plane blip misattributed to the
    // destination). They are exercised in depth by test/validate-seal-dest-gap-evidence.ts.
    // Twelve more kinds were added later (exercised in depth by
    // test/validate-seal-refuse-evidence.ts): the checkpoint-corruption trio (checkpoint-invalid,
    // checkpoint-coerced, resume-abandoned), the refuse-to-sign completeness guards (scratch-shard-missing,
    // scratch-hash-mismatch, scratch-preamble-mismatch, merge-count-mismatch, under-crawl,
    // open-shard-count-mismatch, open-batch-missing), the lost terminal verdict (completion-lost) and the
    // silently-normalised absent RUNLOG (runlog-absent). The COUNT is pinned deliberately: a kind added without
    // a recording site and a read path is exactly the "looks closed" failure this closed vocabulary guards against.
    ok("the vocabulary is the thirty-three expected kinds", SEAL_FAULT_KINDS.length === 33);
    for (const k of ["shard-list-truncated", "stale-shard-rows-cleaned", "lease-lost-abandon", "orphan-root-reclaim", "checkpoint-unwrap-failed", "prune-deferred", "prune-runs-skipped", "prune-partial-apply", "fanout-range-stalled", "fanout-report-discarded", "observe-dropped", "config-fault", "run-pressure", "checkpoint-invalid", "checkpoint-coerced", "resume-abandoned", "scratch-shard-missing", "scratch-hash-mismatch", "scratch-preamble-mismatch", "merge-count-mismatch", "under-crawl", "open-shard-count-mismatch", "open-batch-missing", "completion-lost", "runlog-absent"]) {
      ok(`kind ${k} is in the vocabulary`, (SEAL_FAULT_KINDS as readonly string[]).includes(k));
    }
  }

  console.log("\nPART B: sanitiseSealFault -- kind gating (fail-closed on an unknown kind)");
  {
    ok("an out-of-vocabulary kind is DROPPED (returns null)", sanitiseSealFault({ kind: "hostile-not-a-kind", at: NOW }, NOW) === null);
    ok("a non-string kind is DROPPED (returns null)", sanitiseSealFault({ kind: 42 as unknown }, NOW) === null);
    ok("an absent kind is DROPPED (returns null)", sanitiseSealFault({}, NOW) === null);
    const f = sanitiseSealFault({ kind: "lease-lost-abandon", at: NOW }, NOW);
    ok("a member kind is accepted", f !== null && f.kind === "lease-lost-abandon");
  }

  console.log("\nPART C: sanitiseSealFault -- shard-list-truncated counts + ids round-trip");
  {
    const f = sanitiseSealFault({ kind: "shard-list-truncated", at: NOW, downpipeId: "dp1", runId: "01RUN", found: 968, expected: 970 }, NOW) as SealFault;
    ok("kind/at/ids/counts round-trip", f.kind === "shard-list-truncated" && f.at === NOW && f.downpipeId === "dp1" && f.runId === "01RUN" && f.found === 968 && f.expected === 970);
    // Only the fields RELEVANT to a kind are set; an unposted field is OMITTED (never emitted as undefined,
    // which canonicalJSON would reject on the pack path).
    ok("unposted fields are omitted, not undefined", !("cleaned" in f) && !("reclaimed" in f) && !("wormBlocked" in f));
  }

  console.log("\nPART D: sanitiseSealFault -- defensive clamps (fail-closed on malformed values)");
  {
    // A negative / NaN / fractional / over-max count is clamped to a bounded non-negative integer.
    const f = sanitiseSealFault({ kind: "stale-shard-rows-cleaned", cleaned: -5, found: Number.NaN, expected: 2.9, reclaimed: 5_000_000_000 }, NOW) as SealFault;
    ok("a negative count clamps to 0", f.cleaned === 0);
    ok("a NaN count clamps to 0", f.found === 0);
    ok("a fractional count floors", f.expected === 2);
    ok("an over-max count caps at 1e9", f.reclaimed === 1_000_000_000);
    ok("at defaults to the injected now when absent/malformed", f.at === NOW);
  }

  console.log("\nPART E: sanitiseSealFault -- id clamps + strict-boolean WORM flag");
  {
    // A non-string / empty id is OMITTED; an over-length id is sliced to the 128 bound.
    const f = sanitiseSealFault({ kind: "orphan-root-reclaim", downpipeId: "", runId: "r".repeat(300), reclaimed: 3, wormBlocked: true }, NOW) as SealFault;
    ok("an empty-string id is omitted", !("downpipeId" in f));
    ok("an over-length id is sliced to 128", f.runId !== undefined && f.runId.length === 128);
    ok("reclaimed round-trips", f.reclaimed === 3);
    ok("wormBlocked:true survives", f.wormBlocked === true);
    // A non-boolean wormBlocked coerces to false (strict === true), and an ABSENT wormBlocked is omitted.
    const g = sanitiseSealFault({ kind: "orphan-root-reclaim", wormBlocked: "yes" as unknown }, NOW) as SealFault;
    ok("a non-boolean wormBlocked coerces to false", g.wormBlocked === false);
    const h = sanitiseSealFault({ kind: "orphan-root-reclaim" }, NOW) as SealFault;
    ok("an absent wormBlocked is omitted", !("wormBlocked" in h));
  }

  console.log("\nPART F: isWormRefusal -- the orphan-root-reclaim WORM classifier");
  {
    // A delete REFUSED by object-lock / WORM / immutability policy (the irreducible-orphan case).
    ok("object-lock refusal matches", isWormRefusal("DELETE run/01/root: status 403 (AccessDenied: object lock)"));
    ok("a bare WORM message matches", isWormRefusal("cannot delete WORM object under compliance retention"));
    ok("a governance-mode retention matches", isWormRefusal("Governance retention prevents deletion"));
    ok("a 409 lock conflict matches", isWormRefusal("DELETE key: status 409 (ObjectLockConflict)"));
    // A bare "Forbidden" with no lock vocabulary is a ROTATED or UNDER-SCOPED credential, which the operator
    // can fix in a minute. Classifying it as a WORM refusal would tell support "locked by design, nothing to
    // fix", and that verdict rides into the support pack through `wormBlocked` (seal/runseal-do.ts).
    //
    // The line above it proves the precedence is still right: a refusal carrying BOTH lock
    // vocabulary and AccessDenied is still worm-locked, because S3 answers a locked object with a 403.
    ok("a bare Forbidden does NOT match, it is a fixable credential", isWormRefusal("Forbidden") === false);
    ok("a bare AccessDenied does NOT match either", isWormRefusal("AccessDenied") === false);
    ok("AccessDenied WITH lock vocabulary still matches, so precedence survives", isWormRefusal("AccessDenied: object-lock retention prevents delete"));
    // A transient / non-WORM failure does NOT match (it only lowers `reclaimed`, never sets wormBlocked).
    ok("a 500 outage does NOT match", isWormRefusal("DELETE key: status 500 (InternalError)") === false);
    ok("a network fault does NOT match", isWormRefusal("fetch failed: ECONNRESET") === false);
    ok("a 404 does NOT match", isWormRefusal("DELETE key: status 404") === false);
  }

  console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main();
