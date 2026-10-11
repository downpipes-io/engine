// validate-runlog-sig-absent-promote: a RUNLOG whose .sig object has been deleted, but whose .sig.pending
// still verifies the stored body, is promoted: the pending signature is republished as the .sig.
//
// resolveRunlogSignature (src/seal/pipeline.ts) treats "no .sig at all" and "a .sig that does not verify"
// the same way. Both fall through to the pending check, and a verifying pending signature is published
// either way. A .sig that never arrived (a crash between the two writes) and a .sig that was deleted look
// the same once the pending signature verifies. The promotion keeps no separate record of which one it was.
//
// THIS FILE PROVES, against a real SchedulerDO, a real R2 destination double and a real signed RUNLOG:
//   1. with RUNLOG.sig deleted and RUNLOG.sig.pending verifying the stored body, resolveRunlogSignature
//      returns "promoted" and republishes .sig;
//   2. the same state, met through the admin route, answers POST /runlog/resign with outcome "resumed".
//
// Run: node test/validate-runlog-sig-absent-promote.ts

import { verdictReached } from "./lib/verdict-guard.ts";
import { sigAbsentEstate, RUNLOG_SIG, RUNLOG_PENDING, admin } from "./lib/runlog-sig-absent-shared.ts";
import { resolveRunlogSignature } from "../src/seal/pipeline.ts";

let failures = 0;
function ok(label: string, cond: boolean, detail?: unknown): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) {
    failures++;
    if (detail !== undefined) console.log(`         ${JSON.stringify(detail).slice(0, 400)}`);
  }
}

async function main(): Promise<void> {
  const e = await sigAbsentEstate();

  console.log("-- CONTROL: a freshly written RUNLOG verifies under its own .sig, with a matching .sig.pending --");
  ok("the fresh RUNLOG's .sig verifies", (await resolveRunlogSignature(e.dest, e.body, e.verifier)) === "verified");
  ok("the fresh RUNLOG's .sig.pending is present (the writer's own resume trail)", (await e.dest.get(RUNLOG_PENDING)) !== null);

  console.log("\n-- 1. RUNLOG.sig deleted, .sig.pending left verifying the body --");
  await e.dest.delete(RUNLOG_SIG);
  ok("CONTROL: .sig is actually absent", (await e.dest.get(RUNLOG_SIG)) === null);
  const state = await resolveRunlogSignature(e.dest, e.body, e.verifier);
  ok(`resolveRunlogSignature promotes the pending signature over the body (got "${state}")`, state === "promoted");
  ok("the .sig object is republished from the pending signature and itself verifies", (await e.dest.get(RUNLOG_SIG)) !== null && (await resolveRunlogSignature(e.dest, e.body, e.verifier)) === "verified");

  // Re-delete .sig so the admin route meets the same absent-.sig, pending-verifies state the pipeline call
  // above just proved, rather than the republished one.
  await e.dest.delete(RUNLOG_SIG);
  const resign = await admin(e.env, "POST", "/runlog/resign", e.cookie, { destinationId: "", digest: e.digest });
  ok(`POST /runlog/resign over the same state answers outcome "resumed" (got ${resign.status} ${JSON.stringify(resign.body)})`, resign.status === 200 && resign.body.outcome === "resumed");

  console.log(failures === 0 ? "\nVERDICT: PASS failures=0\n" : `\nVERDICT: FAIL failures=${failures}\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
