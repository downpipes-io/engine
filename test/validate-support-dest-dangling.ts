// Prove the pack's dangling-destination-reference detection.
//
// A downpipe can PIN a destination (config.destinationId, or the fan-out config.destinationIds list that
// supersedes it). If that pin names a destination since removed from the roster, every run fails loudly --
// but the pack never counted or attributed it. danglingDestinationRef cross-checks a config against the
// roster id set; fetchDestinationIdSet reads the roster and returns null on a fault so the caller skips the
// check (no false positives against an unreadable roster). This tests the pure helper across the pin shapes
// (absent = default = never dangling, single pin, fan-out list) and the read-fault-returns-null contract.
//
// Run:  node test/validate-support-dest-dangling.ts

import { danglingDestinationRef, fetchDestinationIdSet } from "../src/admin/support-sections-config.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

async function main(): Promise<void> {
  console.log("validate-support-dest-dangling\n");

  const roster = new Set(["dest-a", "dest-b"]);

  ok("an ABSENT pin (default destination) is never dangling", danglingDestinationRef({}, roster) === false);
  ok("a single pin present in the roster is not dangling", danglingDestinationRef({ destinationId: "dest-a" }, roster) === false);
  ok("a single pin absent from the roster IS dangling", danglingDestinationRef({ destinationId: "dest-gone" }, roster) === true);
  ok("a fan-out list all present is not dangling", danglingDestinationRef({ destinationIds: ["dest-a", "dest-b"] }, roster) === false);
  ok("a fan-out list with any absent id IS dangling", danglingDestinationRef({ destinationIds: ["dest-a", "dest-gone"] }, roster) === true);
  // Regression guard for the dangling-else fix: a fan-out list of all-present ids must NOT fall through to
  // the destinationId branch (a stale destinationId alongside a good destinationIds list must be ignored,
  // because destinationIds supersedes destinationId).
  ok("destinationIds supersedes a stale destinationId (fan-out all-present wins, no false dangle)", danglingDestinationRef({ destinationId: "dest-gone", destinationIds: ["dest-a"] }, roster) === false);

  // fetchDestinationIdSet returns the id set from GET /destinations.
  const okScheduler = { async fetch() { return new Response(JSON.stringify({ destinations: [{ id: "dest-a" }, { id: "dest-b" }, { notAnId: true }] })); } } as unknown as DurableObjectStub;
  const set = await fetchDestinationIdSet(okScheduler);
  ok("fetchDestinationIdSet returns the roster id set (non-string ids dropped)", set !== null && set.has("dest-a") && set.has("dest-b") && set.size === 2);

  // A read fault returns null so the caller SKIPS the dangling check (no false positives).
  const faultScheduler = { async fetch() { throw new Error("roster unavailable"); } } as unknown as DurableObjectStub;
  ok("fetchDestinationIdSet returns null on a read fault (caller skips the check)", (await fetchDestinationIdSet(faultScheduler)) === null);

  console.log(failures === 0 ? "\nALL SUPPORT-DEST-DANGLING VALIDATIONS PASS" : `\n${failures} FAILURE(S)`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
