// validate-repl-signer-defer: when the replication signer in SIGNER_PRIVATE will not load, the cron
// pass defers every fan-out downpipe for the tick instead of writing anything or crashing.
//
// runReplications loads the signer inside a try/catch and keeps the thrown message as signerFault. Each
// fan-out downpipe then takes the same noteSkipped path a per-downpipe fault uses, and the pass returns
// normally, having written nothing. A signer that will not load therefore defers the downpipes that need
// it, and never ends the whole pass for every downpipe on the estate.
//
// WHAT THIS PROVES, against the real runReplications over a stub scheduler that answers only GET
// /downpipes and GET /history (the two reads the pass makes before it ever touches a signer):
//   1. with an undersized SIGNER_PRIVATE, runReplications does not throw.
//   2. the one fan-out downpipe is counted as deferred (replicationPassTally().deferredDownpipes === 1).
//   3. the scheduler saw only the two reads and the pass's own fault post: no runlog-lock, no
//      destination write, nothing mirrored.
//   4. the skip is logged at error level and names the decode fault, the same line a per-downpipe fault
//      would use (so this path is not silent in Workers Logs).
//
// THE PLANT: change the catch block that keeps signerFault to rethrow, so a signer load failure escapes
// runReplications. Checks 1 and 2 then go red, because the pass throws instead of deferring.
//
// Run: node test/validate-repl-signer-defer.ts

import { b64urlEncode } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { replicationPassTally, resetReplicationPassTally, runReplications } from "../src/seal/replicate.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const DP = "dp-signer-defer";

// A downpipe state with two destinations and a completed run, the shape GET /downpipes returns for a
// fan-out downpipe. Only the fields runReplications reads are populated.
const DOWNPIPE_STATE = {
  config: { id: DP, destinationId: "dest-a", destinationIds: ["dest-a", "dest-b"] },
  lastRunId: "01K5ZZKBKACTAV9WEVGEMMVR01",
};

// A stub scheduler DO that answers the two reads the pass makes before it loads a signer, and records
// every path it was asked for. It holds no state and serves no write route: if the pass ever reached a
// write (runlog-lock, a destination copy), the path would show up here as something other than the two
// reads below, and the length-2 assertion would catch it.
function stubScheduler(): { fetch: (input: RequestInfo | URL) => Promise<Response>; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    fetch: async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url).pathname;
      calls.push(path);
      if (path === "/downpipes") return new Response(JSON.stringify([DOWNPIPE_STATE]), { status: 200 });
      if (path === "/history") return new Response(JSON.stringify({ byDownpipe: { [DP]: [] } }), { status: 200 });
      // The pass's own end-of-tick health post (postSealFault), since every downpipe was deferred. Not a
      // replication write: no runlog-lock, destination or RUNLOG route is reachable from this stub, so if
      // the pass tried to mirror anything it would hit the throw below instead.
      if (path === "/seal-fault") return new Response(JSON.stringify({ ok: true }), { status: 200 });
      throw new Error(`stub scheduler: unexpected call ${path}`);
    },
  };
}

// Captures console.error lines written during the call, the sink log("error", ...) writes to.
function captureErrors<T>(run: () => Promise<T>): Promise<{ result?: T; threw: boolean; lines: string[] }> {
  const lines: string[] = [];
  const real = console.error;
  console.error = (line: unknown) => {
    lines.push(String(line));
  };
  return run()
    .then((result) => ({ result, threw: false, lines }))
    .catch(() => ({ threw: true, lines }))
    .finally(() => {
      console.error = real;
    }) as Promise<{ result?: T; threw: boolean; lines: string[] }>;
}

async function main(): Promise<void> {
  // SIGNER_PRIVATE must decode to 64 bytes (ed25519 seed || ML-DSA-87 seed); 40 random bytes fail
  // loadSigner's length check deterministically, with no dependence on the random content.
  const badSigner = b64urlEncode(crypto.getRandomValues(new Uint8Array(40)));
  const env = { SIGNER_PRIVATE: badSigner } as unknown as Env;

  console.log("-- a signer that will not load defers the fan-out downpipe, writes nothing --");
  resetReplicationPassTally();
  const scheduler = stubScheduler();
  const { threw, lines } = await captureErrors(() => runReplications(env, scheduler as unknown as DurableObjectStub));

  ok("runReplications did not throw", !threw);
  ok(`the one fan-out downpipe was counted as deferred (got ${replicationPassTally().deferredDownpipes})`, !threw && replicationPassTally().deferredDownpipes === 1);
  ok(
    `the scheduler saw only the two reads and the pass's own fault post, no replication write (got ${JSON.stringify(scheduler.calls)})`,
    JSON.stringify(scheduler.calls) === JSON.stringify(["/downpipes", "/history", "/seal-fault"]),
  );
  ok(
    `the skip was logged at error level and names a decode fault (got ${JSON.stringify(lines)})`,
    lines.some((l) => l.includes(DP) && l.includes("skipped this tick") && l.includes("64 bytes")),
  );

  console.log(failures === 0 ? "\nVERDICT: PASS failures=0\n" : `\nVERDICT: FAIL failures=${failures}\n`);
  verdictReached(failures);
  process.exit(failures === 0 ? 0 : 1);
}

await main();
