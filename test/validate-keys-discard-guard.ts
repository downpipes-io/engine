// The break-glass-only DISCARD GUARD (custody-critical), driven through the REAL
// handleAdmin dispatch.
//
//   node test/validate-keys-discard-guard.ts
//
// Why this file exists. `POST /admin/keys/break-glass-only` deletes the operational key. Any archive
// wrapped to operational whose break-glass vintage is NO LONGER the current one is then openable by
// nothing that remains installed, so discarding the key is silent, permanent, old-vintage data loss.
// router-keys.ts refuses with 409 unless the body carries `confirmDiscardStranded: true`. Before this
// file, NO test under engine/test mentioned `confirmDiscardStranded`, `discardGuard`,
// `operationalSoleAccessRunCount` or even `computeKeyVintages`: every refusal branch of the most
// destructive owner action in the product was untested, and the guard's own comment claimed "the
// console shows the count first", which was false (the console had no consumer at all).
//
// The guard is fail-CLOSED by design, and that is the property worth pinning hardest. It refuses when
// removing operational is KNOWN to strand a run, AND ALSO when it could not rule that out: an
// unreadable manifest, a truncated scan, a /history fault, or no inventory at all. A guard that
// treated "I could not check" as "nothing to lose" would be worse than no guard, because it would
// look like one. Each case below asserts the refusal AND the specific field that explains it, so a
// regression that keeps the 409 while losing the reason still fails here.
//
// The scheduler is the real SchedulerDO for everything except `/history`, which this file drives. That
// is the one read the guard's uncertainty branches turn on, so overriding just it keeps every other
// part of the route genuine (RBAC, the rate limiter, the audit write).

import { handleAdmin } from "../src/admin/router.ts";
import type { Env } from "../src/env.d.ts";
import { makeScheduler, TEAM, AUD } from "./validate-rbac-harness.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`);
  if (!cond) failures++;
}

const BARE = "bare-admin-token-for-the-discard-guard-test";

// VINTAGE_RUN_SCAN_MAX in src/admin/key-vintages.ts. Kept as a local so a change there that lowers the
// cap does not silently stop this file from exercising the truncation branch: the assertion below is
// written against "one more than the cap", so if the two drift, the truncated case fails loudly rather
// than passing for the wrong reason.
const SCAN_MAX = 400;

type HistoryMode =
  | { kind: "ok"; okRuns: number }
  | { kind: "status"; status: number }
  | { kind: "throw" };

// Build an env whose scheduler is real except for /history. Returns the audit-visible storage too, so a
// refusal's audit row can be asserted rather than assumed.
function stackWithHistory(mode: HistoryMode): { env: Env; storage: ReturnType<typeof makeScheduler>["storage"] } {
  const base = makeScheduler();
  const stub = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.includes("/history")) {
        if (mode.kind === "throw") throw new Error("simulated /history unavailable");
        if (mode.kind === "status") return Promise.resolve(new Response("upstream failed", { status: mode.status }));
        const ring = Array.from({ length: mode.okRuns }, (_, i) => ({ status: "ok", runId: `run-${i}` }));
        return Promise.resolve(
          new Response(JSON.stringify({ byDownpipe: { "dp-1": ring } }), { status: 200, headers: { "content-type": "application/json" } }),
        );
      }
      return base.stub.fetch(input, init);
    },
  } as unknown as DurableObjectStub;
  const namespace = {
    idFromName: (_n: string) => ({}) as unknown as DurableObjectId,
    get: (_id: DurableObjectId) => stub,
  } as unknown as DurableObjectNamespace;
  const env = {
    SCHEDULER: namespace,
    CF_ACCESS_TEAM_DOMAIN: TEAM,
    CF_ACCESS_AUD: AUD,
    ADMIN_TOKEN: BARE,
    CF_ACCOUNT_ID: "acct-guard",
    WORKER_NAME: "engine-prod",
  } as unknown as Env;
  return { env, storage: base.storage };
}

interface GuardBody {
  error?: string;
  discardGuard?: boolean;
  strandedRunCount?: number;
  unknownRunCount?: number;
  truncated?: boolean;
  historyReadOk?: boolean;
}

async function post(env: Env, body: unknown): Promise<{ status: number; json: GuardBody }> {
  const resp = await handleAdmin(
    new Request("https://engine.example/admin/keys/break-glass-only", {
      method: "POST",
      headers: { authorization: `Bearer ${BARE}`, "content-type": "application/json", origin: "https://engine.example" },
      body: JSON.stringify(body),
    }),
    env,
  );
  const json = (await resp.json().catch(() => ({}))) as GuardBody;
  return { status: resp.status, json };
}

// A guard refusal is specifically a 409 carrying discardGuard:true. Every "did not refuse" assertion
// below is written against exactly that, never against "not 200": the route has other refusals after
// the guard (an unmarked account, a bad token), and treating one of those as a guard hit would let a
// broken guard pass this file.
function isGuardRefusal(r: { status: number; json: GuardBody }): boolean {
  return r.status === 409 && r.json.discardGuard === true;
}

async function main(): Promise<void> {
  console.log("(1) /history read FAILS: the impact cannot be determined, so the switch is refused");
  {
    const { env } = stackWithHistory({ kind: "status", status: 503 });
    const r = await post(env, { token: "t" });
    ok("(1a) a 503 from /history refuses with 409", isGuardRefusal(r));
    ok("(1b) the refusal reports historyReadOk:false, not a zero count", r.json.historyReadOk === false);
    ok("(1c) the reason names the unreadable history rather than a stranded count", (r.json.error ?? "").includes("run history could not be read in full"));
    ok("(1d) it does NOT claim archives are stranded, because it does not know", (r.json.strandedRunCount ?? -1) === 0);
  }

  console.log("\n(2) /history THROWS: the same fail-closed refusal, via the catch rather than the status check");
  {
    const { env } = stackWithHistory({ kind: "throw" });
    const r = await post(env, { token: "t" });
    ok("(2a) a thrown /history refuses with 409", isGuardRefusal(r));
    ok("(2b) the inventory is reported as not computed", r.json.historyReadOk === false);
    // truncated is FALSE here, and that is correct rather than a bug. computeKeyVintages catches a
    // /history throw itself and returns an inventory with historyReadOk:false and zero runs, so it never
    // reaches the router's `inv?.truncated ?? true` fallback: nothing was scanned, so nothing was cut
    // short. The property that matters is that historyReadOk:false ALONE is enough to refuse, with no
    // help from the other three terms, and that is what is pinned.
    ok("(2c) truncated is false, because nothing was scanned to be cut short", r.json.truncated === false);
    ok("(2d) historyReadOk:false alone refuses, with every other term clear", (r.json.strandedRunCount ?? -1) === 0 && (r.json.unknownRunCount ?? -1) === 0 && r.json.truncated === false);
  }

  console.log("\n(3) more OK runs than one pass reads: truncation is uncertainty, so it refuses");
  {
    const { env } = stackWithHistory({ kind: "ok", okRuns: SCAN_MAX + 1 });
    const r = await post(env, { token: "t" });
    ok("(3a) a truncated scan refuses with 409", isGuardRefusal(r));
    ok("(3b) the refusal reports truncated:true", r.json.truncated === true);
    ok("(3c) the reason says older archives were not checked", (r.json.error ?? "").includes("more archives exist than one inventory pass reads"));
  }

  console.log("\n(4) an OK run whose manifest cannot be read back is UNKNOWN, never assumed safe");
  {
    // One ok run, no destination configured, so readRunManifest cannot reach a manifest and the run is
    // unknown rather than readable. This is the branch that matters most in practice: a real estate
    // whose older archives sit on a destination the engine can no longer read must not be discarded
    // on the strength of a count that was never taken.
    const { env } = stackWithHistory({ kind: "ok", okRuns: 1 });
    const r = await post(env, { token: "t" });
    ok("(4a) an unreadable manifest refuses with 409", isGuardRefusal(r));
    ok("(4b) it is counted as unknown, not as stranded", (r.json.unknownRunCount ?? 0) > 0 && (r.json.strandedRunCount ?? -1) === 0);
    ok("(4c) the reason says the vintage could not be read back", (r.json.error ?? "").includes("could not be read back to confirm it is safe"));
    ok("(4d) the reason still warns about archives beyond retained history", (r.json.error ?? "").includes("Older archives beyond retained run history"));
  }

  console.log("\n(5) the ordinary case: nothing sealed yet, so the guard does not fire at all");
  {
    // The guard must never block the common path. With no OK runs, a readable history and no
    // truncation, there is provably nothing to strand and the route proceeds past the guard.
    const { env } = stackWithHistory({ kind: "ok", okRuns: 0 });
    const r = await post(env, { token: "t" });
    ok("(5a) an empty, readable history is NOT a guard refusal", !isGuardRefusal(r));
  }

  console.log("\n(6) confirmDiscardStranded is the deliberate, warned path past a refusal");
  {
    const { env } = stackWithHistory({ kind: "throw" });
    const denied = await post(env, { token: "t" });
    ok("(6a) the same state refuses without confirmation", isGuardRefusal(denied));
    const confirmed = await post(env, { token: "t", confirmDiscardStranded: true });
    ok("(6b) with confirmDiscardStranded:true the guard is bypassed", !isGuardRefusal(confirmed));
  }

  console.log("\n(7) only a literal true confirms: a truthy value must not open this path");
  {
    // The check is `!== true`, and that strictness is worth pinning. A console bug that sent the string
    // "true", or a 1, must not discard the last recipient of an old vintage.
    for (const value of ["true", 1, "yes", {}] as unknown[]) {
      const { env } = stackWithHistory({ kind: "throw" });
      const r = await post(env, { token: "t", confirmDiscardStranded: value });
      ok(`(7) confirmDiscardStranded=${JSON.stringify(value)} does NOT bypass the guard`, isGuardRefusal(r));
    }
  }

  console.log(`\n${failures === 0 ? "DISCARD-GUARD OK: every refusal branch refuses, the ordinary case is untouched, and only a literal true confirms" : `${failures} FAILURE(S)`}`);
  if (failures > 0) process.exitCode = 1;
  if (failures > 0) (globalThis as unknown as { process: { exit(code: number): never } }).process.exit(1);
}

main().catch((e) => {
  console.error(e);
  (globalThis as unknown as { process: { exit(code: number): never } }).process.exit(1);
});
