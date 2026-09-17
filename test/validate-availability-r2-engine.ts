// Validate the ENGINE half of the R2 rebuild of the console availability gaps.
//
// Three console gaps cannot be closed IN the console: the discriminating fact is one the browser
// structurally cannot hold.
//
//   Token verification: the console sees a flat 400 from POST /sources/discovery-token. THE ENGINE MAKES THE
//         CLOUDFLARE CALL AND SEES THE STATUS. So "your token lacks the scope" (403) and "that is not a valid
//         token" (401) -- opposite remedies -- are a fact here and an inference anywhere else.
//   Guard refusals: three guards (last-Owner, last-passkey, no-first-party-session) throw PLAIN Errors and answer
//         400, so they never enter the DO's AuthError funnel and never reach the authzRefusals ledger unless named
//         at the point they fire. Without that, `last-owner-guard` is IN the vocabulary and DEAD on the console
//         RBAC path: nothing can write it.
//   Session-scoped refusals: the console's ring is in-memory and is reset on every pack download, while a report
//         can be time-displaced BY CONSTRUCTION ("I turned dual control on LAST WEEK"). Only the engine can
//         remember across a session.
//
// SO THIS SUITE ASSERTS ONE THING AND IT IS NOT "A ROW WAS RECORDED". For each gap it NAMES the states that
// must be told apart, drives each through the real classifier or recorder, and asserts they
// produce DIFFERENT rows. Two states that must be told apart and produce one row is a FAILURE here.
//
// Run with `npx tsx test/validate-availability-r2-engine.ts`.

import { classifyTokenSetFailure, applyDiscoveryTokenSet, DISCOVERY_TOKEN_SET_FAIL_CLASSES } from "../src/admin/discovery-health.ts";
import { AUTHZ_GUARD_GATES, AUTHZ_REFUSALS_KEY, classifyAuthzGate, recordAuthzRefusal, type LedgerStorage } from "../src/sched/sched-fault-ledger.ts";
import { adminRefusalReasonForStatus, noteAdminWriteRefusal } from "../src/admin/diag-admin.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  if (cond) console.log(`  ok   ${label}`);
  else {
    console.log(`  FAIL ${label}`);
    failures++;
  }
}
function eq(label: string, actual: unknown, expected: unknown): void {
  ok(`${label} (got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)})`, actual === expected);
}
function section(title: string): void {
  console.log(`\n-- ${title} --`);
}

// memStorage is a Map-backed LedgerStorage, the same fake the other ledger validators use.
function memStorage(): LedgerStorage & { dump(): Record<string, unknown> } {
  const m = new Map<string, unknown>();
  return {
    get: async <T,>(k: string): Promise<T | undefined> => m.get(k) as T | undefined,
    put: async <T,>(k: string, v: T): Promise<void> => void m.set(k, v),
    dump: (): Record<string, unknown> => Object.fromEntries(m),
  };
}

// captureStub records the DO writes a router-side recorder posts, so "which surface:reason landed" is read off
// the WIRE rather than out of the recorder's own head.
function captureStub(): { stub: DurableObjectStub; posts: Array<{ path: string; body: Record<string, unknown> }> } {
  const posts: Array<{ path: string; body: Record<string, unknown> }> = [];
  const stub = {
    fetch: async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url);
      const raw = typeof init?.body === "string" ? init.body : "{}";
      posts.push({ path: url.pathname, body: JSON.parse(raw) as Record<string, unknown> });
      return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
  return { stub, posts };
}

// ==============================================================================================
// "Verify and save always fails": FIVE faults wearing ONE sentence
// ==============================================================================================
//
// THE REFUTATION. Without engine-side classification, a typo'd token, a scope-less token, an expired token, a
// Cloudflare outage and a verify that never got an answer would all COALESCE to {discovery-connect, sources,
// refused} on the console's own ring, and support could not remotely distinguish a scope gap from token-invalid --
// a pair with OPPOSITE remedies.
section("the five refusals that were one flat 400");

const g129: Array<[string, string, string]> = [
  // [what actually happened, the engine's own error literal, the class it must resolve to]
  ["a 403: the token is VALID and lacks the scope", "accounts: HTTP 403", "scope-insufficient"],
  ["a 401: the token is not a credential at all", "accounts: HTTP 401", "token-invalid"],
  ["a 200 that listed cleanly and saw NO account (valid token, scope admits nothing)", "accounts: the token cannot list any account", "scope-insufficient"],
  ["a 500: Cloudflare itself failed the verify", "accounts: HTTP 500", "cf-api-error"],
  ["a 429: Cloudflare throttled the verify", "accounts: HTTP 429", "cf-api-error"],
  ["the fetch THREW: no status was ever seen", "accounts: connect ECONNREFUSED", "verify-timeout"],
];
for (const [what, literal, want] of g129) {
  eq(what, classifyTokenSetFailure([literal], false), want);
}
// The shape rejection happens BEFORE any Cloudflare call, so there is no status to weigh.
eq("a paste that is not a token at all (shape-rejected before any call)", classifyTokenSetFailure([], true), "token-invalid");

// THE DISCRIMINATION ASSERTION. It is not "each classified"; it is "a scope gap and an invalid token produce
// DIFFERENT rows", never one.
ok(
  "THE HEADLINE PAIR: a scope gap and an invalid token are DIFFERENT rows",
  classifyTokenSetFailure(["accounts: HTTP 403"], false) !== classifyTokenSetFailure(["accounts: HTTP 401"], false),
);
const g129Classes = new Set(g129.map(([, lit]) => classifyTokenSetFailure([lit], false)));
ok("the six drives resolve to FOUR distinct classes (the two cf-api-error arms are honestly one remedy)", g129Classes.size === 4);
ok("every produced class is a frozen member", [...g129Classes].every((c) => (DISCOVERY_TOKEN_SET_FAIL_CLASSES as readonly string[]).includes(c)));

// NO-CUSTODY. The applier is the DO-side chokepoint: a value that is not a frozen member is DROPPED, never
// coerced to the nearest one and never carried.
const hostile = applyDiscoveryTokenSet({ outcome: "refused", failClass: "acct-1234-secret-token-abc", accountsSeen: 3 }, 1000);
ok("a customer value smuggled into failClass is DROPPED, never carried", hostile !== null && hostile.failClass === undefined);
ok("...and the record still lands (the refusal is not lost with it)", hostile !== null && hostile.outcome === "refused");
const notAMember = applyDiscoveryTokenSet({ outcome: "sort-of-ok", failClass: "signature" }, 1000);
ok("an out-of-vocabulary OUTCOME fails the record CLOSED (nothing is written)", notAMember === null);
const okRec = applyDiscoveryTokenSet({ outcome: "ok", failClass: "scope-insufficient", accountsSeen: 2 }, 1000);
ok("an `ok` carrying a failClass drops it: a drifted call site cannot claim a healthy token failed", okRec !== null && okRec.failClass === undefined);
eq("...and the count is clamped, not trusted", applyDiscoveryTokenSet({ outcome: "ok", accountsSeen: -5 }, 1000)?.accountsSeen, 0);

// ==============================================================================================
// the three guards that would otherwise refuse in silence
// ==============================================================================================
//
// THE REFUTATION. writeOutcomeForStatus maps EVERY ordinary 4xx to `refused-validation`, so on the console the
// last-Owner guard refusing an offboarding and a plain shape refusal on the same POST would be the byte-identical
// row {admin-write, access-security, role-delete, refused-validation}, coalesced into it. The pack would say
// "role-delete was refused N times" and could not say why. The guards throw PLAIN Errors, which the DO's
// AuthError funnel does not catch, so `last-owner-guard` would be a vocabulary member nothing could write unless
// it is recorded at the site where the guard fires.
section("the guard is named at the site where it is KNOWN");

for (const gate of ["last-owner-guard", "last-passkey-guard", "first-party-session-required"]) {
  ok(`the ledger admits the ${gate} gate`, (AUTHZ_GUARD_GATES as readonly string[]).includes(gate));
}

// The three guards, driven through the real recorder, must land as THREE DIFFERENT KEYS.
{
  const st = memStorage();
  await recordAuthzRefusal(st, "last-owner-guard");
  await recordAuthzRefusal(st, "last-passkey-guard");
  await recordAuthzRefusal(st, "first-party-session-required");
  await recordAuthzRefusal(st, "last-owner-guard"); // a second offboarding refusal: it COUNTS, it does not fork
  const agg = (st.dump()[AUTHZ_REFUSALS_KEY] ?? {}) as Record<string, { count: number }>;
  ok("the three guards are THREE distinct rows, not one", Object.keys(agg).length === 3);
  eq("the last-Owner guard counts its repeats", agg["last-owner-guard"]?.count, 2);
  eq("the last-passkey guard is its own row", agg["last-passkey-guard"]?.count, 1);
  eq("the first-party-session guard is its own row", agg["first-party-session-required"]?.count, 1);
}

// NO-CUSTODY: the ledger is the chokepoint. An out-of-vocabulary gate (a drifted caller, a hostile internal post)
// cannot add a key, so no caller-derived string can ever become one.
{
  const st = memStorage();
  await recordAuthzRefusal(st, "someone@maelstrom.au was refused");
  ok("an out-of-vocabulary gate adds NO key: a refusal message can never become a storage key", st.dump()[AUTHZ_REFUSALS_KEY] === undefined);
}

// The classifier's ORDER is the discrimination. The last-passkey guard's sentence NAMES the sole Owner too, so a
// broader last-owner pattern would swallow it and file a LOCK-OUT guard as a role-removal guard.
eq(
  "the last-passkey sentence classifies as the PASSKEY guard, not the Owner guard",
  classifyAuthzGate(new Error("cannot revoke the last passkey of the sole Owner; enrol another key or appoint a second Owner first")),
  "last-passkey-guard",
);
eq("the last-Owner sentence still classifies as the Owner guard", classifyAuthzGate(new Error("would remove the last Owner")), "last-owner-guard");
ok(
  "THE PAIR: the lock-out guard and the role-removal guard are DIFFERENT rows",
  classifyAuthzGate(new Error("cannot revoke the last passkey of the sole Owner")) !== classifyAuthzGate(new Error("would remove the last Owner")),
);

// ==============================================================================================
// the refused save that only a dismissed toast would otherwise mention
// ==============================================================================================
//
// THE REFUTATION. "I turned dual control on LAST WEEK and it is off." The console's ring is in-memory, has
// deliberately no sessionStorage, and is RESET on every pack download, so a refusal from a prior session is gone
// and three states would produce an identical pack: refused last week, never attempted, applied and later turned
// off.
section("the engine remembers the refusal across the session the browser cannot");

// The reason map is a total function of ONE INTEGER. Each distinct refusal mode must be a distinct row.
const g177: Array<[number, string]> = [
  [403, "forbidden"], // the capability gate said no
  [400, "validation"], // the submitted shape failed a validator
  [409, "conflict"], // a concurrent writer / a lost precondition
  [429, "rate-limited"], // the limiter refused the attempt
  [500, "do-fault"], // the write FAILED: it never landed, and the operator was told something else
];
for (const [status, want] of g177) eq(`status ${status}`, adminRefusalReasonForStatus(status), want);
ok("the five refusal modes are FIVE distinct rows", new Set(g177.map(([s]) => adminRefusalReasonForStatus(s))).size === 5);

// The route table: the OP rides in the surface, so a failed channel CREATE and a failed channel DELETE cannot
// coalesce -- they are different tickets.
{
  const { stub, posts } = captureStub();
  await noteAdminWriteRefusal(stub, "POST", "/config/approval-policy", 403);
  await noteAdminWriteRefusal(stub, "POST", "/notify/channels", 400);
  await noteAdminWriteRefusal(stub, "POST", "/notify/channels/delete", 400);
  await noteAdminWriteRefusal(stub, "POST", "/auth/recovery-codes/regenerate", 500);
  const rows = posts.filter((p) => p.path === "/diag/admin-refusal").map((p) => `${String(p.body.surface)}:${String(p.body.reason)}`);
  ok("four refused writes are FOUR distinct rows", new Set(rows).size === 4);
  ok("the dual-control switch refused by the capability gate says so", rows.includes("approval-policy:forbidden"));
  ok("a channel CREATE and a channel DELETE refused by the SAME 400 do NOT coalesce", rows.includes("notify-channel-set:validation") && rows.includes("notify-channel-delete:validation"));
  ok("the gap's worst case (recovery-codes regenerate FAILED, not refused) is its own row", rows.includes("recovery-codes-regenerate:do-fault"));
}

// NOISE DISCIPLINE. A signal that cries wolf devalues every true one, and two of these would fire constantly.
{
  const { stub, posts } = captureStub();
  await noteAdminWriteRefusal(stub, "POST", "/config/approval-policy", 200); // it WORKED
  await noteAdminWriteRefusal(stub, "POST", "/config/approval-policy", 204);
  ok("a SUCCESSFUL save records nothing: a save that worked is not a fault", posts.length === 0);

  // The 401 on a gatedFetch route is the OPENING MOVE of a successful step-up ceremony, not a refusal. Recording
  // it would file every dual-controlled save that then SUCCEEDED as a permissions denial.
  await noteAdminWriteRefusal(stub, "POST", "/posture/accept", 401);
  ok("the step-up handshake's 401 records nothing: it is not a refusal, it is the ceremony starting", posts.length === 0);

  // A route that is not a governance write is not this ring's business.
  await noteAdminWriteRefusal(stub, "GET", "/status", 500);
  await noteAdminWriteRefusal(stub, "POST", "/some/unmapped/route", 400);
  ok("an unmapped route records nothing: the surface is a frozen table, never derived from the path", posts.length === 0);
}

// ---- no-custody: a sentinel planted at every new engine fault site reaches nothing on the wire ----
section("no-custody: nothing but closed members, counts and clamped ints crosses the boundary");
{
  const SENTINEL = "acct-9f3-secret-BUCKET-someone@maelstrom.au";
  const { stub, posts } = captureStub();
  await noteAdminWriteRefusal(stub, "POST", `/notify/channels?u=${SENTINEL}`, 400); // a poisoned PATH
  ok("a poisoned path matches no frozen route template, so it records NOTHING", posts.length === 0);

  const st = memStorage();
  await recordAuthzRefusal(st, SENTINEL);
  const rec = applyDiscoveryTokenSet({ outcome: "refused", failClass: SENTINEL, accountsSeen: 1 }, 1000);
  const wire = JSON.stringify({ authz: st.dump(), tokenSet: rec, posts });
  ok("the sentinel appears NOWHERE on anything that reaches the DO or the pack", !wire.includes("acct-9f3") && !wire.includes("maelstrom"));
  ok("negative control: the sentinel IS detectable when actually present", JSON.stringify({ x: SENTINEL }).includes("maelstrom"));
}

console.log(failures === 0 ? "\nAVAILABILITY R2 ENGINE PASS" : `\n${failures} FAILURE(S)`);
verdictReached(failures);
if (failures > 0) process.exit(1);
