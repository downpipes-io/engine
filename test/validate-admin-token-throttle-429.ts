// The bare-token anti-brute-force throttle answers 429, and ONLY it does.
//
// WHY THIS EXISTS. Every deny out of authorise() used to be a byte-identical generic 401, deliberately, so no
// deny class is oracled back to an attacker. That rule is right for every deny that is a statement about the
// CREDENTIAL. The rate limiter is not one: it fires BEFORE tokenEqual (auth.ts), so it refuses a correct and
// an incorrect token identically, and "too many attempts" tells an attacker nothing they did not already know
// from having made them.
//
// Answering 401 for it was actively harmful. A rate limit and a session loss became indistinguishable to
// every caller, so the console's isUnauthorised() signed the operator out on one: a throttled approvals
// lookup ended a session in the middle of a restore.
//
// The load-bearing half of this file is the NEGATIVE: every OTHER deny must stay a bare { ok: false } with no
// throttled marker, or the 429 becomes the oracle the generic 401 exists to prevent.
//
// Run: node test/validate-admin-token-throttle-429.ts

import { authorise } from "../src/admin/auth.ts";
import type { Env } from "../src/env.d.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const tokenEnv = (over: Partial<Env> = {}): Env => ({ ADMIN_TOKEN: "correct-horse", ...over }) as unknown as Env;
const bearer = (token: string): Request => new Request("https://engine.example/admin/downpipes", { headers: { authorization: `Bearer ${token}` } });

async function testThrottleIsMarked(): Promise<void> {
  console.log("\n-- the throttle is marked, and marked ONLY when it fires --");

  const throttled = await authorise(bearer("correct-horse"), tokenEnv(), undefined, undefined, undefined, async () => true);
  ok("a throttled request is refused", throttled.ok === false);
  ok("and carries throttled:true so the router can answer 429", throttled.ok === false && throttled.throttled === true);

  // The SAME limiter verdict on a WRONG token must look identical, which is what makes 429 safe here.
  const throttledWrong = await authorise(bearer("wrong"), tokenEnv(), undefined, undefined, undefined, async () => true);
  ok("a throttled request with a WRONG token is refused identically, so 429 leaks nothing about the token", throttledWrong.ok === false && throttledWrong.throttled === true);

  const allowed = await authorise(bearer("correct-horse"), tokenEnv(), undefined, undefined, undefined, async () => false);
  ok("an un-throttled correct token still authorises", allowed.ok === true);
}

async function testEveryOtherDenyStaysBare(): Promise<void> {
  console.log("\n-- every OTHER deny stays a bare { ok: false }, or the 429 becomes an oracle --");

  const wrong = await authorise(bearer("wrong"), tokenEnv(), undefined, undefined, undefined, async () => false);
  ok("a WRONG token is denied with NO throttled marker", wrong.ok === false && wrong.throttled === undefined);

  const empty = await authorise(new Request("https://engine.example/admin/downpipes"), tokenEnv(), undefined, undefined, undefined, async () => false);
  ok("NO credential is denied with NO throttled marker", empty.ok === false && empty.throttled === undefined);

  const unconfigured = await authorise(bearer("anything"), {} as unknown as Env, undefined, undefined, undefined, async () => false);
  ok("an UNCONFIGURED token is denied with NO throttled marker", unconfigured.ok === false && unconfigured.throttled === undefined);

  const retired = await authorise(bearer("correct-horse"), tokenEnv(), undefined, async () => true, undefined, async () => false);
  ok("a RETIRED token is denied with NO throttled marker", retired.ok === false && retired.throttled === undefined);

  const disabled = await authorise(bearer("correct-horse"), tokenEnv({ ADMIN_TOKEN_DISABLED: "1" } as Partial<Env>), undefined, undefined, undefined, async () => false);
  ok("a DISABLED token fallback is denied with NO throttled marker", disabled.ok === false && disabled.throttled === undefined);
}

// THE ROUTER MUST ACTUALLY RENDER IT, and the reason is a lesson already paid for here: a test that asserts
// only the VERDICT passes even if the router ignores the marker and still writes 401.
//
// This used to prove that by REGEX over router.ts, matching `status: 429` and `retry-after` inside the
// verdict.throttled guard body. That mechanism was wrong twice over. It went red for a change
// that was entirely correct (the literals moved into a shared builder so all four of the engine's 429s stop
// drifting apart), which is a guard failing an improvement. And it could never have caught the drift that
// change fixed, because a hand-built plaintext 429 with no content-type matches `status: 429` perfectly: the
// regex read the two tokens it was told to look for and had no opinion on what was actually sent.
//
// So it drives handleAdmin instead and reads the RESPONSE. Reverting the router to 401 still turns this red,
// which was the whole point, and now a body that no client can parse does too.
async function testRouterRendersIt(): Promise<void> {
  console.log("\n-- the router actually maps the marker to 429 --");
  const { handleAdmin } = await import("../src/admin/router.ts");
  const { makeScheduler } = await import("./validate-rbac-harness.ts");

  // A scheduler whose /rate-check always refuses, so the bare-token throttle fires on the first request.
  // Everything else routes to the real in-memory double, so the request reaches the genuine auth gate.
  const real = makeScheduler();
  const throttling = {
    fetch: (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (url.endsWith("/rate-check")) return Promise.resolve(new Response(JSON.stringify({ allowed: false, retryAfterMs: 30_000 }), { headers: { "content-type": "application/json" } }));
      return real.stub.fetch(input, init);
    },
  } as unknown as DurableObjectStub;
  const env = { ...real.env, ADMIN_TOKEN: "correct-horse", SCHEDULER: { idFromName: () => "id", get: () => throttling } } as unknown as Env;
  const call = (token: string): Promise<Response> =>
    handleAdmin(new Request("https://engine.example/admin/status", { headers: { authorization: `Bearer ${token}`, "CF-Connecting-IP": "203.0.113.44" } }), env);

  const throttled = await call("correct-horse");
  ok("a throttled request through handleAdmin is answered 429, not 401", throttled.status === 429);
  ok("and it carries Retry-After, so the caller can act on it rather than only see it", throttled.headers.get("retry-after") !== null);
  ok("and it is problem+json, so a client that follows the published contract can read it", (throttled.headers.get("content-type") ?? "").includes("application/problem+json"));
  const body = await throttled.text();
  let parsed: { error?: string } = {};
  try {
    parsed = JSON.parse(body) as { error?: string };
  } catch {
    ok(`the throttle 429 body parses as JSON (got ${JSON.stringify(body.slice(0, 40))})`, false);
  }
  ok("and says error: 'rate limited', the field the contract tells an integrator to match on", parsed.error === "rate limited");

  // The generic 401 must survive for everything else, proven the same way rather than by grepping for the
  // literal: a WRONG token, with the throttle NOT firing, is still the byte-identical plaintext 401.
  const unthrottled = makeScheduler();
  const plainEnv = { ...unthrottled.env, ADMIN_TOKEN: "correct-horse" } as unknown as Env;
  const denied = await handleAdmin(new Request("https://engine.example/admin/status", { headers: { authorization: "Bearer wrong" } }), plainEnv);
  ok("a WRONG token is still the generic 401, so the 429 has not widened into every deny", denied.status === 401);
  ok("and the 401 body is still the fixed plaintext, never JSON", (await denied.text()) === "unauthorised");
}

console.log("ADMIN-TOKEN THROTTLE -> 429");
await testThrottleIsMarked();
await testEveryOtherDenyStaysBare();
await testRouterRendersIt();

console.log(failures === 0 ? "\nALL PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
