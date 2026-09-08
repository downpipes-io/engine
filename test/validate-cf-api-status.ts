// The Cloudflare API client's handling of responses that carry no envelope.
//
// WHY THIS EXISTS
// ---------------
// A 204 No Content is a SUCCESS with nothing to parse. The client read the body (null), saw `resp.ok` but
// no `success: true`, and fell into the refusal branch, so a request that worked was thrown as an error.
// Cloudflare answers 204 on several DELETEs, `custom_pages/assets` among them.
//
// Offline and hermetic: a stub fetch, no credentials, no network.

import { makeCfApi } from "../src/sources/cf-config-core.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

// stub answers one canned response, so each case pins exactly one status/body pair.
function stub(status: number, body: string | null): typeof fetch {
  return (async () =>
    new Response(body, { status, headers: body === null ? {} : { "content-type": "application/json" } })) as unknown as typeof fetch;
}

console.log("-- 204 No Content is a SUCCESS, not a refusal --");
{
  const api = makeCfApi("t", stub(204, null));
  let threw = "";
  let result: unknown = "unset";
  try {
    result = await api.send("DELETE", "/accounts/x/custom_pages/assets/y", undefined);
  } catch (e) {
    threw = (e as Error).message;
  }
  ok("a 204 does not throw", threw === "");
  ok("a 204 yields a null result rather than a fabricated object", result === null);
}

console.log("\n-- a 2xx that SHOULD have carried a result and did not stays loud --");
{
  // Deliberately NOT swallowed. A 200 with an unparseable body is a real fault: something was meant to come
  // back and did not, and treating it as success would hide exactly the shape anomaly this client already
  // records elsewhere. Narrowing the fix to 204 is what keeps this case failing.
  const api = makeCfApi("t", stub(200, "not json at all"));
  let threw = "";
  try {
    await api.get("/accounts/x/whatever");
  } catch (e) {
    threw = (e as Error).message;
  }
  ok("a 200 with an unparseable body still throws", threw !== "");
}

console.log("\n-- ordinary failures are unaffected --");
{
  const api = makeCfApi("t", stub(403, JSON.stringify({ success: false, errors: [{ code: 10000, message: "Forbidden" }] })));
  let threw = "";
  try {
    await api.send("POST", "/accounts/x/thing", {});
  } catch (e) {
    threw = (e as Error).message;
  }
  ok("a 403 still throws", threw !== "");
  ok("and carries Cloudflare's own words", /Forbidden/.test(threw));
}

console.log("\n-- a normal enveloped 200 still returns its result --");
{
  const api = makeCfApi("t", stub(200, JSON.stringify({ success: true, result: { id: "abc" } })));
  const r = (await api.get("/accounts/x/thing")) as { id?: string } | null;
  ok("the result is unwrapped from the envelope", r?.id === "abc");
}

console.log(failures === 0 ? "\nCF API STATUS HANDLING PASS" : `\n${failures} FAILURE(S)`);
if (failures > 0) process.exitCode = 1;
if (failures > 0) process.exit(1);
