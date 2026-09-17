// validate-outbound-redirect: the outbound policy in src/lib/outbound.ts behaves (ASVS V13.2.5, V15.3.2).
// The census (validate-outbound-policy) proves every call site STATES the policy; this proves the policy
// DOES something: a credentialed Cloudflare API call that meets a 302 requests redirect: "manual", fails, and
// issues exactly one request (the Location is never fetched, so the bearer is never replayed); the fixed-host
// pin admits the vendor hosts and refuses look-alikes; and an artefact URL off the channel's host is refused
// before any request. Each refusal is paired with the admitted case as its control.
import { readDeployedBindings } from "../src/admin/cf-api.ts";
import { fetchArtefactBytesDetailed } from "../src/admin/router-sources.ts";
import { assertEgressHost, isFixedEgressHost, UPDATE_CHANNEL_HOST } from "../src/lib/outbound.ts";
import { makeCfApi } from "../src/sources/cf-config-core.ts";
import { verdictReached } from "./lib/verdict-guard.ts";

let failures = 0;
function ok(label: string, cond: boolean): void { console.log(`  ${cond ? "ok  " : "FAIL"} ${label}`); if (!cond) failures++; }

// A stub fetch that answers a 302 to an attacker host and records every request it sees, with the init.
function redirectingStub(): { fetchImpl: typeof fetch; calls: { url: string; redirect: string | undefined; auth: boolean }[] } {
  const calls: { url: string; redirect: string | undefined; auth: boolean }[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const headers = new Headers(init?.headers);
    calls.push({ url, redirect: init?.redirect, auth: headers.has("authorization") });
    if (url.startsWith("https://evil.example/")) return new Response("{}", { status: 200 });
    return new Response(null, { status: 302, headers: { location: "https://evil.example/replay" } });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

async function main(): Promise<void> {
  console.log("\n(1) a credentialed Cloudflare API read that meets a 302 requests redirect: manual, fails, and never fetches the Location");
  {
    const { fetchImpl, calls } = redirectingStub();
    let threw = false;
    let result: unknown = null;
    try { result = await readDeployedBindings("tok", "acct", "script", fetchImpl, true); } catch { threw = true; }
    ok("(1) readDeployedBindings requested redirect: manual", calls.length >= 1 && calls.every((c) => c.redirect === "manual"));
    ok("(1) the 302 was a failed call (threw or returned nothing usable), not a followed redirect", threw || (Array.isArray(result) && result.length === 0));
    ok("(1) exactly one request, and none to the Location host (the bearer was not replayed)", calls.length === 1 && !calls.some((c) => c.url.startsWith("https://evil.example/")));
    ok("(1) control: the one request carried the bearer to the Cloudflare host", calls[0]?.auth === true && calls[0].url.startsWith("https://api.cloudflare.com/"));
  }
  console.log("\n(2) the shared Cloudflare configuration client carries the same policy");
  {
    const { fetchImpl, calls } = redirectingStub();
    const api = makeCfApi("tok", fetchImpl);
    let threw = false;
    try { await api.get("/zones/z1/settings"); } catch { threw = true; }
    ok("(2) makeCfApi requested redirect: manual on every attempt", calls.length >= 1 && calls.every((c) => c.redirect === "manual"));
    ok("(2) the 302 surfaced as a thrown fault", threw);
    ok("(2) no request went to the Location host", !calls.some((c) => c.url.startsWith("https://evil.example/")));
  }
  console.log("\n(3) the fixed-host pin admits the vendor hosts and refuses look-alikes");
  {
    ok("(3) api.cloudflare.com is fixed", isFixedEgressHost("api.cloudflare.com"));
    ok("(3) a team's Access host is fixed by suffix", isFixedEgressHost("maelstrom.cloudflareaccess.com"));
    ok("(3) sts.ap-southeast-2.amazonaws.com is fixed by suffix", isFixedEgressHost("sts.ap-southeast-2.amazonaws.com"));
    ok("(3) api.cloudflare.com.evil.example is NOT fixed", !isFixedEgressHost("api.cloudflare.com.evil.example"));
    ok("(3) a bare suffix (cloudflareaccess.com) is NOT fixed", !isFixedEgressHost("cloudflareaccess.com"));
    let admitted = false;
    try { assertEgressHost("https://api.cloudflare.com/client/v4"); admitted = true; } catch { admitted = false; }
    ok("(3) assertEgressHost admits https://api.cloudflare.com", admitted);
    let refused = "";
    try { assertEgressHost("https://api.cloudflare.com.evil.example/x?token=secret"); } catch (e) { refused = (e as Error).message; }
    ok("(3) assertEgressHost refuses the look-alike, naming the host and not the query", refused.includes("api.cloudflare.com.evil.example") && !refused.includes("secret"));
    let plain = "";
    try { assertEgressHost("http://api.cloudflare.com/client/v4"); } catch (e) { plain = (e as Error).message; }
    ok("(3) assertEgressHost refuses plaintext", plain.includes("not https"));
  }
  console.log("\n(4) an artefact URL off the channel's host is refused before any request");
  {
    const realFetch = globalThis.fetch;
    let fetched = 0;
    globalThis.fetch = (async (): Promise<Response> => { fetched++; return new Response(new Uint8Array([1, 2, 3]), { status: 200 }); }) as typeof fetch;
    try {
      const off = await fetchArtefactBytesDetailed("https://mirror.example/engine.tar");
      ok("(4) an off-host artefact URL is refused with cause url-config", off.ok === false && off.cause === "url-config");
      ok("(4) nothing was requested from it", fetched === 0);
      const on = await fetchArtefactBytesDetailed(`https://${UPDATE_CHANNEL_HOST}/engine.tar`);
      ok("(4) control: the channel host is fetched (one request, bytes returned)", on.ok === true && fetched === 1);
    } finally {
      globalThis.fetch = realFetch;
    }
  }
  console.log(failures === 0 ? "\nOUTBOUND REDIRECT + FIXED HOST VECTORS PASS" : `\n${failures} FAILURE(S)`);
  verdictReached(failures);
  if (failures > 0) process.exit(1);
}
void main();
