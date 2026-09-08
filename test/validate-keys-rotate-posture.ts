// Validates the two new no-customer-CLI key operations added to attach.ts:
//   - rotateBreakGlassPublic: writes ONLY a new BREAK_GLASS_PUBLIC via a scoped token (validate
//     before write; one PUT to the collection endpoint; Bearer; no value/token leak).
//   - removeOperationalSecrets: SETS the durable OPERATIONAL_RETIRED marker FIRST, then deletes
//     BOTH operational secrets to enter strict break-glass-only (PRIVATE deleted FIRST so a partial
//     failure still removes the decryption-capable key; item endpoints; Bearer; idempotent on a 404;
//     stops + names the scope on a real failure). The marker PUT is FATAL on failure (unlike its
//     best-effort clear in addOperationalSecrets/installEngineSecrets): a switch that cannot durably
//     record itself must not proceed to delete the operational secrets.
// No real network: a stub fetch records PUT/DELETE calls. Run: node test/validate-keys-rotate-posture.ts

import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { rotateBreakGlassPublic, removeOperationalSecrets } from "../src/admin/attach.ts";
import { handleAdmin } from "../src/admin/router.ts";
import { SchedulerDO } from "../src/index.ts";
import { b64urlEncode, concat } from "../src/crypto/bytes.ts";
import type { Env } from "../src/env.d.ts";
import { MockStorage } from "./mock-storage.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}
function randomBytes(n: number): Uint8Array { return crypto.getRandomValues(new Uint8Array(n)); }

// A valid recipient public = x25519 public(32) || ML-KEM-1024 ek(1568) = 1600 bytes.
const bgKp = x25519.keygen();
const NEW_BREAK_GLASS_PUBLIC = b64urlEncode(concat(bgKp.publicKey, ml_kem1024.keygen(randomBytes(64)).publicKey));
const TOKEN = "cfat-test-edit-workers-token-1234567890";

interface Call { method: string; url: string; auth: string; body: string }
function makeStub(opts: { status404On?: string; failOn?: string } = {}): { fetch: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const auth = headers["authorization"] ?? headers["Authorization"] ?? "";
    calls.push({ method, url, auth, body: String(init?.body ?? "") });
    if (opts.status404On && url.includes(opts.status404On)) return new Response(null, { status: 404 });
    if (opts.failOn && url.includes(opts.failOn)) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "Authentication error" }] }), { status: 403 });
    return new Response(JSON.stringify({ success: true }), { status: 200 });
  }) as typeof fetch;
  return { fetch: fetchImpl, calls };
}

async function main(): Promise<void> {
  console.log("-- rotateBreakGlassPublic: validate before write --");
  {
    const s1 = makeStub();
    let threw = "";
    try { await rotateBreakGlassPublic("acct1", "downpipe-engine", TOKEN, "not-base64url!!", s1.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a malformed break-glass public is refused before any network call", /break-glass public did not parse/.test(threw));
    ok("a malformed public made ZERO fetch calls", s1.calls.length === 0);

    const s2 = makeStub();
    threw = "";
    try { await rotateBreakGlassPublic("acct1", "downpipe-engine", "", NEW_BREAK_GLASS_PUBLIC, s2.fetch); } catch (e) { threw = (e as Error).message; }
    ok("an empty token is refused before any network call", /deploy token/.test(threw) && s2.calls.length === 0);

    // A non-string token is coerced to empty by the leading guard, so the token-required check fires.
    const s3 = makeStub();
    threw = "";
    try { await rotateBreakGlassPublic("acct1", "downpipe-engine", undefined as unknown as string, NEW_BREAK_GLASS_PUBLIC, s3.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a non-string (missing) token is refused before any network call", /deploy token/.test(threw) && s3.calls.length === 0);

    // A non-string public is coerced to empty, so the public-required check fires (distinct from the
    // parse-failure case above which sends a junk-but-present string).
    const s4 = makeStub();
    threw = "";
    try { await rotateBreakGlassPublic("acct1", "downpipe-engine", TOKEN, 9999 as unknown as string, s4.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a non-string (missing) break-glass public is refused as required, no fetch", /new break-glass public is required/.test(threw) && s4.calls.length === 0);

    // An empty-string public (after trim) is refused as required before the parse step.
    const s5 = makeStub();
    threw = "";
    try { await rotateBreakGlassPublic("acct1", "downpipe-engine", TOKEN, "   ", s5.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a blank break-glass public is refused as required, no fetch", /new break-glass public is required/.test(threw) && s5.calls.length === 0);
  }

  console.log("\n-- rotateBreakGlassPublic: good public -> exactly one PUT of BREAK_GLASS_PUBLIC --");
  {
    const stub = makeStub();
    await rotateBreakGlassPublic("acct-xyz", "downpipe-engine", TOKEN, NEW_BREAK_GLASS_PUBLIC, stub.fetch);
    const puts = stub.calls.filter((c) => c.method === "PUT");
    ok("exactly one PUT", puts.length === 1 && stub.calls.length === 1);
    const parsed = JSON.parse(puts[0]?.body ?? "{}") as { name?: string; text?: string; type?: string };
    ok("the PUT sets BREAK_GLASS_PUBLIC with the new value and type secret_text", parsed.name === "BREAK_GLASS_PUBLIC" && parsed.text === NEW_BREAK_GLASS_PUBLIC && parsed.type === "secret_text");
    ok("the PUT hit the collection secrets endpoint for the account+script", /\/accounts\/acct-xyz\/workers\/scripts\/downpipe-engine\/secrets$/.test(puts[0]?.url ?? ""));
    ok("the PUT carried Authorization: Bearer <token>", puts[0]?.auth === `Bearer ${TOKEN}`);
    ok("no other secret was touched (signer/operational untouched)", puts.length === 1);
  }

  console.log("\n-- rotateBreakGlassPublic: a failed PUT names the scope and leaks nothing --");
  {
    const stub = makeStub({ failOn: "/secrets" });
    let threw = "";
    try { await rotateBreakGlassPublic("acct-xyz", "downpipe-engine", TOKEN, NEW_BREAK_GLASS_PUBLIC, stub.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a failed PUT throws naming the Edit Cloudflare Workers template", /Edit Cloudflare Workers/.test(threw));
    ok("the failure reason carries no token", !threw.includes(TOKEN));
  }

  console.log("\n-- removeOperationalSecrets: sets OPERATIONAL_RETIRED first, then deletes PRIVATE, then PUBLIC --");
  {
    const stub = makeStub();
    await removeOperationalSecrets("acct-xyz", "downpipe-engine", TOKEN, stub.fetch);
    ok("exactly three calls: the marker PUT, then two DELETEs", stub.calls.length === 3);
    const [first, second, third] = stub.calls;
    ok("call #1 PUTs the OPERATIONAL_RETIRED marker to the collection endpoint", first?.method === "PUT" && /\/accounts\/acct-xyz\/workers\/scripts\/downpipe-engine\/secrets$/.test(first?.url ?? ""));
    const markerBody = JSON.parse(first?.body ?? "{}") as { name?: string; text?: string; type?: string };
    ok('the marker PUT sets OPERATIONAL_RETIRED = "true" (a boolean flag, never a key)', markerBody.name === "OPERATIONAL_RETIRED" && markerBody.text === "true" && markerBody.type === "secret_text");
    ok("call #2 deletes OPERATIONAL_PRIVATE (the decryption-capable key goes first)", second?.method === "DELETE" && /\/secrets\/OPERATIONAL_PRIVATE$/.test(second?.url ?? ""));
    ok("call #3 deletes OPERATIONAL_PUBLIC", third?.method === "DELETE" && /\/secrets\/OPERATIONAL_PUBLIC$/.test(third?.url ?? ""));
    const dels = stub.calls.filter((c) => c.method === "DELETE");
    ok("both DELETEs hit the per-secret ITEM endpoint for the account+script", dels.every((c) => /\/accounts\/acct-xyz\/workers\/scripts\/downpipe-engine\/secrets\/OPERATIONAL_(PRIVATE|PUBLIC)$/.test(c.url)));
    ok("every call (marker PUT + both DELETEs) carried Authorization: Bearer <token>", stub.calls.every((c) => c.auth === `Bearer ${TOKEN}`));
  }

  console.log("\n-- removeOperationalSecrets: idempotent on a 404 (already absent); the marker is still set --");
  {
    // The PRIVATE is already gone (404). The helper must treat that as success and STILL delete PUBLIC,
    // and must still set the marker (the marker PUT runs before either delete, so a 404 on a LATER call
    // cannot affect it).
    const stub = makeStub({ status404On: "/secrets/OPERATIONAL_PRIVATE" });
    let threw = "";
    try { await removeOperationalSecrets("acct-xyz", "downpipe-engine", TOKEN, stub.fetch); } catch (e) { threw = (e as Error).message; }
    const dels = stub.calls.filter((c) => c.method === "DELETE");
    const puts = stub.calls.filter((c) => c.method === "PUT");
    ok("a 404 on the first delete does not throw", threw === "");
    ok("the marker PUT still happened", puts.length === 1);
    ok("it still proceeds to delete OPERATIONAL_PUBLIC (idempotent)", dels.length === 2 && /OPERATIONAL_PUBLIC$/.test(dels[1]?.url ?? ""));
  }

  console.log("\n-- removeOperationalSecrets: a failed marker PUT is FATAL and stops before either delete --");
  {
    // Unlike the CLEAR side (best-effort in addOperationalSecrets/installEngineSecrets), SETTING the
    // marker must be fatal: if it cannot be durably recorded, the switch must not proceed to delete the
    // operational secrets, or the engine could end up genuinely break-glass-only with NO durable record
    // of that at all -- the exact silent-reversal hazard the marker exists to close. failOn matches
    // every call this stub makes (the marker's collection endpoint and the deletes' item endpoints all
    // contain "/secrets"), but since the marker PUT runs FIRST and throws immediately, neither delete is
    // ever attempted regardless.
    const stub = makeStub({ failOn: "/secrets" });
    let threw = "";
    try { await removeOperationalSecrets("acct-xyz", "downpipe-engine", TOKEN, stub.fetch); } catch (e) { threw = (e as Error).message; }
    const dels = stub.calls.filter((c) => c.method === "DELETE");
    ok("a failed marker PUT throws", /could not set the engine secret OPERATIONAL_RETIRED/.test(threw));
    ok("NEITHER delete is attempted (the switch never proceeds on an unrecorded marker)", dels.length === 0);
    ok("the failure carries no token", !threw.includes(TOKEN));
  }

  console.log("\n-- removeOperationalSecrets: empty/non-string token refused with no fetch --");
  {
    const stub = makeStub();
    let threw = "";
    try { await removeOperationalSecrets("acct-xyz", "downpipe-engine", "", stub.fetch); } catch (e) { threw = (e as Error).message; }
    ok("an empty token is refused before any network call", /deploy token/.test(threw) && stub.calls.length === 0);

    // A non-string token is coerced to empty by the leading guard, so the same token-required refusal
    // fires before either DELETE is attempted.
    const stub2 = makeStub();
    threw = "";
    try { await removeOperationalSecrets("acct-xyz", "downpipe-engine", null as unknown as string, stub2.fetch); } catch (e) { threw = (e as Error).message; }
    ok("a non-string (missing) token is refused before any network call", /deploy token/.test(threw) && stub2.calls.length === 0);
  }

  console.log("\n-- removeOperationalSecrets: a real failure (403) on the first delete stops there; the marker already landed --");
  {
    // PRIVATE delete is rejected with 403: the helper throws (the decryption key delete failed) and does
    // NOT proceed to PUBLIC, so the operator gets a clear failure rather than a half-applied posture. The
    // marker PUT (which runs BEFORE either delete) already succeeded -- the fail-safe property B7 needs:
    // even this half-applied failure leaves deploy.sh able to see the deliberate-removal marker.
    const stub = makeStub({ failOn: "/secrets/OPERATIONAL_PRIVATE" });
    let threw = "";
    try { await removeOperationalSecrets("acct-xyz", "downpipe-engine", TOKEN, stub.fetch); } catch (e) { threw = (e as Error).message; }
    const dels = stub.calls.filter((c) => c.method === "DELETE");
    const puts = stub.calls.filter((c) => c.method === "PUT");
    ok("a 403 on the first delete throws", /could not remove the engine secret OPERATIONAL_PRIVATE/.test(threw));
    ok("it stops on the first failure (only one DELETE attempted)", dels.length === 1);
    ok("the OPERATIONAL_RETIRED marker PUT already succeeded before the failing delete", puts.length === 1);
    ok("the failure carries no token", !threw.includes(TOKEN));
  }

  console.log("\n-- routes through handleAdmin: gate + server-enforcement wiring --");
  {
    const ADMIN_TOKEN = "rotate-posture-admin-token";
    const mkEnv = (extra: Record<string, unknown>): { env: Env; calls: string[] } => {
      const storage = new MockStorage();
      const dobj = new SchedulerDO({ storage } as unknown as DurableObjectState);
      const stub = { fetch: (input: RequestInfo | URL, init?: RequestInit) => dobj.fetch(new Request(typeof input === "string" ? input : (input as URL).toString(), init)) } as unknown as DurableObjectStub;
      const namespace = { idFromName: () => ({}) as unknown as DurableObjectId, get: () => stub } as unknown as DurableObjectNamespace;
      const calls: string[] = [];
      const env = { SCHEDULER: namespace, ADMIN_TOKEN, WORKER_NAME: "downpipe-engine", ...extra } as unknown as Env;
      return { env, calls };
    };
    const post = (env: Env, path: string, body: unknown) => handleAdmin(new Request(`https://engine.example/admin${path}`, {
      method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" }, body: JSON.stringify(body),
    }), env);

    // No CF API should ever be hit in these wiring checks (gate/guard short-circuits before any PUT/DELETE).
    const realFetch = globalThis.fetch;
    const cfCalls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : (input as URL).toString();
      if (url.startsWith("https://api.cloudflare.com")) { cfCalls.push(`${init?.method ?? "GET"} ${url}`); return new Response(JSON.stringify({ success: true }), { status: 200 }); }
      throw new Error(`unexpected network fetch in test: ${url}`);
    }) as typeof fetch;
    try {
      // acknowledge with NO keys present -> server refuses to clear (ok:false), no DO marker touched.
      {
        const { env } = mkEnv({ CF_ACCOUNT_ID: "acct1" });
        const resp = await post(env, "/setup/acknowledge", {});
        const bodyText = await resp.text();
        ok("acknowledge with keys absent returns ok:false reason keys-not-present (server-enforced)", resp.status === 200 && /"ok":false/.test(bodyText) && /keys-not-present/.test(bodyText));
      }
      // acknowledge WITH keys present -> ok:true (buildStatus sees signer+break-glass via env).
      {
        const { env } = mkEnv({ CF_ACCOUNT_ID: "acct1", SIGNER_PRIVATE: "x", BREAK_GLASS_PUBLIC: "y" });
        const resp = await post(env, "/setup/acknowledge", {});
        const bodyText = await resp.text();
        ok("acknowledge with keys present returns ok:true", resp.status === 200 && /"ok":true/.test(bodyText));
      }
      // rotate with the engine account NOT marked -> 400 before any CF call.
      {
        const { env } = mkEnv({}); // no CF_ACCOUNT_ID, no marked engine account
        const resp = await post(env, "/keys/rotate", { token: TOKEN, breakGlassPublic: NEW_BREAK_GLASS_PUBLIC });
        ok("rotate refuses (400) when the engine account is not marked", resp.status === 400);
      }
      // break-glass-only with the engine account NOT marked -> 400 before any CF call.
      {
        const { env } = mkEnv({});
        const resp = await post(env, "/keys/break-glass-only", { token: TOKEN });
        ok("break-glass-only refuses (400) when the engine account is not marked", resp.status === 400);
      }
      ok("NO Cloudflare API call was made in any gate/guard short-circuit", cfCalls.length === 0);
    } finally {
      globalThis.fetch = realFetch;
    }
  }

  if (failures > 0) process.exitCode = 1;
  if (failures > 0) {
    console.error(`\n${failures} FAILURE(S)`);
    process.exit(1);
  }
  console.log("\nKEYS-ROTATE-POSTURE VECTORS PASS");
}

main().catch((e) => { console.error(e); process.exit(1); });
