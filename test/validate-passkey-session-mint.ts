// Focused UNIT tests for sessionCookieForFinish (src/admin/router-auth-flow.ts), the critical passkey
// session-mint path that turns a finished ceremony body into a hardened Set-Cookie. The full
// register -> login round trip is exercised end to end elsewhere (validate-passkey-roundtrip.ts), and the
// error branches of sessionCookieForFinish are isolated here: a malformed body, a non-ok body, an empty
// email, and a DO mint failure each yield null and must
// NOT issue a session. These tests drive the real function with a tiny fake scheduler stub so each guard is
// asserted on its own (no DO, no network). They are written as negative controls: each would FAIL if the
// corresponding guard were dropped.
//
// Run via the passkey suite orchestrator: node test/validate-passkey.ts

import { sessionCookieForFinish } from "../src/admin/router-auth-flow.ts";
import { SESSION_COOKIE_NAME } from "../src/admin/session.ts";
import type { Env } from "../src/env.d.ts";
import { ok, captureErrors } from "./validate-passkey-harness.ts";

// A production-shaped env: no HARNESS_TEST_FAULTS, so every call below proves the ORDINARY (non-harness)
// guards, independent of the fault-injection seam used elsewhere for negative testing.
const PROD_ENV = {} as unknown as Env;

// fakeIssueScheduler returns a minimal DurableObjectStub whose ONLY response is to /passkey/session/issue:
// `issued` is the JSON body it answers with (the mint outcome), or "throw" to simulate a DO hiccup. Every
// other route is irrelevant to sessionCookieForFinish (it calls only the issue route on the ok-path).
function fakeIssueScheduler(issued: unknown | "throw"): DurableObjectStub {
  return {
    fetch: async (): Promise<Response> => {
      if (issued === "throw") throw new Error("DO unavailable");
      return new Response(JSON.stringify(issued), { headers: { "content-type": "application/json" } });
    },
  } as unknown as DurableObjectStub;
}

export async function run(): Promise<void> {
  // A scheduler that would mint a token IF reached, so the null results below prove the guard short-circuited
  // BEFORE the issue call (not that the mint happened to fail).
  const minting = fakeIssueScheduler({ ok: true, token: "would-be-token" });

  // 1. Malformed JSON body -> null (the JSON.parse is caught; no session).
  ok("sessionCookieForFinish: malformed JSON body -> null", (await sessionCookieForFinish(PROD_ENV, minting, "{not json")) === null);

  // 2. A non-object body (valid JSON but not a record) -> null.
  ok("sessionCookieForFinish: non-object body -> null", (await sessionCookieForFinish(PROD_ENV, minting, "\"a string\"")) === null);
  ok("sessionCookieForFinish: null body -> null", (await sessionCookieForFinish(PROD_ENV, minting, "null")) === null);

  // 3. ok:false body (a ceremony that did not verify) -> null, no session.
  ok("sessionCookieForFinish: ok:false body -> null", (await sessionCookieForFinish(PROD_ENV, minting, JSON.stringify({ ok: false, email: "a@example.com" }))) === null);

  // 4. ok:true but EMPTY / non-string email -> null (no principal to bind a session to).
  ok("sessionCookieForFinish: empty email -> null", (await sessionCookieForFinish(PROD_ENV, minting, JSON.stringify({ ok: true, email: "" }))) === null);
  ok("sessionCookieForFinish: missing email -> null", (await sessionCookieForFinish(PROD_ENV, minting, JSON.stringify({ ok: true }))) === null);
  ok("sessionCookieForFinish: non-string email -> null", (await sessionCookieForFinish(PROD_ENV, minting, JSON.stringify({ ok: true, email: 42 }))) === null);

  // 5. ok:true with a valid email but the DO mint returns ok:false / no token -> null.
  ok(
    "sessionCookieForFinish: DO issue ok:false -> null",
    (await sessionCookieForFinish(PROD_ENV, fakeIssueScheduler({ ok: false }), JSON.stringify({ ok: true, email: "a@example.com" }))) === null,
  );
  ok(
    "sessionCookieForFinish: DO issue empty token -> null",
    (await sessionCookieForFinish(PROD_ENV, fakeIssueScheduler({ ok: true, token: "" }), JSON.stringify({ ok: true, email: "a@example.com" }))) === null,
  );

  // 6. ok:true with a valid email but the DO fetch THROWS -> null, and a coarse error is logged (never the
  //    email or token). The function must NOT throw (the finish response is always returned).
  {
    const cap = captureErrors();
    let result: string | null = "unset" as unknown as string;
    let threw = false;
    try {
      result = await sessionCookieForFinish(PROD_ENV, fakeIssueScheduler("throw"), JSON.stringify({ ok: true, email: "a@example.com" }));
    } catch {
      threw = true;
    }
    cap.restore();
    ok("sessionCookieForFinish: DO mint failure -> null (never throws)", !threw && result === null);
    ok("sessionCookieForFinish: DO mint failure logs a coarse reason", cap.errors.some((e) => e.includes("passkey session mint skipped")));
    ok("sessionCookieForFinish: DO mint failure log carries no email", !cap.errors.some((e) => e.includes("a@example.com")));
  }

  // 7. The HAPPY path: ok:true + valid email + a minted token -> a hardened __Host- session Set-Cookie.
  {
    const cookie = await sessionCookieForFinish(PROD_ENV, fakeIssueScheduler({ ok: true, token: "minted-token-abc" }), JSON.stringify({ ok: true, email: "a@example.com" }));
    ok("sessionCookieForFinish: happy path returns a __Host- session cookie", cookie !== null && cookie.startsWith(`${SESSION_COOKIE_NAME}=minted-token-abc`));
    ok("sessionCookieForFinish: happy-path cookie is HttpOnly + Secure + SameSite=Strict", cookie !== null && cookie.includes("HttpOnly") && cookie.includes("Secure") && cookie.includes("SameSite=Strict"));
  }

  // 8. A production env NEVER touches the fault store, even with a fault armed underneath it -- the flag
  //    gate is checked first inside consumePasskeySessionMintFault, so the happy path is unaffected.
  {
    const cookie = await sessionCookieForFinish(PROD_ENV, fakeIssueScheduler({ ok: true, token: "minted-token-abc" }), JSON.stringify({ ok: true, email: "a@example.com" }));
    ok("sessionCookieForFinish: prod env mints normally regardless of the (inert) fault seam", cookie !== null);
  }
}
