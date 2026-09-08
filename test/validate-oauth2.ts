// Drive the GitHub-class OAuth2 (no id_token) adapter (src/admin/oauth2.ts) end to end with a STUB fetch
// returning GitHub-shaped responses. There is NO id_token and NO signature: trust derives from the
// TLS-protected token exchange, and identity from the /user, /user/emails, /user/teams + /user/orgs calls.
// Vectors: the happy path (subject from the IMMUTABLE numeric id, primary+verified email, org/team + org
// groups), a token-exchange non-200 reject, a private (null) email principal, a profile with no id reject,
// the login-is-never-the-subject guarantee, the basic-auth token-exchange style, and the group bounding.
// Every HTTP call goes through guardedOidcFetch (https-only, redirect:"manual" with a 3xx refused, size cap). No real network.
// Run: node test/validate-oauth2.ts
//
// Node 25 strip-types; Web Crypto only.

import { completeOauth2Login, buildOauth2AuthorizeUrl } from "../src/admin/oauth2.ts";
import type { Oauth2Connection } from "../src/admin/idpconn.ts";
import { oidcSubject } from "../src/admin/identity.ts";

let failures = 0;
function ok(label: string, cond: boolean): void {
  console.log(cond ? `  ok   ${label}` : `  FAIL ${label}`);
  if (!cond) failures++;
}

const API = "https://api.github.com";
const TOKEN_URL = "https://github.com/login/oauth/access_token";
const AUTHORIZE_URL = "https://github.com/login/oauth/authorize";
const PROFILE_URL = "https://api.github.com/user";
const EMAIL_URL = "https://api.github.com/user/emails";
const TEAMS_URL = "https://api.github.com/user/teams";
const ORGS_URL = "https://api.github.com/user/orgs";
const REDIRECT = "https://console.downpipes.io/admin/oauth2/callback/github";
const CLIENT = "Iv1.github-client";
const SECRET = "gh-secret-value";
const NUMERIC_ID = 583231; // GitHub's immutable user id (octocat's real id), a NUMBER on the wire
const LOGIN = "octocat"; // the RENAMEABLE handle that must NEVER become the subject

const baseConn: Oauth2Connection = {
  id: "github",
  kind: "oauth2",
  label: "GitHub",
  presetId: "github",
  enabled: true,
  authorizeUrl: AUTHORIZE_URL,
  tokenUrl: TOKEN_URL,
  tokenAuthStyle: "post_json",
  clientId: CLIENT,
  secretRef: { mode: "do-plaintext" },
  scopes: ["read:user", "user:email", "read:org"],
  apiBase: API,
  profileUrl: PROFILE_URL,
  subjectPath: "id",
  subjectPrefix: "github",
  emailUrl: EMAIL_URL,
  groupsUrls: [TEAMS_URL, ORGS_URL],
  pkce: "none",
  createdBy: "owner@example.com",
  createdAt: "2026-06-13T00:00:00.000Z",
};

// The expected stable subject + issuer for the base GitHub connection. issuer = subjectPrefix:apiBase;
// subject = oidc:<connId>|<issuer>|<immutable-numeric-id>.
const EXPECT_ISSUER = "github:https://api.github.com";
const EXPECT_SUBJECT = `oidc:github|${EXPECT_ISSUER}|${NUMERIC_ID}`;

// ---- stub GitHub fetch ----
// Each vector can override the per-endpoint status and body. The stub records every request (url + init)
// so the assertions can inspect the token-exchange body/headers and the Bearer + User-Agent on the API
// calls. Unrecognised URLs throw (a real test must wire every endpoint it exercises).
interface StubOpts {
  tokenStatus?: number;
  tokenBody?: string; // override the raw token-exchange body
  profileStatus?: number;
  profileBody?: unknown; // override the /user JSON value (use {} for "no id")
  emailStatus?: number;
  emailBody?: unknown; // override the /user/emails JSON value
  teamsBody?: unknown;
  orgsBody?: unknown;
  accessToken?: string;
}
interface Recorded {
  url: string;
  init: RequestInit;
}
function makeFetch(opts: StubOpts = {}): { fetch: typeof fetch; reqs: Recorded[] } {
  const reqs: Recorded[] = [];
  const accessToken = opts.accessToken ?? "gho_opaque_access_token";
  const fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    reqs.push({ url, init: init ?? {} });
    const json = (v: unknown, status = 200): Response => new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
    if (url === TOKEN_URL) {
      if (opts.tokenBody !== undefined) return new Response(opts.tokenBody, { status: opts.tokenStatus ?? 200, headers: { "content-type": "application/json" } });
      return json({ access_token: accessToken, token_type: "bearer", scope: "read:user,user:email" }, opts.tokenStatus ?? 200);
    }
    if (url === PROFILE_URL) {
      if (opts.profileBody !== undefined) return json(opts.profileBody, opts.profileStatus ?? 200);
      return json({ id: NUMERIC_ID, login: LOGIN, name: "The Octocat" }, opts.profileStatus ?? 200);
    }
    if (url === EMAIL_URL) {
      if (opts.emailBody !== undefined) return json(opts.emailBody, opts.emailStatus ?? 200);
      return json(
        [
          { email: "old@users.noreply.github.com", primary: false, verified: true },
          { email: "octocat@github.com", primary: true, verified: true },
          { email: "unverified@github.com", primary: false, verified: false },
        ],
        opts.emailStatus ?? 200,
      );
    }
    if (url === TEAMS_URL) {
      return json(opts.teamsBody ?? [{ slug: "engineers", organization: { login: "acme" } }]);
    }
    if (url === ORGS_URL) {
      return json(opts.orgsBody ?? [{ login: "acme" }]);
    }
    throw new Error(`unexpected fetch in test: ${url}`);
    // Cast via globalThis.fetch: inside this initializer the bare `fetch` resolves to the local const being
    // declared (a self-reference that would make it implicitly any), so name the global type explicitly.
  }) as typeof globalThis.fetch;
  return { fetch, reqs };
}

console.log("OAuth2 (GitHub-class) adapter\n");

// 1. Happy path -> a full principal.
{
  const { fetch, reqs } = makeFetch();
  const r = await completeOauth2Login(baseConn, { code: "the-code", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("completeOauth2Login succeeds on the GitHub shapes", r.ok === true);
  if (r.ok) {
    ok("  -> subject is oidc:<connId>|github:<apiBase>|<numericId> (the IMMUTABLE id)", r.principal.subject === EXPECT_SUBJECT);
    ok("  -> subject NEVER contains the renameable login", !r.principal.subject.includes(LOGIN));
    ok("  -> issuer == subjectPrefix:apiBase", r.principal.issuer === EXPECT_ISSUER);
    ok("  -> primary+verified email is chosen", r.principal.email === "octocat@github.com");
    ok("  -> emailVerified true for a verified primary", r.principal.emailVerified === true);
    ok("  -> groups are [\"org/team\", \"org\"]", JSON.stringify(r.principal.groups) === JSON.stringify(["acme/engineers", "acme"]));
  }
  // The token exchange went to the token URL with the right grant + post_json client auth.
  const tokenReq = reqs.find((q) => q.url === TOKEN_URL);
  ok("token exchange hit the token URL", tokenReq !== undefined);
  if (tokenReq) {
    const sent = new URLSearchParams((tokenReq.init.body as string) ?? "");
    ok("token exchange posts grant_type=authorization_code + code + redirect_uri + client_id", sent.get("grant_type") === "authorization_code" && sent.get("code") === "the-code" && sent.get("redirect_uri") === REDIRECT && sent.get("client_id") === CLIENT);
    ok("post_json puts the client_secret in the body", sent.get("client_secret") === SECRET);
    const headers = (tokenReq.init.headers ?? {}) as Record<string, string>;
    ok("token exchange asks for application/json", String(headers["accept"] ?? "").includes("application/json"));
    ok("post_json sends NO Authorization header", headers["authorization"] === undefined);
  }
  // Every API call carried the Bearer token + a User-Agent (GitHub rejects a UA-less request).
  const apiReq = reqs.find((q) => q.url === PROFILE_URL);
  ok("profile call hit the profile URL", apiReq !== undefined);
  if (apiReq) {
    const headers = (apiReq.init.headers ?? {}) as Record<string, string>;
    ok("profile call carries Authorization: Bearer <token>", headers["authorization"] === "Bearer gho_opaque_access_token");
    ok("profile call carries a User-Agent (GitHub requires one)", typeof headers["user-agent"] === "string" && headers["user-agent"].length > 0);
  }
  const teamsReq = reqs.find((q) => q.url === TEAMS_URL);
  if (teamsReq) {
    const headers = (teamsReq.init.headers ?? {}) as Record<string, string>;
    ok("groups call carries the Bearer token + User-Agent too", headers["authorization"] === "Bearer gho_opaque_access_token" && typeof headers["user-agent"] === "string");
  }
}

// 2. A token-exchange non-200 -> reject (no profile/email/group calls are made).
{
  const { fetch, reqs } = makeFetch({ tokenStatus: 401, tokenBody: JSON.stringify({ error: "bad_verification_code" }) });
  const r = await completeOauth2Login(baseConn, { code: "bad", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("a token-exchange non-200 rejects", r.ok === false);
  ok("  -> no API calls are made after a failed exchange", reqs.find((q) => q.url === PROFILE_URL) === undefined);
}

// 2b. GitHub's quirk: a failed exchange can return HTTP 200 with an `error` field and NO access_token.
{
  const { fetch } = makeFetch({ tokenBody: JSON.stringify({ error: "incorrect_client_credentials", error_description: "bad" }) });
  const r = await completeOauth2Login(baseConn, { code: "x", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("a 200 token response with no access_token rejects (GitHub error-in-200 quirk)", r.ok === false);
}

// 2c. Subject-collision guard: a NUMERIC id above 2^53 (a snowflake id, e.g. Discord ~1.7e17) loses precision
//     through String(), so two distinct accounts could fold to one subject and the second inherit the first's
//     role. The adapter REFUSES a non-safe-integer numeric id; the same values as STRINGS are accepted and
//     stay distinct.
{
  // 2 ** 53 and 2 ** 53 + 4, written as expressions because the digit literals this test first carried
  // (…993 and …995) themselves lose precision at parse and silently denote exactly these two values.
  // Both are non-safe integers, which is all the refusal arm needs.
  const r1 = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, makeFetch({ profileBody: { id: 2 ** 53, login: "a" } }).fetch);
  const r2 = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, makeFetch({ profileBody: { id: 2 ** 53 + 4, login: "b" } }).fetch);
  ok("a non-safe-integer numeric id is refused (no precision-loss subject collision)", r1.ok === false && r2.ok === false);
  const s1 = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, makeFetch({ profileBody: { id: "9007199254740993", login: "a" } }).fetch);
  const s2 = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, makeFetch({ profileBody: { id: "9007199254740995", login: "b" } }).fetch);
  ok("the same ids as STRINGS are accepted and do NOT collide", s1.ok === true && s2.ok === true && (s1.ok && s2.ok ? s1.principal.subject !== s2.principal.subject : false));
}

// 3. A private (no public/primary verified) email -> principal with email null.
{
  // GitHub returns 200 [] from /user/emails when the user has not granted user:email, or no primary
  // verified address exists. The principal still resolves (subject + groups), with email null.
  const { fetch } = makeFetch({ emailBody: [] });
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("a private email yields a principal with email null", r.ok === true && r.principal.email === null);
  ok("  -> emailVerified is false when no email", r.ok === true && r.principal.emailVerified === false);
  if (r.ok) ok("  -> subject is still the immutable id", r.principal.subject === EXPECT_SUBJECT);
}

// 3b. /user/emails returns a primary that is NOT verified -> email null (never trust an unverified address).
{
  const { fetch } = makeFetch({ emailBody: [{ email: "spoof@evil.com", primary: true, verified: false }] });
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("an unverified primary email is NOT surfaced (email null)", r.ok === true && r.principal.email === null && r.principal.emailVerified === false);
}

// 4. A profile with no id -> reject (we have nothing immutable to key the subject on).
{
  const { fetch } = makeFetch({ profileBody: { login: LOGIN, name: "no id here" } });
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("a profile with no id at subjectPath rejects (no immutable subject)", r.ok === false);
}

// 4b. The login must NEVER be used as the subject, even when the id is present alongside it.
{
  const { fetch } = makeFetch(); // id present AND login present
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("the login is NEVER the subject (id is used verbatim)", r.ok === true && r.principal.subject === oidcSubject("github", EXPECT_ISSUER, String(NUMERIC_ID)) && !r.principal.subject.includes(LOGIN));
}

// 5. post_form_basic puts the credentials in an Authorization: Basic header, not the body.
{
  const conn: Oauth2Connection = { ...baseConn, tokenAuthStyle: "post_form_basic" };
  const { fetch, reqs } = makeFetch();
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("post_form_basic still succeeds", r.ok === true);
  const tokenReq = reqs.find((q) => q.url === TOKEN_URL);
  if (tokenReq) {
    const headers = (tokenReq.init.headers ?? {}) as Record<string, string>;
    ok("post_form_basic uses Authorization: Basic base64(clientId:secret)", headers["authorization"] === `Basic ${btoa(`${CLIENT}:${SECRET}`)}`);
    ok("post_form_basic does NOT put the secret in the body", !new URLSearchParams((tokenReq.init.body as string) ?? "").has("client_secret"));
  }
}

// 6. PKCE: when conn.pkce === "supported" and a verifier is provided, it is sent in the exchange body.
{
  const conn: Oauth2Connection = { ...baseConn, pkce: "supported" };
  const { fetch, reqs } = makeFetch();
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, codeVerifier: "the-verifier", clientSecret: SECRET }, fetch);
  ok("pkce 'supported' + a provided verifier succeeds", r.ok === true);
  const tokenReq = reqs.find((q) => q.url === TOKEN_URL);
  if (tokenReq) {
    const sent = new URLSearchParams((tokenReq.init.body as string) ?? "");
    ok("the code_verifier is sent when pkce is supported", sent.get("code_verifier") === "the-verifier");
  }
  // And when pkce is "none", a verifier is NOT sent even if one is passed.
  const { fetch: f2, reqs: r2 } = makeFetch();
  await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, codeVerifier: "leaked", clientSecret: SECRET }, f2);
  const t2 = r2.find((q) => q.url === TOKEN_URL);
  if (t2) ok("the code_verifier is NOT sent when pkce is 'none'", !new URLSearchParams((t2.init.body as string) ?? "").has("code_verifier"));
}

// 7. Group extraction + bounding: dedupe across teams/orgs, cap, drop empty/over-long/control-char.
{
  // Overlapping org appears in both /user/orgs and (implicitly) as a team's org-prefixed slug; the org
  // login "acme" appears once, the "acme/engineers" team once, and a second org "beta" once. A blank slug,
  // a control-char slug and an over-256 slug are dropped.
  const longSlug = "z".repeat(300);
  const { fetch } = makeFetch({
    teamsBody: [
      { slug: "engineers", organization: { login: "acme" } },
      { slug: "engineers", organization: { login: "acme" } }, // exact duplicate
      { slug: "", organization: { login: "acme" } }, // empty slug -> dropped
      { slug: "badslug", organization: { login: "acme" } }, // control char -> dropped
      { slug: longSlug, organization: { login: "acme" } }, // over-256 combined -> dropped
    ],
    orgsBody: [{ login: "acme" }, { login: "beta" }, { login: "acme" }],
  });
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("groups dedupe across teams + orgs and drop empty/control/over-long", r.ok === true && JSON.stringify(r.principal.groups) === JSON.stringify(["acme/engineers", "acme", "beta"]));
}

// 8. honour explicit emailPath / emailVerifiedPath on a NON-GitHub shape (single object, not the array).
{
  // A generic OAuth2 provider whose profile already carries the email; emailUrl points back at the profile
  // and emailPath/emailVerifiedPath name the fields. (Here the email lives on /user itself.)
  const conn: Oauth2Connection = {
    ...baseConn,
    emailUrl: PROFILE_URL,
    emailPath: "email",
    emailVerifiedPath: "email_verified",
  };
  const { fetch } = makeFetch({ profileBody: { id: NUMERIC_ID, login: LOGIN, email: "person@corp.example", email_verified: true } });
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fetch);
  ok("explicit emailPath/emailVerifiedPath are honoured on a non-GitHub shape", r.ok === true && r.principal.email === "person@corp.example" && r.principal.emailVerified === true);
}

// 9. SSRF guard is in force: every call goes through guardedOidcFetch, which sets redirect:"manual" (a 3xx is
// handed back and hard-failed, never chased -- the 3xx-refusal proof itself lives in validate-oidc.ts).
{
  let sawRedirectManual = true;
  const probe = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    if (init?.redirect !== "manual") sawRedirectManual = false;
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    if (url === TOKEN_URL) return new Response(JSON.stringify({ access_token: "t" }), { status: 200, headers: { "content-type": "application/json" } });
    if (url === PROFILE_URL) return new Response(JSON.stringify({ id: NUMERIC_ID, login: LOGIN }), { status: 200, headers: { "content-type": "application/json" } });
    if (url === EMAIL_URL) return new Response(JSON.stringify([]), { status: 200, headers: { "content-type": "application/json" } });
    if (url === TEAMS_URL || url === ORGS_URL) return new Response(JSON.stringify([]), { status: 200, headers: { "content-type": "application/json" } });
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
  await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, probe);
  ok("every OAuth2 HTTP call sets redirect:'manual' (guardedOidcFetch, no redirect following)", sawRedirectManual);
}

// ---- per-endpoint controllable stub --------------------------------------------------------------
// A finer stub than makeFetch: each endpoint can be given an exact Response, made to THROW (a network
// fault or an SSRF screen failure surfaces this way through guardedOidcFetch), or left to a sensible
// default. It lets the vectors below drive the helper error paths (a thrown fetch, a non-200, a non-JSON
// body) on each of the token, profile, email and group endpoints independently.
type EndpointAnswer = Response | "throw" | "throw-non-error" | undefined;
interface FineOpts {
  token?: EndpointAnswer;
  profile?: EndpointAnswer;
  email?: EndpointAnswer;
  teams?: EndpointAnswer;
  orgs?: EndpointAnswer;
}
function jsonResp(v: unknown, status = 200): Response {
  return new Response(JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
}
function fineFetch(opts: FineOpts): typeof fetch {
  const defaults: Record<string, () => Response> = {
    [TOKEN_URL]: () => jsonResp({ access_token: "gho_opaque_access_token", token_type: "bearer" }),
    [PROFILE_URL]: () => jsonResp({ id: NUMERIC_ID, login: LOGIN, name: "The Octocat" }),
    [EMAIL_URL]: () => jsonResp([{ email: "octocat@github.com", primary: true, verified: true }]),
    [TEAMS_URL]: () => jsonResp([{ slug: "engineers", organization: { login: "acme" } }]),
    [ORGS_URL]: () => jsonResp([{ login: "acme" }]),
  };
  const pick: Record<string, EndpointAnswer> = {
    [TOKEN_URL]: opts.token,
    [PROFILE_URL]: opts.profile,
    [EMAIL_URL]: opts.email,
    [TEAMS_URL]: opts.teams,
    [ORGS_URL]: opts.orgs,
  };
  return (async (input: RequestInfo | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : (input as Request).url;
    const answer = pick[url];
    if (answer === "throw") throw new Error(`simulated network fault at ${url}`);
    // A fetch that rejects with a NON-Error value (a buggy polyfill / a raw reject). guardedJson's
    // `e instanceof Error ? e.message : "error"` must fall to the generic "error" string, never crash.
    if (answer === "throw-non-error") throw "raw-string-fault"; // eslint-disable-line no-throw-literal
    if (answer !== undefined) return answer;
    const def = defaults[url];
    if (def) return def();
    throw new Error(`unexpected fetch in test: ${url}`);
  }) as typeof fetch;
}

// 10. buildOauth2AuthorizeUrl: the authorize URL is assembled with the GitHub-class params, the scopes are
//     joined when present, and the PKCE challenge is attached ONLY when the connection opts in.
{
  const url = buildOauth2AuthorizeUrl(baseConn, { state: "st-123", redirectUri: REDIRECT });
  const q = new URL(url).searchParams;
  ok("authorize URL keeps the provider authorize host + path", url.startsWith(AUTHORIZE_URL));
  ok("authorize URL sets response_type=code + client_id + redirect_uri + state", q.get("response_type") === "code" && q.get("client_id") === CLIENT && q.get("redirect_uri") === REDIRECT && q.get("state") === "st-123");
  ok("authorize URL joins the configured scopes with a space", q.get("scope") === baseConn.scopes.join(" "));
  ok("a pkce 'none' connection omits the PKCE challenge even if one is passed", buildOauth2AuthorizeUrl(baseConn, { state: "s", challenge: "ch", redirectUri: REDIRECT }).includes("code_challenge") === false);

  // No scopes configured -> the scope param is omitted entirely (the scopes.length > 0 false branch).
  const noScopes: Oauth2Connection = { ...baseConn, scopes: [] };
  ok("an empty scopes list omits the scope param", new URL(buildOauth2AuthorizeUrl(noScopes, { state: "s", redirectUri: REDIRECT })).searchParams.has("scope") === false);

  // PKCE supported + a provided challenge -> the S256 challenge is attached.
  const pkceConn: Oauth2Connection = { ...baseConn, pkce: "supported" };
  const pq = new URL(buildOauth2AuthorizeUrl(pkceConn, { state: "s", challenge: "the-challenge", redirectUri: REDIRECT })).searchParams;
  ok("pkce 'supported' + a challenge attaches code_challenge + S256 method", pq.get("code_challenge") === "the-challenge" && pq.get("code_challenge_method") === "S256");
  // PKCE supported but NO challenge supplied -> still omitted (the challenge !== undefined false branch).
  ok("pkce 'supported' with NO challenge omits it (nothing to attach)", new URL(buildOauth2AuthorizeUrl(pkceConn, { state: "s", redirectUri: REDIRECT })).searchParams.has("code_challenge") === false);
}

// 11. post_json token auth with NO resolved client secret -> fail closed with the exact reason (we never
//     attempt a confidential exchange without the secret).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT }, fineFetch({}));
  ok("post_json with no client secret fails closed", r.ok === false);
  if (!r.ok) ok("  -> reason names the missing post_json secret", r.reason.includes("post_json token auth requires a resolved client secret"));
}

// 11b. post_form_basic token auth with NO resolved client secret -> the matching fail-closed reason.
{
  const conn: Oauth2Connection = { ...baseConn, tokenAuthStyle: "post_form_basic" };
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT }, fineFetch({}));
  ok("post_form_basic with no client secret fails closed", r.ok === false && (r.ok ? false : r.reason.includes("post_form_basic token auth requires a resolved client secret")));
}

// 12. The token endpoint THROWS (a network fault / SSRF screen) -> a clean "token endpoint fetch failed"
//     reason, never an exception out of completeOauth2Login.
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ token: "throw" }));
  ok("a throwing token endpoint is caught and rejected", r.ok === false && (r.ok ? false : r.reason.startsWith("token endpoint fetch failed:")));
}

// 12b. The token endpoint returns a NON-JSON body at 200 -> rejected as non-JSON (the JSON.parse catch).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ token: new Response("<html>not json</html>", { status: 200, headers: { "content-type": "text/html" } }) }));
  ok("a non-JSON token body is rejected", r.ok === false && (r.ok ? false : r.reason === "token endpoint returned non-JSON"));
}

// 12c. The token endpoint returns a 200 whose JSON is NOT an object (a bare JSON null) -> rejected (the
//      "token response is not an object" guard; null parses successfully but is not an object we can read).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ token: jsonResp(null) }));
  ok("a token body of JSON null is rejected (not an object)", r.ok === false && (r.ok ? false : r.reason === "token response is not an object"));
}

// 13. The profile fetch fails (a non-200 from the profile endpoint) -> the login rejects with the profile
//     reason prefixed (the !prof.ok branch + guardedJson's non-200 reason).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ profile: jsonResp({ error: "nope" }, 403) }));
  ok("a non-200 profile rejects the login", r.ok === false);
  if (!r.ok) ok("  -> reason is the prefixed profile failure (endpoint returned 403)", r.reason === "profile fetch: endpoint returned 403");
}

// 13b. The profile endpoint returns non-JSON -> guardedJson reports it and the login rejects.
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ profile: new Response("oops", { status: 200, headers: { "content-type": "text/plain" } }) }));
  ok("a non-JSON profile body rejects the login", r.ok === false && (r.ok ? false : r.reason === "profile fetch: endpoint returned non-JSON"));
}

// 13c. The profile endpoint THROWS -> guardedJson's fetch-failed catch, surfaced through the profile reason.
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ profile: "throw" }));
  ok("a throwing profile endpoint is caught and rejected", r.ok === false && (r.ok ? false : r.reason.startsWith("profile fetch: fetch failed:")));
}

// 13d. The profile carries an EMPTY-STRING id -> rejected (a string id passes the type gate but an empty
//      String() cannot key a subject).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ profile: jsonResp({ id: "", login: LOGIN }) }));
  ok("an empty-string profile id is rejected", r.ok === false && (r.ok ? false : r.reason === "profile id is empty"));
}

// 14. A failing EMAIL endpoint is NON-FATAL: the subject + groups still resolve and email stays null (the
//     em.ok false branch is taken, so resolveEmail is never reached and email remains null).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ email: jsonResp({}, 500) }));
  ok("a failing email endpoint does not fail the login", r.ok === true);
  if (r.ok) {
    ok("  -> email stays null when the email endpoint failed", r.principal.email === null && r.principal.emailVerified === false);
    ok("  -> the subject + groups still resolve", r.principal.subject === EXPECT_SUBJECT && JSON.stringify(r.principal.groups) === JSON.stringify(["acme/engineers", "acme"]));
  }
}

// 14b. The default (GitHub) email shape returns a NON-ARRAY 200 body (e.g. an object) -> email null (the
//      resolveEmail !Array.isArray branch; emailPath is unset so the array shape is expected).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ email: jsonResp({ not: "an array" }) }));
  ok("a non-array email body (GitHub shape) yields email null", r.ok === true && (r.ok ? r.principal.email === null && r.principal.emailVerified === false : false));
}

// 14c. The email array contains non-object entries (a bare string, null) before the real address; those are
//      skipped (the per-entry non-object continue) and the primary+verified entry is still found.
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ email: jsonResp(["not-an-object", null, { email: "real@github.com", primary: true, verified: true }]) }));
  ok("non-object email entries are skipped and the primary+verified address is still found", r.ok === true && (r.ok ? r.principal.email === "real@github.com" && r.principal.emailVerified === true : false));
}

// 15. emailPath set but the resolved address is an EMPTY/whitespace string -> email null (the addr empty
//     guard in the emailPath branch). The email endpoint is a dedicated single-object document here.
{
  const conn: Oauth2Connection = { ...baseConn, emailPath: "email", emailVerifiedPath: "email_verified" };
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ email: jsonResp({ email: "   ", email_verified: true }) }));
  ok("an empty/whitespace emailPath address yields email null", r.ok === true && (r.ok ? r.principal.email === null && r.principal.emailVerified === false : false));
}

// 15b. emailPath + emailVerifiedPath where the verified flag is NOT true -> email null (the verified false
//      branch of the ternary; never surface an address we cannot trust).
{
  const conn: Oauth2Connection = { ...baseConn, emailPath: "email", emailVerifiedPath: "email_verified" };
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ email: jsonResp({ email: "person@corp.example", email_verified: false }) }));
  ok("an emailPath address with verified !== true is dropped (email null)", r.ok === true && (r.ok ? r.principal.email === null && r.principal.emailVerified === false : false));
}

// 15c. emailPath set with NO emailVerifiedPath configured -> the provider is asserting the address, so it is
//      surfaced as verified (the no-verified-path branch). A leading/trailing space is trimmed off too.
{
  const conn: Oauth2Connection = { ...baseConn, emailPath: "email" };
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ email: jsonResp({ email: " trusted@corp.example " }) }));
  ok("emailPath with no emailVerifiedPath surfaces the trimmed address as verified", r.ok === true && (r.ok ? r.principal.email === "trusted@corp.example" && r.principal.emailVerified === true : false));
}

// 16. A connection with NO groupsUrls at all -> the principal simply carries no groups (the groupsUrls ??
//     [] empty-iteration path); email + subject still resolve.
{
  // Omit groupsUrls (baseConn sets it) to model a connection with none, rather than an explicit undefined
  // which exactOptionalPropertyTypes forbids for an optional field. The runtime shape is identical.
  const { groupsUrls: _noGroupsUrls, ...rest } = baseConn;
  const conn: Oauth2Connection = { ...rest };
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({}));
  ok("a connection with no groupsUrls carries an empty groups list", r.ok === true && (r.ok ? JSON.stringify(r.principal.groups) === "[]" : false));
}

// 16b. A group endpoint that fails (non-200) or returns a non-array contributes NOTHING (additive); the
//      other endpoint still folds its groups in.
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ teams: jsonResp({ error: "x" }, 500), orgs: jsonResp([{ login: "acme" }]) }));
  ok("a failing group endpoint contributes nothing, the other still folds in", r.ok === true && (r.ok ? JSON.stringify(r.principal.groups) === JSON.stringify(["acme"]) : false));
  // A 200 that is a JSON object rather than an array is likewise ignored.
  const r2 = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ teams: jsonResp({ slug: "not-in-an-array" }), orgs: jsonResp([{ login: "beta" }]) }));
  ok("a non-array group body is ignored, the other endpoint still folds in", r2.ok === true && (r2.ok ? JSON.stringify(r2.principal.groups) === JSON.stringify(["beta"]) : false));
}

// 16c. Group entries that are non-objects (a bare string, null) inside an array are skipped; a valid org
//      entry afterwards is still read (the per-entry non-object continue in resolveGroups).
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ teams: jsonResp([]), orgs: jsonResp(["str", null, { login: "gamma" }]) }));
  ok("non-object group entries are skipped, a valid org after them is still read", r.ok === true && (r.ok ? JSON.stringify(r.principal.groups) === JSON.stringify(["gamma"]) : false));
}

// 16d. The generic groupsPath shape: an entry that is NEITHER a team ({slug,organization}) NOR an org
//      ({login}) but carries a flat membership name at conn.groupsPath is read via that path.
{
  const conn: Oauth2Connection = { ...baseConn, groupsUrls: [ORGS_URL], groupsPath: "name" };
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ orgs: jsonResp([{ name: "platform-team" }, { name: "data-team" }]) }));
  ok("a generic entry is read via the configured groupsPath", r.ok === true && (r.ok ? JSON.stringify(r.principal.groups) === JSON.stringify(["platform-team", "data-team"]) : false));
}

// 17. Group cap behaviour: addGroup stops at GROUPS_MAX (200). A single endpoint returning 250 distinct
//     orgs yields exactly 200 groups, and the team/org break-on-cap path is exercised (addGroup returns
//     false at the cap so resolveGroups breaks out).
{
  const manyOrgs = Array.from({ length: 250 }, (_v, i) => ({ login: `org${i}` }));
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ teams: jsonResp([]), orgs: jsonResp(manyOrgs) }));
  ok("the groups list is capped at 200 even when the provider returns more", r.ok === true && (r.ok ? r.principal.groups.length === 200 : false));
  if (r.ok) ok("  -> the cap keeps the FIRST entries (org0 present, org249 dropped)", r.principal.groups.includes("org0") && !r.principal.groups.includes("org249"));
}

// 17b. Non-string group candidates (a numeric login / numeric slug) are dropped by addGroup's string gate;
//      a valid string entry afterwards is still kept.
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ teams: jsonResp([{ slug: 123, organization: { login: "acme" } }]), orgs: jsonResp([{ login: "kept-org" }]) }));
  // The numeric slug means the entry is not a team (slug not a string) and not an org (no string login on a
  // team-shaped entry), so it falls through and contributes nothing; the org endpoint's valid login is kept.
  ok("a non-string slug entry contributes nothing, a valid org login is kept", r.ok === true && (r.ok ? JSON.stringify(r.principal.groups) === JSON.stringify(["kept-org"]) : false));
}

// 17c. The cap is reached on the FIRST groups endpoint, so the SECOND endpoint is short-circuited before any
//      of its entries are read (the per-URL `out.length >= GROUPS_MAX break` at the top of the URL loop). The
//      first endpoint contributes exactly 200 teams; the second endpoint's distinct org is therefore never
//      folded in, proving the outer loop stopped rather than merely the inner one.
{
  const manyTeams = Array.from({ length: 220 }, (_v, i) => ({ slug: `team${i}`, organization: { login: "acme" } }));
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ teams: jsonResp(manyTeams), orgs: jsonResp([{ login: "never-reached-org" }]) }));
  ok("the cap reached on the first endpoint stops the whole fold", r.ok === true && (r.ok ? r.principal.groups.length === 200 : false));
  if (r.ok) ok("  -> the second endpoint is short-circuited (its org is never folded in)", !r.principal.groups.includes("never-reached-org") && r.principal.groups.includes("acme/team0"));
}

// 17d. The cap is reached while folding the TEAM shape specifically: a single teams endpoint returns more than
//      200 distinct teams, so addGroup returns false on the 200th push and the team branch breaks out (the
//      `if (!addGroup(...)) break` on the team path, distinct from the org-shape break exercised in 17).
{
  const manyTeams = Array.from({ length: 230 }, (_v, i) => ({ slug: `team${i}`, organization: { login: "acme" } }));
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ teams: jsonResp(manyTeams), orgs: jsonResp([]) }));
  ok("the team-shape fold breaks out exactly at the cap", r.ok === true && (r.ok ? r.principal.groups.length === 200 : false));
  if (r.ok) ok("  -> the cap keeps the first teams (team0 present, team200 dropped)", r.principal.groups.includes("acme/team0") && !r.principal.groups.includes("acme/team200"));
}

// 17e. The cap is reached while folding the GENERIC groupsPath shape: a configured groupsPath endpoint returns
//      more than 200 distinct flat names, so addGroup returns false on the 200th and the generic branch breaks
//      out (the `if (!addGroup(...)) break` on the groupsPath path).
{
  const conn: Oauth2Connection = { ...baseConn, groupsUrls: [ORGS_URL], groupsPath: "name" };
  const manyNames = Array.from({ length: 240 }, (_v, i) => ({ name: `flat-group-${i}` }));
  const r = await completeOauth2Login(conn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ orgs: jsonResp(manyNames) }));
  ok("the generic groupsPath fold breaks out exactly at the cap", r.ok === true && (r.ok ? r.principal.groups.length === 200 : false));
  if (r.ok) ok("  -> the cap keeps the first names (flat-group-0 present, flat-group-200 dropped)", r.principal.groups.includes("flat-group-0") && !r.principal.groups.includes("flat-group-200"));
}

// 18. A guardedJson fetch (here the profile call) rejects with a NON-Error value (a raw string throw from a
//     buggy polyfill). guardedJson's `e instanceof Error ? e.message : "error"` must fall to the generic
//     "error" string rather than crash, so the reason is the prefixed, fully-formed "fetch failed: error".
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ profile: "throw-non-error" }));
  ok("a profile fetch that throws a non-Error is caught with the generic reason", r.ok === false && (r.ok ? false : r.reason === "profile fetch: fetch failed: error"));
}

// 18b. The TOKEN exchange fetch rejects with a NON-Error value too: exchangeOauth2Code's own
//      `e instanceof Error ? e.message : "error"` must likewise fall to "error", giving the precise
//      "token endpoint fetch failed: error" reason and never an exception out of completeOauth2Login.
{
  const r = await completeOauth2Login(baseConn, { code: "c", redirectUri: REDIRECT, clientSecret: SECRET }, fineFetch({ token: "throw-non-error" }));
  ok("a token exchange that throws a non-Error is caught with the generic reason", r.ok === false && (r.ok ? false : r.reason === "token endpoint fetch failed: error"));
}

console.log("");
if (failures > 0) process.exitCode = 1;
if (failures > 0) {
  console.log(`OAUTH2 ADAPTER VECTORS: ${failures} FAILED`);
  process.exit(1);
}
console.log("OAUTH2 ADAPTER VECTORS PASS");
