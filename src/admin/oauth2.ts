// The native OAuth2 (no id_token) Relying Party adapter, for a GitHub-class provider. Unlike the OIDC flow
// (oidc.ts), there is NO signed id_token here: trust derives ENTIRELY from the TLS-protected token exchange
// (an opaque access_token the provider hands back over https), and identity from a userinfo call made WITH
// that token. We therefore NEVER verify a token signature (there is none) and NEVER call the id_token
// verifier; the access_token is opaque and is only ever used as a Bearer credential to GitHub's own API.
//
// The trust chain is: (1) exchange the authorization code at conn.tokenUrl over the SSRF-guarded fetch and
// obtain the opaque access_token; (2) GET the profile and read the IMMUTABLE id at conn.subjectPath (a
// number or a string) - NEVER the renameable login/username - and fold it into a stable, collision-proof
// subject via oidcSubject(conn.id, issuer, id); (3) optionally GET the email endpoint and surface ONLY a
// primary AND verified address (an unverified or non-primary address is never trusted, so it never gates a
// pending-invite bind upstream); (4) optionally GET the groups endpoints and bound the membership list with
// the SAME discipline as oidc.ts extractGroups (trim, drop empty/over-long/control-char, dedupe, cap). The
// issuer string is the synthetic conn.subjectPrefix + ":" + conn.apiBase (GHES isolation: a self-hosted
// GitHub Enterprise instance folds its own apiBase, so two installs never share a subject namespace).
//
// PURE/INJECTED: the network is the passed-in doFetch (the real global fetch in prod, a stub in the
// validator), and EVERY HTTP call goes through guardedOidcFetch (https-only, no redirect following,
// response size capped, host category screened by assertSafeFetchEndpoint). This module touches no storage;
// the DO owns the single-use state record, the redirectUri pinning, and resolving the client secret from
// its secretRef just-in-time. The clientSecret VALUE is passed in by the caller and never lives here.
//
// Node 25 strip-types + Workers compatible: Web Crypto + fetch only, no Node builtins, no enums.

import { GROUP_NAME_MAX, GROUPS_MAX } from "./groups-bounds.ts";
import { type ClaimDropTally, claimDropCounter } from "./posture-counters.ts";
import { oidcSubject } from "./identity.ts";
import type { Oauth2Connection } from "./idpconn.ts";
import { guardedOidcFetch } from "./oidc.ts";
import { oauthErrorMark, oauthErrorMarkFromBody } from "./sso-failure-class.ts";

// ---- bounds ------------------------------------------------------------------------------------
// Shared from groups-bounds.ts (the same limits on every IdP path): the most groups the engine carries from
// one login, and the max length of a single group string after trimming. The combined "<org>/<team>" or bare
// "<org>" entries are bounded by these.

// A User-Agent is MANDATORY for the GitHub REST API (it rejects a UA-less request with 403). We send a
// stable, honest identifier on every provider call. It carries no secret and is the same on every request.
const USER_AGENT = "downpipes-oauth2/1";

// buildOauth2AuthorizeUrl assembles the authorization URL for a no-id_token (GitHub-class) provider: the same
// authorization-code redirect as OIDC but with NO nonce (there is no id_token to bind one to) and the
// provider's own authorize endpoint + scopes. PKCE S256 is attached ONLY when the connection opts in
// (conn.pkce === "supported"); a confidential OAuth App (GitHub OAuth Apps do not support PKCE) omits the
// challenge and relies on the single-use state + the client secret for the flow's integrity. state is the
// single-use CSRF token stored server-side; redirectUri is the one pre-registered for this connId.
export function buildOauth2AuthorizeUrl(conn: Oauth2Connection, p: { state: string; challenge?: string; redirectUri: string }): string {
  const u = new URL(conn.authorizeUrl);
  const q = u.searchParams;
  q.set("response_type", "code");
  q.set("client_id", conn.clientId);
  q.set("redirect_uri", p.redirectUri);
  if (conn.scopes.length > 0) q.set("scope", conn.scopes.join(" "));
  q.set("state", p.state);
  if (conn.pkce === "supported" && p.challenge !== undefined) {
    q.set("code_challenge", p.challenge);
    q.set("code_challenge_method", "S256");
  }
  return u.toString();
}

export interface Oauth2Principal {
  subject: string; // oidc:<connId>|<issuer>|<immutable-id>; issuer is the synthetic subjectPrefix:apiBase
  email: string | null; // null when the provider asserted no PRIMARY+VERIFIED address (private email)
  emailVerified: boolean; // true only for a surfaced primary+verified address; gates pending-invite binding upstream
  groups: string[]; // bounded membership (org/team + org), deduped + capped
  // claimDrops: the CLOSED counter names of the group claims this provider asserted and the engine
  // bounded away (an over-long name, a control-char name, or every group past GROUPS_MAX). Diagnostic only: it
  // never affects the principal, the groups or the role. The DO callback bumps them into the admin-counter
  // aggregate; the dropped values themselves never leave the bounder.
  claimDrops?: string[];
  issuer: string; // conn.subjectPrefix + ":" + conn.apiBase
}

// getByPath resolves a dotted path (e.g. "organization.login") into an arbitrary JSON value. Mirrors
// oidc.ts getByPath: only own string keys are walked; a missing or non-object intermediate yields
// undefined. Used for the immutable-id path, the email path, and the per-entry group fields.
function getByPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const seg of path.split(".")) {
    if (typeof cur !== "object" || cur === null || Array.isArray(cur)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

// addGroup applies the SAME normalisation discipline as oidc.ts boundGroups to a single candidate group
// string and pushes it onto the accumulator if it survives: trim, drop empty, drop over GROUP_NAME_MAX,
// drop any name carrying an ASCII control character (0x00-0x1F or 0x7F), dedupe (first wins), cap at
// GROUPS_MAX. Returns false once the cap is reached so the caller can stop early. This bounds the
// customer's own provider data before it becomes a group->role lookup key, identically to the OIDC path.
// G271: `drops` is the bounded, redaction-safe tally. Every `return true` below is a group the provider
// asserted and this function is THROWING AWAY, and each one used to be silent. The dropped NAME never rides:
// the tally holds only closed counter names, added once per sign-in however many groups were dropped, so a
// provider asserting 300 over-long teams is one observation of "this provider's group names are over-length",
// not 300. Without it, "the user is in the right team and gets viewer" -- because the mapped team fell past
// GROUPS_MAX -- produced exactly the same (empty) evidence as a provider that asserted no teams at all.
function addGroup(raw: unknown, seen: Set<string>, out: string[], drops: ClaimDropTally): boolean {
  if (out.length >= GROUPS_MAX) {
    drops.add(claimDropCounter("oauth2", "groups-list-capped"));
    return false;
  }
  if (typeof raw !== "string") return true;
  const g = raw.trim();
  if (g.length === 0) return true;
  if (g.length > GROUP_NAME_MAX) {
    drops.add(claimDropCounter("oauth2", "group-overlength"));
    return true;
  }
  for (let i = 0; i < g.length; i++) {
    const c = g.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) {
      drops.add(claimDropCounter("oauth2", "group-control-char"));
      return true; // control char -> drop
    }
  }
  if (seen.has(g)) return true;
  seen.add(g);
  out.push(g);
  return out.length < GROUPS_MAX;
}

// guardedJson is the one JSON-over-guarded-fetch helper every step uses: it screens + fetches the URL
// (guardedOidcFetch: https-only, redirect:"manual" with a 3xx refused, size cap), requires a 200, and parses the body as JSON.
// It NEVER throws: a screen failure, a non-200, or a non-JSON body all resolve to a precise reason. headers
// are merged onto the Accept the helper always sets, so a caller adds the Authorization + User-Agent.
async function guardedJson(url: string, headers: Record<string, string>, doFetch: typeof fetch): Promise<{ ok: true; value: unknown } | { ok: false; reason: string }> {
  let resp: { status: number; bodyText: string };
  try {
    resp = await guardedOidcFetch(url, { method: "GET", headers: { accept: "application/json", ...headers } }, doFetch);
  } catch (e) {
    return { ok: false, reason: `fetch failed: ${e instanceof Error ? e.message : "error"}` };
  }
  if (resp.status !== 200) return { ok: false, reason: `endpoint returned ${resp.status}` };
  let value: unknown;
  try {
    value = JSON.parse(resp.bodyText);
  } catch {
    return { ok: false, reason: "endpoint returned non-JSON" };
  }
  return { ok: true, value };
}

// exchangeOauth2Code performs the authorization-code -> token exchange for a no-id_token provider. The body
// is x-www-form-urlencoded (grant_type=authorization_code, code, redirect_uri, client_id), the response is
// requested as application/json (GitHub defaults to a form-encoded body without this Accept), and the client
// authentication follows conn.tokenAuthStyle: "post_json" puts the client_secret in the body, while
// "post_form_basic" sends HTTP Basic Authorization: Basic base64(clientId:secret) and keeps the secret out
// of the body. The code_verifier is included ONLY when conn.pkce === "supported" and one was provided (a
// public-PKCE GitHub App), never otherwise. The returned access_token is OPAQUE - it is a Bearer credential
// only, never a verifiable token. GitHub's quirk of returning HTTP 200 with an `error` field and NO
// access_token is treated as a failure (the absence of access_token is the check). Returns the token or a
// precise reason; it never throws.
async function exchangeOauth2Code(
  conn: Oauth2Connection,
  params: { code: string; redirectUri: string; codeVerifier?: string; clientSecret?: string },
  doFetch: typeof fetch,
): Promise<{ ok: true; accessToken: string } | { ok: false; reason: string }> {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", params.code);
  body.set("redirect_uri", params.redirectUri);
  body.set("client_id", conn.clientId);
  if (conn.pkce === "supported" && params.codeVerifier !== undefined) body.set("code_verifier", params.codeVerifier);
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
  if (conn.tokenAuthStyle === "post_json") {
    if (params.clientSecret === undefined) return { ok: false, reason: "post_json token auth requires a resolved client secret" };
    body.set("client_secret", params.clientSecret);
  } else {
    // post_form_basic: HTTP Basic, secret kept out of the body.
    if (params.clientSecret === undefined) return { ok: false, reason: "post_form_basic token auth requires a resolved client secret" };
    headers.authorization = `Basic ${btoa(`${conn.clientId}:${params.clientSecret}`)}`;
  }
  let resp: { status: number; bodyText: string };
  try {
    resp = await guardedOidcFetch(conn.tokenUrl, { method: "POST", headers, body: body.toString() }, doFetch);
  } catch (e) {
    return { ok: false, reason: `token endpoint fetch failed: ${e instanceof Error ? e.message : "error"}` };
  }
  // Carry the provider's own RFC 6749 s5.2 `error` code (allowlisted to the closed spec vocabulary by
  // oauthErrorMarkFromBody, which discards the body it parsed it out of), so an expired / rotated client secret
  // reads as invalid_client rather than as an anonymous "token endpoint returned 401".
  if (resp.status !== 200) return { ok: false, reason: `token endpoint returned ${resp.status}${oauthErrorMarkFromBody(resp.bodyText)}` };
  let json: unknown;
  try {
    json = JSON.parse(resp.bodyText);
  } catch {
    return { ok: false, reason: "token endpoint returned non-JSON" };
  }
  if (typeof json !== "object" || json === null) return { ok: false, reason: "token response is not an object" };
  const accessToken = (json as Record<string, unknown>).access_token;
  // The absence of access_token is the failure signal (covers both a non-error empty body AND GitHub's
  // HTTP-200-with-error quirk, where `error`/`error_description` are present and access_token is not).
  if (typeof accessToken !== "string" || accessToken.length === 0) {
    return { ok: false, reason: `token response carried no access_token${oauthErrorMark((json as Record<string, unknown>).error)}` };
  }
  return { ok: true, accessToken };
}

// resolveEmail surfaces the user's email, honestly null when none is trustworthy. Two shapes are
// supported, chosen by whether conn.emailPath is set:
//  - GitHub default (conn.emailPath unset): conn.emailUrl returns an ARRAY of {email,primary,verified};
//    we surface ONLY the entry that is BOTH primary AND verified (an unverified or non-primary address is
//    never trusted), else null.
//  - generic (conn.emailPath set): the email endpoint returns a single object (it may even be the profile
//    itself); we read conn.emailPath for the address and conn.emailVerifiedPath (when set) for the verified
//    flag, surfacing the address only when that flag is the JSON boolean true (or when no verified path is
//    configured at all, in which case the provider is asserting the address is usable). A non-string
//    address yields null.
// email is OPTIONAL: with no conn.emailUrl the function is not called and the principal carries email null.
function resolveEmail(conn: Oauth2Connection, doc: unknown): { email: string | null; emailVerified: boolean } {
  if (conn.emailPath !== undefined) {
    const addr = getByPath(doc, conn.emailPath);
    if (typeof addr !== "string" || addr.trim().length === 0) return { email: null, emailVerified: false };
    if (conn.emailVerifiedPath !== undefined) {
      const verified = getByPath(doc, conn.emailVerifiedPath) === true;
      // Only a verified address is surfaced; an unverified one is dropped entirely (never carry an
      // address we cannot trust, since the pending-invite bind upstream keys on email + emailVerified).
      return verified ? { email: addr.trim(), emailVerified: true } : { email: null, emailVerified: false };
    }
    // No verified path configured: the provider is asserting the address itself; surface it as verified.
    return { email: addr.trim(), emailVerified: true };
  }
  // GitHub /user/emails shape: an array of {email, primary, verified}. Pick the primary+verified entry.
  if (!Array.isArray(doc)) return { email: null, emailVerified: false };
  for (const entry of doc) {
    if (typeof entry !== "object" || entry === null) continue;
    const rec = entry as Record<string, unknown>;
    if (rec.primary === true && rec.verified === true && typeof rec.email === "string" && rec.email.trim().length > 0) {
      return { email: (rec.email as string).trim(), emailVerified: true };
    }
  }
  return { email: null, emailVerified: false };
}

// resolveGroups folds every conn.groupsUrls endpoint into one bounded membership list. Two GitHub shapes
// are recognised per endpoint (chosen by entry shape, not URL): a team entry {slug, organization:{login}}
// becomes "<org-login>/<team-slug>", and an org entry {login} becomes the bare "<org-login>". A configured
// conn.groupsPath, when set, also reads that dotted path off each entry as an additional candidate (for a
// generic provider whose membership is a flat list). The combined list is bounded by addGroup (trim, drop
// empty/over-long/control-char, dedupe, cap GROUPS_MAX). A non-200 / non-array endpoint contributes
// nothing (groups are additive; a single failing membership endpoint never fails the whole login). With no
// conn.groupsUrls the principal simply carries no groups.
async function resolveGroups(conn: Oauth2Connection, authHeaders: Record<string, string>, doFetch: typeof fetch, drops: ClaimDropTally): Promise<string[]> {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const url of conn.groupsUrls ?? []) {
    // G271: the cap stops the walk here too, so a whole membership endpoint can go unread. Same fact, same name.
    if (out.length >= GROUPS_MAX) {
      drops.add(claimDropCounter("oauth2", "groups-list-capped"));
      break;
    }
    const res = await guardedJson(url, authHeaders, doFetch);
    if (!res.ok || !Array.isArray(res.value)) continue; // additive: a failing endpoint contributes nothing
    for (const entry of res.value) {
      if (out.length >= GROUPS_MAX) {
        drops.add(claimDropCounter("oauth2", "groups-list-capped"));
        break;
      }
      if (typeof entry !== "object" || entry === null) continue;
      const rec = entry as Record<string, unknown>;
      // Team shape: {slug, organization:{login}} -> "<org>/<team>". Both halves must be present and
      // non-empty after trimming; an empty slug or org would otherwise yield a malformed "<org>/" or
      // "/<team>" group that addGroup's combined-string check could not catch (it sees a non-empty join).
      const slug = rec.slug;
      const orgLogin = getByPath(rec, "organization.login");
      if (typeof slug === "string" && typeof orgLogin === "string") {
        const s = slug.trim();
        const o = orgLogin.trim();
        if (s.length > 0 && o.length > 0) {
          // G271: NO `break` on a full list. addGroup returns false the moment the push FILLS the list, and
          // breaking here skipped the cap check at the top of the loop -- so 260 teams capped at 200 and
          // recorded nothing at all, which is the gap's own headline ticket. Falling through to the next
          // iteration lets the top-of-loop guard see that entries REMAIN and record the drop. When the list
          // fills exactly and no entry remains, nothing was dropped and nothing is recorded: no false signal.
          addGroup(`${o}/${s}`, seen, out, drops);
        }
        continue;
      }
      // Org shape: {login} -> "<org>".
      const login = rec.login;
      if (typeof login === "string") {
        addGroup(login, seen, out, drops);
        continue;
      }
      // Generic shape: an explicit groupsPath off the entry (e.g. a flat membership name).
      //
      // NO `break` here either. The team and org
      // branches above had their break removed; this one kept it, and it is the branch a GENERIC provider (the
      // documented hatch for a flat membership list, idpconn-validators.ts validates conn.groupsPath as a live
      // connection field) walks. addGroup returns false the moment the push FILLS the list, WITHOUT recording a
      // drop, and breaking on that skipped the top-of-loop cap guard -- the sole producer of
      // claim-drop-oauth2-groups-list-capped on this walk. So 260 asserted groups capped at 200 recorded nothing
      // at all, byte-identical to an IdP that asserted no groups: the gap's own headline ticket ("the user is in
      // the right group and gets viewer") producing the same empty row as "your IdP sent us nothing". Falling
      // through lets the top-of-loop guard see that entries REMAIN and record the drop; when the list fills
      // exactly and no entry remains, nothing was dropped and nothing is recorded.
      if (conn.groupsPath !== undefined) {
        const v = getByPath(rec, conn.groupsPath);
        if (typeof v === "string") addGroup(v, seen, out, drops);
      }
    }
  }
  return out;
}

// completeOauth2Login is the callback-side orchestrator for a GitHub-class OAuth2 provider. It NEVER
// verifies a token signature and NEVER calls the id_token verifier (there is no id_token): trust is the
// TLS-protected exchange, identity is the userinfo call. Steps:
//   1. exchange the code at conn.tokenUrl over guardedOidcFetch -> opaque access_token (per tokenAuthStyle);
//   2. GET conn.profileUrl with Authorization: Bearer <token> + User-Agent; read the IMMUTABLE id at
//      conn.subjectPath (number or string -> String()); subject = oidcSubject(conn.id, issuer, String(id)),
//      where issuer = conn.subjectPrefix + ":" + conn.apiBase; the renameable login is NEVER the subject;
//   3. email (optional): GET conn.emailUrl and surface only a primary+verified (GitHub) / path-driven
//      (generic) address, else null;
//   4. groups (optional): GET each conn.groupsUrls, fold GitHub team/org shapes into "<org>/<team>" + "<org>",
//      bound the combined list (cap 200, trim, drop empty/over-256/control-char, dedupe).
// Every HTTP call goes through guardedOidcFetch. The clientSecret VALUE is passed in by the caller (resolved
// just-in-time from secretRef) and never logged. Returns the principal or a precise reason; it never throws.
//
// CALLER (DO callback route) OBLIGATIONS, mirroring completeOidcLogin's: consume the single-use state
// record ATOMICALLY (delete-before-exchange) and reject a missing/replayed state; pass redirectUri == the
// one pre-registered for this connId; pass the codeVerifier FROM that record (never from the request) when
// PKCE is in use; resolve clientSecret just-in-time from secretRef and never log it. There is no nonce and
// no id_token to bind here; the state record IS the CSRF/replay defence for this flow.
export async function completeOauth2Login(
  conn: Oauth2Connection,
  params: { code: string; redirectUri: string; codeVerifier?: string; clientSecret?: string },
  doFetch: typeof fetch,
): Promise<{ ok: true; principal: Oauth2Principal } | { ok: false; reason: string }> {
  // 1. token exchange (opaque access_token; NO signature verification).
  const ex = await exchangeOauth2Code(conn, params, doFetch);
  if (!ex.ok) return ex;
  // The Authorization + User-Agent every provider API call carries. The access_token is used ONLY as a
  // Bearer credential against the provider's own API; it is never decoded or verified.
  const authHeaders: Record<string, string> = { authorization: `Bearer ${ex.accessToken}`, "user-agent": USER_AGENT };

  // 2. profile -> the IMMUTABLE id (never the login).
  const prof = await guardedJson(conn.profileUrl, authHeaders, doFetch);
  if (!prof.ok) return { ok: false, reason: `profile fetch: ${prof.reason}` };
  const rawId = getByPath(prof.value, conn.subjectPath);
  // The immutable id is a number (GitHub) or a string (some providers); anything else (absent, object,
  // boolean) means we have no stable identifier and MUST refuse - we will not key a subject on a mutable
  // field. String(id) is the verbatim fold; the login/username is never consulted.
  if (typeof rawId !== "number" && typeof rawId !== "string") return { ok: false, reason: `profile carried no immutable id at "${conn.subjectPath}"` };
  // A JS number above 2^53 (a snowflake id, e.g. Discord ~1.7e17) loses precision through String(), so two
  // distinct accounts could fold to ONE subject and the second to authenticate would inherit the first's
  // bound role. Refuse a non-safe-integer (also catches float/exponential) numeric id; such a provider MUST
  // emit the id as a STRING (the generic-oauth2 hatch documents this). github.com ids are ~10^8, in range.
  if (typeof rawId === "number" && !Number.isSafeInteger(rawId)) return { ok: false, reason: "profile id is not a safe integer; configure the provider to emit the id as a string" };
  const id = String(rawId);
  if (id.length === 0) return { ok: false, reason: "profile id is empty" };
  const issuer = `${conn.subjectPrefix}:${conn.apiBase}`;
  const subject = oidcSubject(conn.id, issuer, id);

  // 3. email (optional; honestly null when none is trustworthy).
  let email: string | null = null;
  let emailVerified = false;
  if (conn.emailUrl !== undefined) {
    const em = await guardedJson(conn.emailUrl, authHeaders, doFetch);
    if (em.ok) {
      const r = resolveEmail(conn, em.value);
      email = r.email;
      emailVerified = r.emailVerified;
    }
    // A failing email endpoint is non-fatal: the address is optional, so we leave email null rather than
    // failing the whole login (the subject + groups still resolve, and email gates only invite binding).
  }

  // 4. groups (optional; additive + bounded).
  // G271: the tally the bounders fill as they drop. The DO's shared IdP-callback recorder already reads
  // principal.claimDrops (it has done since the OIDC path landed) and bumps each closed name into the admin
  // counters; this path simply never gave it anything to read, so the guard was permanently false and the
  // OAuth2 front door was the one live interactive sign-in kind that recorded nothing at all.
  const drops: ClaimDropTally = new Set<string>();
  const groups = await resolveGroups(conn, authHeaders, doFetch, drops);

  return { ok: true, principal: { subject, email, emailVerified, groups, issuer, ...(drops.size > 0 ? { claimDrops: [...drops] } : {}) } };
}
