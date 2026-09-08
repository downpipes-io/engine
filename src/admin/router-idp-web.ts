// router-idp-web.ts -- the PRE-AUTH native external-IdP web edge: the OIDC sign-in flow (providers / start
// / callback) and the SAML 2.0 SP flow (metadata / start / the cross-origin ACS POST), plus their __Host-
// txn cookies, the relative-only returnTo guard and the generic no-oracle failure redirect. These run
// BEFORE the main authorise() gate.
import type { Env } from "../env.d.ts";
import { log } from "../log.ts";
import { bumpAdminCounter } from "./diag-counters.ts";
import { recordDiagWrite } from "./diag-writer.ts";
import { authRateLimited } from "./router-core.ts";
import { type AdminRuntime, doURL, recordAuthSignalEdge, schedulerStub } from "./router-helpers.ts";
import { routeSignInContextAlert } from "./router-notify.ts";
import { sessionSetCookie } from "./session.ts";
import { classifySsoStartFailure, classifySsoSubCode, idpErrorSignalName, ssoEdgeSignalName, ssoSubSignalName } from "./sso-failure-class.ts";



// IDP_TXN_COOKIE_MAX_AGE_S is the lifetime (10 minutes, in whole seconds) of the short-TTL login-CSRF /
// fixation binding cookie set by both the OIDC and SAML start flows. SAFE_RETURN_TO_MAX_LENGTH is the
// maximum accepted length of a relative-only returnTo path before safeReturnTo falls back to "/".
const IDP_TXN_COOKIE_MAX_AGE_S = 600;
const SAFE_RETURN_TO_MAX_LENGTH = 512;

// fireInBackground: see router-identity.ts's identical helper. This
// whole file is PRE-AUTH (like router-auth-flow.ts's handlePasskey), so runtime is threaded as a plain
// parameter down the call chain rather than read off a RouterCtx, which does not exist yet at this point.
function fireInBackground(runtime: AdminRuntime | undefined, task: Promise<unknown>): void {
  if (runtime?.waitUntil) runtime.waitUntil(task);
  else void task;
}


// ==== Native external-IdP (OIDC) sign-in flow (pre-auth web edge) ==========================================

// OIDC_TXN_COOKIE is the short-TTL login-CSRF / fixation binding: /start drops a high-entropy txnId here and
// the DO's callback cross-checks it against the single-use state record's txnId, so a forged callback for a
// login the victim never started is refused. It is __Host- (pinned to this exact host over HTTPS, no Domain)
// and SameSite=Lax NOT Strict: the callback is a top-level GET navigation the IdP triggers from ITS origin, so
// a Strict cookie would not be sent on the return and the bind would be lost; Lax IS sent on a top-level
// cross-site GET, which is exactly this case (and no weaker - the value is single-use and DO-cross-checked).
export const OIDC_TXN_COOKIE = "__Host-downpipes_oidc_txn";


export function oidcTxnSetCookie(txnId: string): string {
  return `${OIDC_TXN_COOKIE}=${txnId}; Path=/; Max-Age=${IDP_TXN_COOKIE_MAX_AGE_S}; HttpOnly; Secure; SameSite=Lax`;
}

export function oidcTxnClearCookie(): string {
  return `${OIDC_TXN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

export function readOidcTxnCookie(req: Request): string | null {
  const header = req.headers.get("cookie");
  if (header === null) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    if (part.slice(0, eq).trim() !== OIDC_TXN_COOKIE) continue;
    const v = part.slice(eq + 1).trim();
    return v.length > 0 ? v : null;
  }
  return null;
}


// SAML_TXN_COOKIE is the SAML SP-initiated browser-binding cookie (the analogue of OIDC_TXN_COOKIE): /start drops
// the DO-minted browserBind value here and the ACS requires it to match the value stored in the consumed
// single-use request record before a session is minted, closing forced-login / session-fixation (an
// attacker-captured assertion replayed into a victim's browser carries no matching cookie).
//
// SameSite=None; Secure (NOT Lax, the OIDC analogue above). This is the load-bearing distinction from OIDC: the
// SAML HTTP-POST binding returns the assertion as an auto-submitting FORM POST from the IdP's origin to our ACS,
// a CROSS-SITE POST. A browser does NOT send a Lax (or Strict) cookie on a cross-site POST, only on a top-level
// cross-site GET; the OIDC callback is such a GET so Lax is correct there, but a Lax SAML cookie would arrive
// empty at the ACS and the browser-binding check would always fail (SAML SSO would be non-functional). None is
// required so the cookie rides that cross-site POST, and it is safe: the value is single-use, HttpOnly and
// cross-checked at the ACS against the consumed request record inside the DO, so widening SameSite does not
// weaken the fixation / replay defence (an attacker still cannot read or forge a matching browserBind). The
// __Host- prefix keeps it pinned to this exact host over HTTPS with no Domain.
export const SAML_TXN_COOKIE = "__Host-downpipes_saml_txn";

export function samlTxnSetCookie(v: string): string {
  return `${SAML_TXN_COOKIE}=${v}; Path=/; Max-Age=${IDP_TXN_COOKIE_MAX_AGE_S}; HttpOnly; Secure; SameSite=None`;
}

export function samlTxnClearCookie(): string {
  return `${SAML_TXN_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=None`;
}

export function readSamlTxnCookie(req: Request): string | null {
  const header = req.headers.get("cookie");
  if (header === null) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    if (part.slice(0, eq).trim() !== SAML_TXN_COOKIE) continue;
    const v = part.slice(eq + 1).trim();
    return v.length > 0 ? v : null;
  }
  return null;
}


// safeReturnTo enforces a RELATIVE-only, same-origin landing path (open-redirect + code-leak defence): only a
// value beginning with a single "/" (never "//" or "/\\", which a browser can read as a protocol-relative or
// backslash-host URL to a FOREIGN origin) and carrying no control characters or backslashes, length-capped, is
// accepted; anything else falls back to "/". The callback 302 also carries Referrer-Policy: no-referrer, so the
// authorization code never leaks via the Referer even to the trusted landing.
export function safeReturnTo(raw: string | null | undefined): string {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > SAFE_RETURN_TO_MAX_LENGTH) return "/";
  if (raw[0] !== "/" || raw[1] === "/" || raw[1] === "\\") return "/";
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || raw[i] === "\\") return "/";
  }
  return raw;
}


// recordSsoSubCause (G009 / G018) counts the SUB-CAUSE of a failed interactive sign-in in the bounded auth-signal
// aggregate. The DO's callback / ACS already classifies the failure to one of the 10 coarse SSO_FAIL_CODES, which
// name the STAGE that refused but not the CAUSE the operator has to fix; the DO also RETURNS its free-text reason
// to this edge, where until now it was simply dropped on the floor. So the sub-cause is classified HERE, at the
// last point that sees the reason: classifySsoSubCode reads it TRANSIENTLY, selects one member of the closed
// SSO_SUB_CODES vocabulary, and the reason is discarded -- only the closed `sso-sub-*` name is ever recorded
// (the DO drops any name outside AUTH_SIGNAL_NAMES, which is the redaction boundary). It rides the CHECKED
// diag-writer, so a sub-cause write DROPPED during a DO outage is itself counted in droppedWrites rather than
// vanishing. Fire-and-forget: the user's generic failure redirect is unchanged and is never delayed.
function recordSsoSubCause(scheduler: DurableObjectStub, reason: unknown, runtime?: AdminRuntime): void {
  const name = ssoSubSignalName(classifySsoSubCode(typeof reason === "string" ? reason : ""));
  const write = recordDiagWrite(scheduler, "auth-signal", () =>
    scheduler.fetch(doURL("/auth-signal"), { method: "POST", body: JSON.stringify({ name }), headers: { "content-type": "application/json" } }),
  );
  fireInBackground(runtime, write);
}

// oidcFailRedirect is the GENERIC sign-in-failure landing (no oracle): a 302 to the console sign-in page with a
// coarse ?oidc=failed flag, carrying NO detail of which check failed. On the callback path it also clears the
// txn cookie. Referrer-Policy: no-referrer so no query (a leaked code/state) rides the Referer onward.
export function oidcFailRedirect(consoleOrigin: string, clearTxn: boolean = false): Response {
  const headers = new Headers({ location: `${consoleOrigin}/?oidc=failed`, "referrer-policy": "no-referrer", "cache-control": "no-store" });
  if (clearTxn) headers.append("set-cookie", oidcTxnClearCookie());
  return new Response(null, { status: 302, headers });
}


// handleSaml is the PRE-AUTH native-SAML SP flow (the analogue of handleOidc). Three routes, all under
// /admin/saml/*:
//   GET  metadata/<connId>  the SP EntityDescriptor (public; the customer uploads it to their IdP).
//   GET  start/<connId>     the DO mints the AuthnRequest + RelayState record; 302 to the IdP SSO URL.
//   POST acs/<connId>       the IdP's cross-origin form POST (SAMLResponse + RelayState); the DO consumes the
//                           single-use RelayState, verifies the signed assertion (pinned cert), mints the v3
//                           saml session; set the cookie + 302 to the relative-only returnTo.
// The acsUrl is built from CONSOLE_ORIGIN (the canonical public host the AuthnRequest declares + the assertion
// Recipient/Destination is checked against), never the request host. Every failure is GENERIC (oidcFailRedirect).
export async function handleSaml(req: Request, env: Env, sub: string, runtime?: AdminRuntime): Promise<Response> {
  const scheduler = schedulerStub(env);
  const consoleOrigin = typeof env.CONSOLE_ORIGIN === "string" ? env.CONSOLE_ORIGIN.replace(/\/+$/, "") : "";
  // PER-IP pre-throttle (the same authRateLimited ceremony limiter as /admin/auth/*, V2.4.1): this whole
  // surface is unauthenticated by necessity and start/acs each cost a DO round trip (start also a live
  // outbound fetch to the customer's real IdP for discovery-less setups), so an unthrottled flood is a
  // CPU-DoS + third-party-amplification vector. Checked PER MATCHED BRANCH, after the method+sub match but
  // before the branch's handler, so an unmatched sub-path stays a cheap plain 404 with no DO round trip.
  if (req.method === "GET" && sub.startsWith("metadata/")) {
    const authLimited = await authRateLimited(scheduler, req, runtime);
    if (authLimited) return authLimited;
    return handleSamlMetadata(scheduler, consoleOrigin, sub.slice("metadata/".length), runtime);
  }
  if (req.method === "GET" && sub.startsWith("start/")) {
    const authLimited = await authRateLimited(scheduler, req, runtime);
    if (authLimited) return authLimited;
    return handleSamlStart(req, scheduler, consoleOrigin, sub.slice("start/".length));
  }
  if (req.method === "POST" && sub.startsWith("acs/")) {
    const authLimited = await authRateLimited(scheduler, req, runtime);
    if (authLimited) return authLimited;
    return handleSamlAcs(req, env, scheduler, consoleOrigin, sub.slice("acs/".length), runtime);
  }
  return new Response("not found", { status: 404 });
}

// handleSamlMetadata serves GET metadata/<connId>: the SP EntityDescriptor (public). A missing connection or
// a DO that cannot render is a 404; a DO hiccup is a 503. The acsUrl is built from CONSOLE_ORIGIN.
async function handleSamlMetadata(scheduler: DurableObjectStub, consoleOrigin: string, connId: string, runtime?: AdminRuntime): Promise<Response> {
  const acsUrl = `${consoleOrigin}/admin/saml/acs/${connId}`;
  try {
    const resp = await scheduler.fetch(doURL("/idp/saml/metadata"), { method: "POST", body: JSON.stringify({ connId, acsUrl }), headers: { "content-type": "application/json" } });
    const out = (await resp.json()) as { ok?: boolean; metadata?: string };
    if (out.ok !== true || typeof out.metadata !== "string") {
      // G116: "our IdP cannot import your SP metadata URL" left no server-side evidence at all.
      fireInBackground(runtime, recordAuthSignalEdge(scheduler, ssoEdgeSignalName("edge-metadata-unavailable")));
      return new Response("not found", { status: 404 });
    }
    return new Response(out.metadata, { status: 200, headers: { "content-type": "application/samlmetadata+xml; charset=utf-8", "cache-control": "no-store" } });
  } catch {
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, ssoEdgeSignalName("edge-metadata-unavailable")));
    return new Response("metadata unavailable", { status: 503 });
  }
}

// handleSamlStart serves GET start/<connId>: the DO mints the AuthnRequest + RelayState record; 302 to the
// IdP SSO URL with the browser-binding cookie. Any non-ok shape or DO hiccup is a generic failure redirect.
async function handleSamlStart(req: Request, scheduler: DurableObjectStub, consoleOrigin: string, connId: string): Promise<Response> {
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo"));
  const acsUrl = `${consoleOrigin}/admin/saml/acs/${connId}`;
  try {
    const resp = await scheduler.fetch(doURL("/idp/saml/start"), { method: "POST", body: JSON.stringify({ connId, returnTo, acsUrl }), headers: { "content-type": "application/json" } });
    const out = (await resp.json()) as { ok?: boolean; redirectUrl?: string; browserBind?: string };
    if (out.ok !== true || typeof out.redirectUrl !== "string" || typeof out.browserBind !== "string") return oidcFailRedirect(consoleOrigin);
    // Set the SAML browser-binding cookie (forced-login defence) alongside the 302 to the IdP SSO URL.
    return new Response(null, { status: 302, headers: { location: out.redirectUrl, "set-cookie": samlTxnSetCookie(out.browserBind), "referrer-policy": "no-referrer", "cache-control": "no-store" } });
  } catch {
    return oidcFailRedirect(consoleOrigin);
  }
}

// handleSamlAcs serves POST acs/<connId>: the IdP's cross-origin form POST. The DO consumes the single-use
// RelayState, verifies the signed assertion (pinned cert) and mints the v3 saml session; set the cookie + 302
// to the relative-only returnTo. Every failure is a generic redirect (no oracle).
async function handleSamlAcs(req: Request, env: Env, scheduler: DurableObjectStub, consoleOrigin: string, connId: string, runtime?: AdminRuntime): Promise<Response> {
  const acsUrl = `${consoleOrigin}/admin/saml/acs/${connId}`;
  let samlResponse = "";
  let relayState = "";
  try {
    // The HTTP-POST binding sends application/x-www-form-urlencoded; URLSearchParams decodes the percent-encoded
    // base64 (the IdP form-encodes the + and = of the standard base64, which decode back here).
    const form = new URLSearchParams(await req.text());
    samlResponse = form.get("SAMLResponse") ?? "";
    relayState = form.get("RelayState") ?? "";
  } catch {
    return oidcFailRedirect(consoleOrigin, false);
  }
  if (samlResponse.length === 0 || relayState.length === 0) {
    // G116: the cross-origin form POST arrived without an assertion (or without the server-minted RelayState):
    // a proxy mangled it, or it is not an ACS POST at all. It never becomes a DO request, so nothing counted it.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, ssoEdgeSignalName("edge-parse")));
    return oidcFailRedirect(consoleOrigin, false);
  }
  // The browser-binding cookie set at /start (the forced-login defence); the DO requires it to match the
  // stored record value. A replayed assertion in a foreign browser carries no matching cookie.
  const browserBind = readSamlTxnCookie(req) ?? "";
  // The source IP for the sign-in audit event, forwarded in the DO request body (the body-forward pattern;
  // an SP-POST ACS carries no caller header). Server-read from the edge header, never a client field.
  const sourceIp = req.headers.get("CF-Connecting-IP");
  try {
    const resp = await scheduler.fetch(doURL("/idp/saml/acs"), { method: "POST", body: JSON.stringify({ connId, samlResponse, relayState, acsUrl, browserBind, ...(sourceIp !== null ? { sourceIp } : {}) }), headers: { "content-type": "application/json" } });
    const out = (await resp.json()) as { ok?: boolean; token?: string; returnTo?: string; newSignInContext?: boolean; reason?: unknown };
    if (out.ok !== true || typeof out.token !== "string") {
      // G018: count the SAML sub-cause (the IdP's own StatusCode class, an encrypted assertion, an IdP-initiated
      // POST at an SP-initiated-only connection, which bearer binding blocked) before discarding the reason.
      recordSsoSubCause(scheduler, out.reason, runtime);
      return oidcFailRedirect(consoleOrigin, false);
    }
    // R6: same fire-and-forget unusual-context notify as the OIDC callback (delivery never affects sign-in).
    if (out.newSignInContext === true) {
      fireInBackground(
        runtime,
        routeSignInContextAlert(env, scheduler).catch((e: unknown) => {
          log("error", `sign-in-context alert delivery failed (sign-in unaffected): ${(e as Error).message}`);
        }),
      );
    }
    const headers = new Headers({ location: safeReturnTo(out.returnTo), "referrer-policy": "no-referrer", "cache-control": "no-store" });
    headers.append("set-cookie", sessionSetCookie(out.token));
    headers.append("set-cookie", samlTxnClearCookie());
    return new Response(null, { status: 302, headers });
  } catch {
    // G116: the ACS leg could not reach the DO (or its answer was not JSON). The user sees the same generic
    // failure redirect; the DIFFERENCE is that this is an ENGINE availability fault, not a connection fault,
    // and the DO's classifier -- the only thing that writes ssoFailures -- was never reached to say so.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, ssoEdgeSignalName("edge-transport")));
    return oidcFailRedirect(consoleOrigin, false);
  }
}


// handleOidc is the PRE-AUTH native-OIDC sign-in flow (the analogue of handlePasskey). Three routes, all under
// /admin/oidc/*:
//   GET providers          the pre-auth display DTO for the "Sign in with X" buttons (no internal config).
//   GET start/<connId>     the DO mints state+nonce+PKCE and the authorize URL; set the __Host- txn cookie
//                          (SameSite=Lax) and 302 to the IdP with Referrer-Policy: no-referrer.
//   GET callback/<connId>  cross-check the txn cookie, run the DO callback (single-use state consume, the
//                          login-CSRF + RFC 9207 binds, the guarded exchange + id_token verify, the v3 mint),
//                          set the session cookie + clear the txn cookie, 302 to the relative-only returnTo.
// Every failure is GENERIC (oidcFailRedirect), never an oracle. The redirect_uri is built from CONSOLE_ORIGIN
// (the canonical public host the IdP has pre-registered), never the request host.
export async function handleOidc(req: Request, env: Env, sub: string, runtime?: AdminRuntime): Promise<Response> {
  const scheduler = schedulerStub(env);
  const consoleOrigin = typeof env.CONSOLE_ORIGIN === "string" ? env.CONSOLE_ORIGIN.replace(/\/+$/, "") : "";
  // PER-IP pre-throttle (the same authRateLimited ceremony limiter as /admin/auth/*, V2.4.1): this whole
  // surface is unauthenticated by necessity and start/callback each cost a DO round trip (start also a live
  // outbound fetch to the customer's real IdP for discovery-based connections), so an unthrottled flood is a
  // CPU-DoS + third-party-amplification vector. Checked PER MATCHED BRANCH, after the method+sub match but
  // before the branch's handler, so an unmatched sub-path stays a cheap plain 404 with no DO round trip.
  if (req.method === "GET" && sub === "providers") {
    const authLimited = await authRateLimited(scheduler, req, runtime);
    if (authLimited) return authLimited;
    return handleOidcProviders(scheduler, runtime);
  }
  if (req.method === "GET" && sub.startsWith("start/")) {
    const authLimited = await authRateLimited(scheduler, req, runtime);
    if (authLimited) return authLimited;
    return handleOidcStart(req, scheduler, consoleOrigin, sub.slice("start/".length), runtime);
  }
  if (req.method === "GET" && sub.startsWith("callback/")) {
    const authLimited = await authRateLimited(scheduler, req, runtime);
    if (authLimited) return authLimited;
    return handleOidcCallback(req, env, scheduler, consoleOrigin, sub.slice("callback/".length), runtime);
  }
  return new Response("not found", { status: 404 });
}

// handleOidcProviders serves GET providers: the pre-auth display DTO for the sign-in buttons (no internal
// config). A DO hiccup yields an EMPTY provider list (no IdP buttons), never a 500.
async function handleOidcProviders(scheduler: DurableObjectStub, runtime?: AdminRuntime): Promise<Response> {
  try {
    const resp = await scheduler.fetch(doURL("/idp/providers"), { method: "GET" });
    const body = await resp.text();
    return new Response(body, { status: resp.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
  } catch {
    // G051 / G116: an EMPTY provider list is served, so every SSO button vanishes from the sign-in page and
    // users are told their IdP is not configured. Counted on both aggregates: the degraded read (an absent fact
    // in this pack may not be absent) and the SSO edge family (the sign-in surface itself was degraded).
    fireInBackground(runtime, bumpAdminCounter(scheduler, "degraded-read-providers-list"));
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, ssoEdgeSignalName("edge-providers-unavailable")));
    return new Response(JSON.stringify({ ok: true, providers: [] }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
}

// handleOidcStart serves GET start/<connId>: the DO mints state+nonce+PKCE and the authorize URL; set the
// __Host- txn cookie (SameSite=Lax) and 302 to the IdP. The redirect_uri is built from CONSOLE_ORIGIN.
async function handleOidcStart(req: Request, scheduler: DurableObjectStub, consoleOrigin: string, connId: string, runtime?: AdminRuntime): Promise<Response> {
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo"));
  const redirectUri = `${consoleOrigin}/admin/oidc/callback/${connId}`;
  try {
    const resp = await scheduler.fetch(doURL("/idp/oidc/start"), {
      method: "POST",
      body: JSON.stringify({ connId, redirectUri, returnTo }),
      headers: { "content-type": "application/json" },
    });
    const out = (await resp.json()) as { ok?: boolean; authorizeUrl?: string; txnId?: string; reason?: unknown };
    if (out.ok !== true || typeof out.authorizeUrl !== "string" || typeof out.txnId !== "string") {
      // OBSERVE (G002): the sign-in died at /start, so it will NEVER reach the DO's callback wrapper - the only
      // thing that writes the SSO-failure aggregate. Until now this recorded nothing anywhere, which is why "the
      // SSO button just errors" arrived with a pack showing zero SSO failures. Classify the DO's reason to a
      // CLOSED name (the reason interpolates discovery errors, connIds and endpoint hosts, so it is read
      // transiently and discarded - only the name is recorded) and count it in the bounded auth-signal aggregate.
      // Best-effort and fire-and-forget: the user still gets the same generic failure redirect.
      fireInBackground(runtime, recordAuthSignalEdge(scheduler, classifySsoStartFailure(typeof out.reason === "string" ? out.reason : "")));
      return oidcFailRedirect(consoleOrigin);
    }
    return new Response(null, {
      status: 302,
      headers: { location: out.authorizeUrl, "set-cookie": oidcTxnSetCookie(out.txnId), "referrer-policy": "no-referrer", "cache-control": "no-store" },
    });
  } catch {
    // The edge could not reach the scheduler DO at all (or its response was not JSON): the sign-in never even got
    // as far as minting state. An engine-side availability fault, recorded apart from every connection-side cause.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, "sso-start-do-unreachable"));
    return oidcFailRedirect(consoleOrigin);
  }
}

// handleOidcCallback serves GET callback/<connId>: cross-check the txn cookie, run the DO callback (single-use
// state consume, the login-CSRF + RFC 9207 binds, the guarded exchange + id_token verify, the v3 mint), set
// the session cookie + clear the txn cookie, 302 to the relative-only returnTo. Every failure is generic.
async function handleOidcCallback(req: Request, env: Env, scheduler: DurableObjectStub, consoleOrigin: string, connId: string, runtime?: AdminRuntime): Promise<Response> {
  const params = new URL(req.url).searchParams;
  const code = params.get("code") ?? "";
  const state = params.get("state") ?? "";
  const iss = params.get("iss");
  const idpError = params.get("error");
  const txnId = readOidcTxnCookie(req) ?? "";
  // The IdP may return ?error=... (the user declined, or a config fault); treat it as a generic failure. A
  // missing code/state/txn is likewise refused without distinguishing which is absent (no oracle).
  if (idpError !== null || code.length === 0 || state.length === 0 || txnId.length === 0) {
    // G116: the IdP's OWN `?error=` code is the single most diagnostic artefact in the whole flow -- it is the
    // IdP saying WHY it declined (an expired client secret answers invalid_client; a conditional-access policy
    // answers access_denied; an IdP outage answers temporarily_unavailable) -- and it was read, used to pick a
    // generic redirect, and thrown away before the DO was ever invoked. Mapped through a CLOSED registry set,
    // so an attacker-controlled query string can never inject a key; error_description is never read at all.
    // A malformed callback with no error code is the edge-parse leg. The user-facing redirect is UNCHANGED.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, idpError !== null ? idpErrorSignalName(idpError) : ssoEdgeSignalName("edge-parse")));
    return oidcFailRedirect(consoleOrigin, true);
  }
  // The source IP for the sign-in audit event, read from the edge header and forwarded in the DO request
  // body (the recovery-code body-forward pattern): a client OIDC sign-in carries no caller header, so the
  // body is the only way "where someone signed in from" reaches the trail. Server-read, never client-set.
  const sourceIp = req.headers.get("CF-Connecting-IP");
  try {
    const resp = await scheduler.fetch(doURL("/idp/oidc/callback"), {
      method: "POST",
      body: JSON.stringify({ connId, code, state, txnId, ...(iss !== null ? { iss } : {}), ...(sourceIp !== null ? { sourceIp } : {}) }),
      headers: { "content-type": "application/json" },
    });
    const out = (await resp.json()) as { ok?: boolean; token?: string; returnTo?: string; newSignInContext?: boolean; reason?: unknown };
    if (out.ok !== true || typeof out.token !== "string") {
      // G009: count the OIDC/OAuth2 sub-cause (the provider's own invalid_client / invalid_grant, a kid-not-found
      // after a JWKS rotation, which single-use artefact failed) before discarding the reason.
      recordSsoSubCause(scheduler, out.reason, runtime);
      return oidcFailRedirect(consoleOrigin, true);
    }
    // R6: the DO flagged a materially NEW coarse sign-in context (opt-in). Fire the redaction-safe notify
    // FIRE-AND-FORGET so delivery can never delay or fail the sign-in redirect (the recovery-code pattern).
    if (out.newSignInContext === true) {
      fireInBackground(
        runtime,
        routeSignInContextAlert(env, scheduler).catch((e: unknown) => {
          log("error", `sign-in-context alert delivery failed (sign-in unaffected): ${(e as Error).message}`);
        }),
      );
    }
    const headers = new Headers({ location: safeReturnTo(out.returnTo), "referrer-policy": "no-referrer", "cache-control": "no-store" });
    // Two Set-Cookie headers (append, not set): the session cookie (sign-in) AND the txn cookie cleared.
    headers.append("set-cookie", sessionSetCookie(out.token));
    headers.append("set-cookie", oidcTxnClearCookie());
    return new Response(null, { status: 302, headers });
  } catch {
    // G116: the callback leg could not reach the DO (or its answer was not JSON): an ENGINE availability
    // fault the DO's own classifier can never see, because it was never reached.
    fireInBackground(runtime, recordAuthSignalEdge(scheduler, ssoEdgeSignalName("edge-transport")));
    return oidcFailRedirect(consoleOrigin, true);
  }
}
