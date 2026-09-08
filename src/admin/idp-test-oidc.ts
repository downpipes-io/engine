// The OIDC half of the IdP/SSO "test connection" pre-save probe. Split out of
// idp-test.ts purely to keep that file under the structural line limit; the logic is unchanged and the public
// symbols (OidcTestConfig, testOidcConnection) are re-exported from idp-test.ts so importers are unaffected.
// It is READ-ONLY: it only fetches the metadata an IdP publishes (the OIDC discovery document + the JWKS) and
// never starts a login/redirect. Every outbound fetch goes through the shared SSRF-disciplined primitives in
// idp-test-shared.ts. Australian English; no em dashes.

import type { IdpTestCheck, IdpTestResult } from "./idp-test-shared.ts";
import {
  DEFAULT_FETCH_TIMEOUT_MS,
  fetchGuardedBounded,
  finalise,
  screenFetchUrl,
} from "./idp-test-shared.ts";
import { discoveryUrlFor } from "./oidc.ts";

// A minimal view of an OIDC connection the test needs. The route accepts the SAME shape idpconn stores; this
// is the subset the probe reads. issuer is the trust anchor; the optional explicit endpoints, when all three
// are present, mean the live flow skips discovery, so we still verify them (the JWKS in particular) but note
// that discovery was not consulted.
export interface OidcTestConfig {
  issuer: string;
  discoveryUrl?: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  jwksUri?: string;
}

// testOidcConnection runs the OIDC connectivity + validity checks. The sequence mirrors what the live flow
// (oidc-store.ts resolveEndpoints + makeJwksGetter) actually does, so a green test means the flow's network
// preconditions hold:
//   1. discovery: fetch issuer/.well-known/openid-configuration (or the explicit discoveryUrl), require a 200,
//      JSON, issuer === the configured issuer, and authorization_endpoint + token_endpoint + jwks_uri all
//      present + https-safe. (When the connection carries all three explicit endpoints we skip the discovery
//      fetch, exactly like the live flow, and check those instead.)
//   2. jwks: fetch the resolved jwks_uri, require a 200 + a JSON keys array, and confirm AT LEAST ONE usable
//      signing key (an RSA key with n+e, or an EC P-256 key with x+y) - an empty/garbage JWKS would make every
//      id_token verification fail with "signing key not found".
// Each step is its own check; a failure short-circuits the dependent step with a clear "skipped" line so the
// operator sees the first thing to fix. It never throws.
// EndpointResolution is the outcome of the explicit-or-discovery endpoint step: either a resolved
// jwksUri to probe next, or the terminal checks to return (the step failed and the JWKS is skipped).
type EndpointResolution = { jwksUri: string } | { done: IdpTestCheck[] };

// validateExplicitEndpoints validates the three pinned endpoints (authorization/token/JWKS) when the
// connection carries all of them, so the live flow skips discovery. authorization_endpoint is browser
// facing (never fetched server-side), so it is screened for shape but not fetched.
function validateExplicitEndpoints(cfg: OidcTestConfig, checks: IdpTestCheck[]): EndpointResolution {
  for (const [label, val] of [["authorization_endpoint", cfg.authorizationEndpoint!], ["token_endpoint", cfg.tokenEndpoint!], ["jwks_uri", cfg.jwksUri!]] as const) {
    const p = screenFetchUrl(val);
    if (p !== null) {
      checks.push({ name: "Explicit endpoints", status: "fail", detail: `${label} is not a usable https endpoint: ${p}.` });
      checks.push({ name: "Signing keys (JWKS)", status: "fail", detail: "Skipped: fix the endpoint above first." });
      return { done: checks };
    }
  }
  checks.push({ name: "Explicit endpoints", status: "pass", detail: "The connection pins authorization, token and JWKS endpoints explicitly (discovery is skipped at sign-in)." });
  return { jwksUri: cfg.jwksUri! };
}

// checkDiscoveryEndpoints reads the three endpoints from a parsed discovery document, requiring each
// present + https-safe, and returns the resolved jwks_uri or a reason.
function checkDiscoveryEndpoints(d: Record<string, unknown>): { jwksUri: string } | { reason: string } {
  let resolvedJwks: string | null = null;
  for (const [label, key] of [["authorization_endpoint", "authorization_endpoint"], ["token_endpoint", "token_endpoint"], ["jwks_uri", "jwks_uri"]] as const) {
    const val = d[key];
    if (typeof val !== "string" || val.length === 0) return { reason: `the discovery document is missing ${label}` };
    const p = screenFetchUrl(val);
    if (p !== null) return { reason: `discovery ${label} is not a usable https endpoint: ${p}` };
    if (key === "jwks_uri") resolvedJwks = val;
  }
  return { jwksUri: resolvedJwks! };
}

// validateDiscoveryDocument fetches the .well-known document, requires a 200 + JSON object, checks the
// issuer matches exactly, and resolves the three endpoints. It returns the resolved jwksUri or the
// terminal checks. SSRF note: for an UNSAVED config the operator may supply an explicit discoveryUrl,
// which discoveryUrlFor returns verbatim, so it is NOT host-matched against the issuer here (the
// config-time host check runs only on save). The screen is screenFetchUrl (https + non-internal host)
// plus the exact issuer-mismatch check below, which flags a discovery document served from an
// unrelated host whose issuer field does not equal the configured issuer.
async function validateDiscoveryDocument(cfg: OidcTestConfig, doFetch: typeof fetch, timeoutMs: number, checks: IdpTestCheck[]): Promise<EndpointResolution> {
  const skipJwks = (): EndpointResolution => {
    checks.push({ name: "Signing keys (JWKS)", status: "fail", detail: "Skipped: discovery did not resolve." });
    return { done: checks };
  };
  const discUrl = discoveryUrlFor(cfg);
  const discProblem = screenFetchUrl(discUrl);
  if (discProblem !== null) {
    checks.push({ name: "Discovery document", status: "fail", detail: `The discovery URL is not safe to fetch: ${discProblem}.` });
    return skipJwks();
  }
  const disc = await fetchGuardedBounded(discUrl, doFetch, timeoutMs);
  if (!disc.ok) {
    checks.push({ name: "Discovery document", status: "fail", detail: `Could not fetch ${discUrl}: ${disc.reason}.` });
    return skipJwks();
  }
  if (disc.status !== 200) {
    checks.push({ name: "Discovery document", status: "fail", detail: `The discovery endpoint returned HTTP ${disc.status} (expected 200). Confirm the issuer is exactly right (no trailing path) and the IdP publishes /.well-known/openid-configuration.` });
    return skipJwks();
  }
  let doc: unknown;
  try {
    doc = JSON.parse(disc.bodyText);
  } catch {
    checks.push({ name: "Discovery document", status: "fail", detail: "The discovery endpoint did not return JSON. Confirm the issuer points at the OIDC base, not an HTML page." });
    return skipJwks();
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    checks.push({ name: "Discovery document", status: "fail", detail: "The discovery document is not a JSON object." });
    return skipJwks();
  }
  const d = doc as Record<string, unknown>;
  // issuer must match exactly (the live parseDiscovery binds this; a mismatch poisons the trust chain).
  const docIssuer = d.issuer;
  if (typeof docIssuer !== "string" || docIssuer.length === 0) {
    checks.push({ name: "Discovery document", status: "fail", detail: "The discovery document is missing its `issuer` field." });
  } else if (docIssuer !== cfg.issuer) {
    // Cap the upstream-supplied issuer before echoing it: the body is only size-limited to 256 KiB, and the detail must stay coarse.
    const safeIssuer = docIssuer.length > 256 ? `${docIssuer.slice(0, 256)}...` : docIssuer;
    checks.push({ name: "Discovery document", status: "fail", detail: `The discovery document's issuer (${safeIssuer}) does not match the configured issuer (${cfg.issuer}); sign-in would reject every token. Set the issuer to the value the IdP publishes.` });
  } else {
    checks.push({ name: "Discovery document", status: "pass", detail: "Fetched the discovery document and its issuer matches." });
  }
  const ep = checkDiscoveryEndpoints(d);
  if ("reason" in ep) {
    checks.push({ name: "Discovery endpoints", status: "fail", detail: `${ep.reason}.` });
    checks.push({ name: "Signing keys (JWKS)", status: "fail", detail: "Skipped: discovery endpoints incomplete." });
    return { done: checks };
  }
  checks.push({ name: "Discovery endpoints", status: "pass", detail: "Discovery advertises authorization_endpoint, token_endpoint and jwks_uri, all https." });
  return { jwksUri: ep.jwksUri };
}

// countUsableJwksKeys counts keys that can verify a token: an RSA key with n + e, or an EC P-256 key
// with x + y. This mirrors what oidc-verify.ts's importVerifyKey requires.
function countUsableJwksKeys(keysRaw: unknown[]): number {
  let usable = 0;
  for (const k of keysRaw) {
    if (typeof k !== "object" || k === null) continue;
    const key = k as { kty?: unknown; n?: unknown; e?: unknown; crv?: unknown; x?: unknown; y?: unknown };
    if (key.kty === "RSA" && typeof key.n === "string" && typeof key.e === "string") usable++;
    else if (key.kty === "EC" && key.crv === "P-256" && typeof key.x === "string" && typeof key.y === "string") usable++;
  }
  return usable;
}

// validateJwks fetches the resolved JWKS and confirms at least one usable signing key, returning the
// single JWKS check.
async function validateJwks(jwksUri: string, doFetch: typeof fetch, timeoutMs: number): Promise<IdpTestCheck> {
  const jwksScreen = screenFetchUrl(jwksUri);
  if (jwksScreen !== null) return { name: "Signing keys (JWKS)", status: "fail", detail: `The JWKS URL is not safe to fetch: ${jwksScreen}.` };
  const jr = await fetchGuardedBounded(jwksUri, doFetch, timeoutMs);
  if (!jr.ok) return { name: "Signing keys (JWKS)", status: "fail", detail: `Could not fetch the JWKS at ${jwksUri}: ${jr.reason}.` };
  if (jr.status !== 200) return { name: "Signing keys (JWKS)", status: "fail", detail: `The JWKS endpoint returned HTTP ${jr.status} (expected 200).` };
  let jwksJson: unknown;
  try {
    jwksJson = JSON.parse(jr.bodyText);
  } catch {
    return { name: "Signing keys (JWKS)", status: "fail", detail: "The JWKS endpoint did not return JSON." };
  }
  const keysRaw = (jwksJson as { keys?: unknown } | null)?.keys;
  if (!Array.isArray(keysRaw)) return { name: "Signing keys (JWKS)", status: "fail", detail: "The JWKS has no `keys` array." };
  const usable = countUsableJwksKeys(keysRaw);
  if (usable === 0) return { name: "Signing keys (JWKS)", status: "fail", detail: `The JWKS returned ${keysRaw.length} key(s) but none is a usable RSA or EC P-256 signing key; id_token verification would fail at sign-in.` };
  return { name: "Signing keys (JWKS)", status: "pass", detail: `Fetched the JWKS; ${usable} usable signing key(s) present.` };
}

export async function testOidcConnection(
  cfg: OidcTestConfig,
  doFetch: typeof fetch,
  opts?: { timeoutMs?: number },
): Promise<IdpTestResult> {
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_FETCH_TIMEOUT_MS;
  const checks: IdpTestCheck[] = [];

  // The configured issuer must itself be a safe https anchor (it is the host the discovery fetch is pinned to).
  const issuerProblem = typeof cfg.issuer === "string" && cfg.issuer.length > 0 ? screenFetchUrl(cfg.issuer) : "the issuer is missing";
  if (issuerProblem !== null) {
    checks.push({ name: "Issuer", status: "fail", detail: `Issuer is not a usable https URL: ${issuerProblem}.` });
    // Without a usable issuer we cannot derive discovery or pin the JWKS host; stop with skipped dependents.
    checks.push({ name: "Discovery document", status: "fail", detail: "Skipped: fix the issuer first." });
    checks.push({ name: "Signing keys (JWKS)", status: "fail", detail: "Skipped: fix the issuer first." });
    return finalise(checks);
  }
  checks.push({ name: "Issuer", status: "pass", detail: `Issuer ${cfg.issuer} is a valid https anchor.` });

  // Resolve the endpoints: explicit (all three present) OR via the discovery document.
  const hasAllExplicit = !!cfg.authorizationEndpoint && !!cfg.tokenEndpoint && !!cfg.jwksUri;
  const resolution = hasAllExplicit
    ? validateExplicitEndpoints(cfg, checks)
    : await validateDiscoveryDocument(cfg, doFetch, timeoutMs, checks);
  if ("done" in resolution) return finalise(resolution.done);

  // JWKS: fetch + confirm at least one usable signing key.
  checks.push(await validateJwks(resolution.jwksUri, doFetch, timeoutMs));
  return finalise(checks);
}
