// The IdP/SSO "test connection" pre-save probe (a misconfigured IdP connection was
// only discovered at the FIRST sign-in, so an operator could save a broken trust root and lock everyone
// out). This module is the dispatcher the route calls: it runs a READ-ONLY connectivity + validity check over
// an OIDC or SAML connection config - SAVED or, more importantly, UNSAVED (the operator tests before committing) -
// and returns a structured { ok, checks: [{ name, status, detail }] } the console renders next to the form.
// It never stores anything, never starts a login/redirect, and never follows an authentication flow: it only
// fetches the metadata an IdP publishes (the OIDC discovery document + the JWKS) and parses the SAML
// config/metadata the operator already holds. There is NOTHING here that mutates state.
//
// The two probes themselves live in sibling modules (idp-test-oidc.ts + idp-test-saml.ts) and lean on the
// shared SSRF-disciplined primitives in idp-test-shared.ts; this file re-exports their public symbols so the
// route and validator keep importing everything from "./idp-test.ts" unchanged. The split is structural only:
// no logic was rewritten.
//
// SECURITY DISCIPLINE (this is a customer-supplied-URL outbound-fetch surface, so it is SSRF-relevant): every
// outbound fetch goes through the SAME guarded path the live OIDC flow uses, layered with the engine's
// thorough internal-host classifier, time-bounded, with coarse secret-free details; see idp-test-shared.ts.
// The whole thing is TOLERANT: any individual fault (DNS, timeout, non-200, missing field, empty JWKS, an
// internal-host URL, an unparseable/expired cert) becomes a { status: "fail" } check with ok:false, never a
// 500 / thrown exception. It is exercised directly by the validator with a stub fetch.
//
// Node 25 strip-types + Workers compatible: Web Crypto + fetch only, no Node builtins, no enums, explicit
// fields, error-as-value at every boundary. Australian English; no em dashes.

import type { OidcTestConfig } from "./idp-test-oidc.ts";
import { testOidcConnection } from "./idp-test-oidc.ts";
import type { SamlTestConfig } from "./idp-test-saml.ts";
import { testSamlConnection } from "./idp-test-saml.ts";
import type { CheckStatus, IdpTestCheck, IdpTestResult } from "./idp-test-shared.ts";
import { finalise, screenFetchUrl } from "./idp-test-shared.ts";

export type { CheckStatus, IdpTestCheck, IdpTestResult, OidcTestConfig, SamlTestConfig };
// Re-export the moved symbols so importers (the route, the validator) are unchanged by the split.
export { finalise, screenFetchUrl, testOidcConnection, testSamlConnection };

// ---- the dispatcher the route calls -------------------------------------------------------------

// A loose proposal as it arrives on the wire (every field untrusted). The route hands the parsed JSON body's
// `proposal` straight in; we read only the discriminator + the fields each kind's test needs, so an UNSAVED
// connection (no id/createdAt/secretRef yet) is fine - the probe needs none of the storage-only fields.
export interface IdpTestProposal {
  kind?: unknown;
  [k: string]: unknown;
}

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function strArr(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  const out: string[] = [];
  for (const e of v) if (typeof e === "string") out.push(e);
  return out;
}

// runIdpConnectionTest is the single entry point the route calls. It routes on the proposal's kind to the
// OIDC or SAML probe, reading only the fields that probe needs from the untrusted body. An unknown/missing
// kind is itself a clean failed check (never a throw). doFetch is injected (the global fetch in prod, a stub
// in the validator); the SAML path ignores it (no server-side fetch). It NEVER throws: a probe that hits an
// unexpected fault still resolves to ok:false with a coarse check, so the route always returns a 200 + the
// structured result, never a 500.
// extractOidcConfig reads only the OIDC fields the probe needs from the untrusted proposal body.
function extractOidcConfig(proposal: IdpTestProposal): OidcTestConfig {
  const cfg: OidcTestConfig = { issuer: str(proposal.issuer) ?? "" };
  const du = str(proposal.discoveryUrl);
  if (du !== undefined) cfg.discoveryUrl = du;
  const ae = str(proposal.authorizationEndpoint);
  if (ae !== undefined) cfg.authorizationEndpoint = ae;
  const te = str(proposal.tokenEndpoint);
  if (te !== undefined) cfg.tokenEndpoint = te;
  const ju = str(proposal.jwksUri);
  if (ju !== undefined) cfg.jwksUri = ju;
  return cfg;
}

// extractOauth2Checks screens the OAuth2 endpoint SHAPE (no network, no login). OAuth2 (GitHub-class,
// no id_token + no discovery + no JWKS) has no read-only probe: a real exchange needs a client secret +
// a code which a pre-save test cannot perform without initiating a login, which the SACRED read-only
// rule forbids. So we run the same https/host shape screen on the configured endpoints and say so.
function extractOauth2Checks(proposal: IdpTestProposal): IdpTestResult {
  const checks: IdpTestCheck[] = [];
  for (const key of ["authorizeUrl", "tokenUrl", "profileUrl", "apiBase"] as const) {
    const val = str((proposal as Record<string, unknown>)[key]);
    if (val === undefined || val.length === 0) {
      checks.push({ name: key, status: "fail", detail: `${key} is not set.` });
      continue;
    }
    const p = screenFetchUrl(val);
    if (p !== null) checks.push({ name: key, status: "fail", detail: `${key} is not a usable https endpoint: ${p}.` });
    else checks.push({ name: key, status: "pass", detail: `${key} is a valid https endpoint.` });
  }
  checks.push({ name: "Live exchange", status: "warn", detail: "OAuth2 providers carry no discovery or JWKS to probe read-only; endpoint shape is validated here, but the credential/exchange is only exercised at the first real sign-in." });
  return finalise(checks);
}

// extractSamlConfig reads only the SAML fields the probe needs from the untrusted proposal body.
function extractSamlConfig(proposal: IdpTestProposal): SamlTestConfig {
  const cfg: SamlTestConfig = {};
  const ei = str(proposal.idpEntityId);
  if (ei !== undefined) cfg.idpEntityId = ei;
  const su = str(proposal.idpSsoUrl);
  if (su !== undefined) cfg.idpSsoUrl = su;
  const certs = strArr(proposal.idpSigningCerts);
  if (certs !== undefined) cfg.idpSigningCerts = certs;
  const xml = str(proposal.idpMetadataXml);
  if (xml !== undefined) cfg.idpMetadataXml = xml;
  return cfg;
}

export async function runIdpConnectionTest(
  proposal: IdpTestProposal,
  doFetch: typeof fetch,
  opts?: { timeoutMs?: number; now?: number },
): Promise<IdpTestResult> {
  try {
    const kind = proposal.kind;
    if (kind === "oidc") return await testOidcConnection(extractOidcConfig(proposal), doFetch, opts);
    if (kind === "oauth2") return extractOauth2Checks(proposal);
    if (kind === "saml") return testSamlConnection(extractSamlConfig(proposal), opts);
    return {
      ok: false,
      checks: [{ name: "Connection kind", status: "fail", detail: `Unknown connection kind ${typeof kind === "string" ? `"${kind}"` : "(none supplied)"}; expected "oidc", "oauth2" or "saml".` }],
    };
  } catch {
    // The whole probe is tolerant: an unexpected fault is reported as a single failed check, never a throw,
    // so the route always returns a structured 200 result rather than a 500.
    return { ok: false, checks: [{ name: "Test connection", status: "fail", detail: "The connection test could not be completed due to an unexpected error. Re-check the connection fields and try again." }] };
  }
}
