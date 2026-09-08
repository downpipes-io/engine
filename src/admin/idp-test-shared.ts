// Shared types, bounds and the SSRF-disciplined outbound-fetch primitives for the IdP/SSO "test connection"
// pre-save probe. This module carries the pieces the OIDC and SAML probes both lean
// on: the { ok, checks } result shape the console renders, the finalise() that stamps ok, the time/expiry
// bounds, the screenFetchUrl() outbound-URL screen and the time-bounded guarded fetch. It is split out of
// idp-test.ts purely to keep that file under the structural line limit; the logic is unchanged and the public
// symbols are re-exported from idp-test.ts so importers are unaffected.
//
// SECURITY DISCIPLINE (this is a customer-supplied-URL outbound-fetch surface, so it is SSRF-relevant):
//   - Every outbound fetch goes through the SAME guarded path the live OIDC flow uses (guardedOidcFetch in
//     oidc.ts): https-only, host screened by assertSafeFetchEndpoint (no IP literal / localhost /
//     cloudflareaccess), redirect:"manual" with any 3xx refused (a 302 to an internal host cannot be chased), and a hard response
//     byte cap. On TOP of that name-screen we layer the engine's THOROUGH internal-host classifier
//     (isInternalSinkHost from notify.ts), which also catches RFC1918 / link-local 169.254.169.254 cloud
//     metadata / IPv6 ULA+link-local literals - the cases the OIDC name-screen alone does not enumerate. A
//     URL that trips EITHER screen is reported as a failed check, never fetched.
//   - Each fetch is time-bounded by an AbortController so a black-holed host cannot hang the probe; the
//     timeout surfaces as a clean "timed out" check, never a throw.
//   - Error details are COARSE and secret-free (a category + the offending field/host), never a raw upstream
//     body, response header, or stack.
//
// Node 25 strip-types + Workers compatible: Web Crypto + fetch only, no Node builtins, no enums, explicit
// fields, error-as-value at every boundary. Australian English; no em dashes.

import { isInternalSinkHost } from "../notify.ts";
import { guardedOidcFetch } from "./oidc.ts";
import { assertSafeFetchEndpoint } from "./oidc-verify.ts";

// ---- the result shape the console renders -------------------------------------------------------

// A single check line. status is a three-state traffic light: "pass" (verified good), "warn" (a non-fatal
// observation worth surfacing, e.g. a SAML cert nearing expiry, that does NOT by itself fail the test), and
// "fail" (a problem that would break sign-in). detail is a short, actionable, secret-free sentence.
export type CheckStatus = "pass" | "warn" | "fail";
export interface IdpTestCheck {
  name: string;
  status: CheckStatus;
  detail: string;
}
// The overall result. ok is true ONLY when no check failed (a "warn" does not clear ok=true... see note):
// ok === (no check has status "fail"). A "warn" leaves ok true (it is an advisory, not a blocker), matching
// the console contract "green unless something is actually broken".
export interface IdpTestResult {
  ok: boolean;
  checks: IdpTestCheck[];
}

// finalise stamps ok from the checks: ok is false the moment ANY check failed, true otherwise (warns do not
// fail the test). One place computes it so the route can never disagree with the lines it returns.
export function finalise(checks: IdpTestCheck[]): IdpTestResult {
  return { ok: !checks.some((c) => c.status === "fail"), checks };
}

// ---- bounds + timing ----------------------------------------------------------------------------

// DEFAULT_FETCH_TIMEOUT_MS bounds a single outbound probe fetch. A real IdP's discovery/JWKS endpoint answers
// in well under a second; 8s is generous for a slow-but-alive host yet short enough that a black-holed host
// does not hang the operator's "Test connection" click. The caller may override it (the validator drives a
// 0-delay stub).
export const DEFAULT_FETCH_TIMEOUT_MS = 8000;
// MS_PER_DAY is the milliseconds-per-day divisor shared by the cert-expiry window and the days-remaining
// computation in idp-test-saml.ts, so the two never drift.
export const MS_PER_DAY = 24 * 60 * 60 * 1000;
// CERT_EXPIRY_WARN_MS: a pinned SAML signing cert within this window of its notAfter is surfaced as a "warn"
// (still valid, sign-in still works, but the operator should plan a rollover). 30 days.
export const CERT_EXPIRY_WARN_MS = 30 * MS_PER_DAY;

// ---- the SSRF screen (name-screen + thorough internal-host classifier) --------------------------

// screenFetchUrl applies BOTH outbound-URL screens the probe relies on and returns null when the URL is safe
// to fetch, or a coarse reason string when it must be refused. It is the single chokepoint every probe URL
// passes through BEFORE a fetch is attempted (the guarded fetch re-applies assertSafeFetchEndpoint as defence
// in depth, but we screen first so an internal-host URL is reported as a clean failed check, not surfaced via
// a thrown guard). The two screens are complementary: assertSafeFetchEndpoint enforces https + rejects the
// obvious name/IP-literal classes; isInternalSinkHost additionally catches RFC1918 / 169.254.169.254 cloud
// metadata / IPv6 ULA+link-local. The detail never echoes anything but the host category.
export function screenFetchUrl(raw: string): string | null {
  let host: string;
  try {
    const u = new URL(raw);
    host = u.hostname;
  } catch {
    return "the URL is not a valid absolute URL";
  }
  try {
    assertSafeFetchEndpoint(raw);
  } catch {
    // assertSafeFetchEndpoint's message can include the raw URL; keep the surfaced detail to a fixed category.
    return "the URL must be https and must not be an IP literal, localhost, or a cloudflareaccess.com host";
  }
  if (isInternalSinkHost(host)) {
    return "the URL is a private/loopback/link-local address or names localhost (incl. cloud metadata); these are refused";
  }
  return null;
}

// ---- a time-bounded wrapper over the shared guarded fetch ---------------------------------------

// fetchGuardedBounded runs the shared guardedOidcFetch (https + host screen + redirect:"manual" with a 3xx refused + byte cap)
// under an AbortController timeout. It returns the GuardedResponse, or a coarse error string (never throws to
// the caller). A timeout, a DNS/connect failure and the byte-cap breach all collapse to a short category here.
export async function fetchGuardedBounded(
  url: string,
  doFetch: typeof fetch,
  timeoutMs: number,
): Promise<{ ok: true; status: number; bodyText: string } | { ok: false; reason: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await guardedOidcFetch(url, { method: "GET", headers: { accept: "application/json" }, signal: ctrl.signal }, doFetch);
    return { ok: true, status: resp.status, bodyText: resp.bodyText };
  } catch (e) {
    // Distinguish an abort (timeout) from any other fault so the detail is actionable, without leaking the
    // upstream error text. An AbortError surfaces either as e.name === "AbortError" or via the signal.
    const aborted = ctrl.signal.aborted || (e instanceof Error && e.name === "AbortError");
    if (aborted) return { ok: false, reason: "the request timed out (no response within the time budget); check the host is reachable and not firewalled" };
    return { ok: false, reason: "could not reach the endpoint (DNS, connection refused, TLS error, or the response exceeded the size cap)" };
  } finally {
    clearTimeout(timer);
  }
}
