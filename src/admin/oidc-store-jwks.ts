// The JWKS getter for the DO-side OIDC store (oidc-store.ts): the per-issuer JWKS cache + the JWKS-HOST PIN
// that the pure verifier (oidc-verify.ts) deliberately leaves to the caller. Factored out so oidc-store.ts
// keeps the connection CRUD + flow orchestration; the symbol is re-exported from oidc-store.ts so importers
// are unchanged.
//
// Node 25 strip-types + Workers compatible: Web Crypto + fetch only, no Node builtins, explicit fields.

import type { OidcConnection } from "./idpconn.ts";
import type { FlowEndpoints } from "./oidc.ts";
import { fetchJwksGuarded } from "./oidc.ts";
import type { JWKS } from "./oidc-verify.ts";

// makeJwksGetter returns the getJwks(force) the flow's verifyIdTokenWithRotation consumes. It owns the
// per-issuer JWKS cache (a closure Map; one getter per login flow, so the cache scope is the flow) AND the
// JWKS-HOST PIN that the pure verifier deliberately leaves to the caller:
//   - if the connection carries an explicit jwksUri, that URL is TRUSTED: it was assertSafeFetchEndpoint-
//     validated at config time, and a real provider legitimately serves its JWKS off-issuer (Google's issuer
//     is accounts.google.com but its JWKS is on www.googleapis.com), so we do NOT re-pin it to the issuer host;
//   - otherwise (the endpoints came from discovery) the discovery-supplied jwks_uri host MUST equal the issuer
//     host. This is the second half of the discovery-trust chain (parseDiscovery binds the doc's issuer; this
//     pins the JWKS host), refusing a poisoned/mis-fetched discovery document that points the JWKS at an
//     unrelated host. A mismatch THROWS (the flow's verifyIdTokenWithRotation awaits getJwks, so the throw
//     surfaces as a clean callback failure).
// fetchJwksGuarded does the SSRF-screened fetch + the duplicate-kid rejection. force bypasses the cache (the
// ONE kid-rotation refetch). The pinned-but-fetched JWKS is cached; a force refetch replaces the cache entry.
export function makeJwksGetter(
  conn: OidcConnection,
  ep: FlowEndpoints,
  doFetch: typeof fetch,
): (force: boolean) => Promise<JWKS> {
  // The effective JWKS URL and whether it is the config-trusted explicit one. When the connection carries an
  // explicit jwksUri we use it as-is; otherwise we use the discovery-resolved ep.jwksUri AFTER pinning its host.
  const trustedJwksUri = conn.jwksUri;
  const cache = new Map<string, JWKS>();
  // Key the cache by the connection's issuer (NEVER by the discovery-supplied jwks_uri, which a hostile
  // discovery doc could vary): one connection = one issuer = one cache slot, per the CALLER OBLIGATIONS.
  const cacheKey = conn.issuer;

  return async (force: boolean): Promise<JWKS> => {
    if (!force) {
      const hit = cache.get(cacheKey);
      if (hit !== undefined) return hit;
    }
    let jwksUri: string;
    if (trustedJwksUri !== undefined) {
      // Config-validated explicit jwksUri: trusted off-issuer (assertSafeFetchEndpoint-checked at config time).
      jwksUri = trustedJwksUri;
    } else {
      // Discovery-resolved jwks_uri: PIN its host to the issuer host. A mismatch is a poisoned/mis-fetched
      // discovery document and is refused outright.
      let jwksHost: string;
      let issuerHost: string;
      try {
        jwksHost = new URL(ep.jwksUri).hostname.toLowerCase();
        issuerHost = new URL(conn.issuer).hostname.toLowerCase();
      } catch {
        throw new Error("jwks-host pin: the jwks_uri or issuer is not a valid URL");
      }
      if (jwksHost !== issuerHost) {
        throw new Error(`jwks-host pin: discovery jwks_uri host "${jwksHost}" does not match the issuer host "${issuerHost}"`);
      }
      jwksUri = ep.jwksUri;
    }
    const res = await fetchJwksGuarded(jwksUri, doFetch);
    if (!res.ok) throw new Error(`jwks fetch failed: ${res.reason}`);
    cache.set(cacheKey, res.jwks);
    return res.jwks;
  };
}
